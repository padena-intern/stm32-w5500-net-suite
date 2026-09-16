/*
 * mqtt_tls_socket.c
 *
 * See mqtt_tls_socket.h for the overall design.
 */

#include <stdio.h>
#include <string.h>
#include "mqtt_tls_socket.h"
#include "socket.h"           /* WIZnet ioLibrary: send()/recv(), SOCK_BUSY, ... */
#include "wolfssl/error-ssl.h"
#include "wolfssl/wolfio.h"   /* WOLFSSL_CBIO_ERR_* */
#include "ca_cert.h"          /* g_ca_cert_der[] / g_ca_cert_der_len - see ca_cert.h */
#include "stm32f7xx_hal.h"    /* RNG_HandleTypeDef / HAL_RNG_* - hardware TRNG */

/*
 * wolfSSL's entropy source, wired to the STM32 hardware TRNG. On bare
 * metal there's no /dev/urandom for wolfSSL to seed its DRBG from, so
 * without this every wolfSSL_new() dies in wc_GenerateSeed() before the
 * handshake even starts.
 *
 * secure_cmd.c already owns this same RNG peripheral for its AES-GCM
 * nonces, through its own static RNG_HandleTypeDef - not reachable from
 * here, so we just re-init our own handle instead (HAL_RNG_Init() is
 * harmless to call twice).
 *
 * Registered via CUSTOM_RAND_GENERATE_SEED in user_settings.h.
 */
static RNG_HandleTypeDef s_mqtt_hrng;
static uint8_t           s_mqtt_hrng_ready = 0;

int MQTT_TLS_SeedRNG(unsigned char *output, unsigned int sz)
{
    if (!s_mqtt_hrng_ready)
    {
        __HAL_RCC_RNG_CLK_ENABLE();
        s_mqtt_hrng.Instance = RNG;
        if (HAL_RNG_Init(&s_mqtt_hrng) != HAL_OK)
        {
            printf("mqtt_tls: RNG init failed\r\n");
            return -1;
        }
        s_mqtt_hrng_ready = 1;
    }

    while (sz > 0)
    {
        uint32_t w;
        uint32_t chunk = sz < sizeof(w) ? sz : sizeof(w);

        if (HAL_RNG_GenerateRandomNumber(&s_mqtt_hrng, &w) != HAL_OK)
        {
            printf("mqtt_tls: RNG generate failed\r\n");
            return -1;
        }

        memcpy(output, &w, chunk);
        output += chunk;
        sz -= chunk;
    }

    return 0;
}

/*
 * wolfSSL gives us the per-session context pointer we registered with
 * wolfSSL_SetIOReadCtx()/SetIOWriteCtx() - we stash the W5500 socket
 * number (0..7) in it directly rather than allocating a struct, since
 * that's all the W5500 send()/recv() calls need.
 */
static inline uint8_t sock_from_ctx(void *ctx)
{
    return (uint8_t)(uintptr_t)ctx;
}

int MQTT_TLS_IORecv(WOLFSSL *ssl, char *buf, int sz, void *ctx)
{
    uint8_t sn = sock_from_ctx(ctx);
    int32_t ret;

    (void)ssl;

    ret = recv(sn, (uint8_t *)buf, (uint16_t)sz);

    if (ret > 0)
        return (int)ret;                       /* got `ret` bytes */

    if (ret == SOCK_BUSY)                       /* == 0: nothing to read yet */
        return WOLFSSL_CBIO_ERR_WANT_READ;

    /* Any negative SOCKERR_* means the socket is in trouble (closed by the
     * peer, timed out, etc). Treat it all as "connection gone" and let
     * mqtt_client.c notice the closed socket state and reconnect. */
    printf("mqtt_tls: recv() error %ld\r\n", (long)ret);
    return WOLFSSL_CBIO_ERR_CONN_CLOSE;
}

int MQTT_TLS_IOSend(WOLFSSL *ssl, char *buf, int sz, void *ctx)
{
    uint8_t sn = sock_from_ctx(ctx);
    int32_t ret;

    (void)ssl;

    ret = send(sn, (uint8_t *)buf, (uint16_t)sz);

    if (ret > 0)
        return (int)ret;

    if (ret == SOCK_BUSY)                       /* TX buffer full right now */
        return WOLFSSL_CBIO_ERR_WANT_WRITE;

    printf("mqtt_tls: send() error %ld\r\n", (long)ret);
    return WOLFSSL_CBIO_ERR_CONN_CLOSE;
}

WOLFSSL_CTX *MQTT_TLS_NewContext(void)
{
    WOLFSSL_CTX *ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method());
    if (ctx == NULL)
    {
        printf("mqtt_tls: wolfSSL_CTX_new failed\r\n");
        return NULL;
    }

    /* Embedded CA cert, DER (ASN.1) form - see ca_cert.h. No filesystem on
     * this board, and skipping PEM parsing (base64 + header lines) saves a
     * meaningful amount of flash for a one-cert, never-changes use case. */
    if (wolfSSL_CTX_load_verify_buffer(ctx, g_ca_cert_der, g_ca_cert_der_len,
                                        WOLFSSL_FILETYPE_ASN1) != WOLFSSL_SUCCESS)
    {
        printf("mqtt_tls: failed to load embedded CA cert\r\n");
        wolfSSL_CTX_free(ctx);
        return NULL;
    }

    /* Require and verify the broker's certificate chain against that CA.
     * (This is server-only TLS auth - the board does not present a client
     * certificate. Ask again if you need mutual TLS later.) */
    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, NULL);

    /* Force exactly the suite user_settings.h was tuned for. */
    if (wolfSSL_CTX_set_cipher_list(ctx, "AES128-GCM-SHA256") != WOLFSSL_SUCCESS)
    {
        printf("mqtt_tls: cipher suite not available in this wolfSSL build\r\n");
        wolfSSL_CTX_free(ctx);
        return NULL;
    }

    wolfSSL_CTX_SetIORecv(ctx, MQTT_TLS_IORecv);
    wolfSSL_CTX_SetIOSend(ctx, MQTT_TLS_IOSend);

    return ctx;
}

WOLFSSL *MQTT_TLS_NewSession(WOLFSSL_CTX *ctx, uint8_t sn)
{
    WOLFSSL *ssl = wolfSSL_new(ctx);
    if (ssl == NULL)
    {
        printf("mqtt_tls: wolfSSL_new failed\r\n");
        return NULL;
    }

    wolfSSL_SetIOReadCtx(ssl, (void *)(uintptr_t)sn);
    wolfSSL_SetIOWriteCtx(ssl, (void *)(uintptr_t)sn);

    /* Bench-test setup: we connect to the broker by static IP, and the
     * self-signed test cert from tools/gen_certs.sh is issued for that IP
     * as a SAN. If you instead connect by hostname with a matching SAN,
     * you can drop this line to get real hostname verification back. */
    wolfSSL_check_domain_name(ssl, 0);

    return ssl;
}
