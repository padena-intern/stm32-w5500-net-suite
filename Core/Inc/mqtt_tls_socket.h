/*
 * mqtt_tls_socket.h
 *
 * Bridges wolfSSL's custom I/O callback API (WOLFSSL_USER_IO, see
 * user_settings.h) to the WIZnet ioLibrary_Driver socket API used by the
 * W5500 (the same socket()/connect()/send()/recv() that httpd_led.c and
 * secure_cmd.c already use).
 *
 * wolfSSL never touches the network directly here - every byte it wants
 * to send or receive goes through TLS_Send()/TLS_Recv() below, which are
 * registered as its I/O callbacks. Both are NON-BLOCKING: they return
 * WOLFSSL_CBIO_ERR_WANT_READ / WANT_WRITE immediately if the W5500 has no
 * data yet / can't accept more data yet, which lets wolfSSL_connect(),
 * wolfSSL_read() and wolfSSL_write() all be driven a little bit at a time
 * from the main super-loop (mqtt_client.c), same style as the existing
 * HTTPD_LED_Task()/SecureCmd_Task() state machines - nothing in this
 * project ever blocks waiting on the network.
 */

#ifndef __MQTT_TLS_SOCKET_H
#define __MQTT_TLS_SOCKET_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include "wolfssl/ssl.h"

/* Call once at startup (order doesn't matter relative to W5500_ChipInit,
 * as long as both happen before MQTT_TLS_NewContext()). Loads the
 * embedded CA certificate (ca_cert.h) into a fresh WOLFSSL_CTX configured
 * for TLS 1.2 client, RSA cert verification, TLS_RSA_WITH_AES_128_GCM_SHA256.
 * Returns NULL on failure (bad/missing CA DER, out of memory, etc). */
WOLFSSL_CTX *MQTT_TLS_NewContext(void);

/* Creates a new WOLFSSL session object bound to W5500 socket `sn` and
 * registers the I/O callbacks below against it. Call once per TCP
 * connection attempt (i.e. every time you reconnect). */
WOLFSSL *MQTT_TLS_NewSession(WOLFSSL_CTX *ctx, uint8_t sn);

/* wolfSSL custom I/O callbacks - registered internally by
 * MQTT_TLS_NewContext()/MQTT_TLS_NewSession(), not meant to be called
 * directly by application code. Declared here only so mqtt_tls_socket.c
 * and the wolfSSL headers agree on the prototype. */
int MQTT_TLS_IORecv(WOLFSSL *ssl, char *buf, int sz, void *ctx);
int MQTT_TLS_IOSend(WOLFSSL *ssl, char *buf, int sz, void *ctx);

/* wolfSSL's entropy source (STM32 hardware TRNG), registered via
 * CUSTOM_RAND_GENERATE_SEED in user_settings.h - not meant to be called
 * directly by application code. Declared here so user_settings.h's
 * reference to it type-checks against this definition. */
int MQTT_TLS_SeedRNG(unsigned char *output, unsigned int sz);

#ifdef __cplusplus
}
#endif

#endif /* __MQTT_TLS_SOCKET_H */
