/*
 * secure_cmd.c
 *
 * See secure_cmd.h for the wire format and command list.
 */

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "secure_cmd.h"
#include "socket.h"
#include "main.h"

#include "wolfssl/wolfcrypt/aes.h"

/* ------------------------------------------------------------------ */
/* Pre-shared AES-256 key. MUST match KEY_HEX in hercules_crypto_tool.py
 * exactly (same 32 bytes / 64 hex chars). This one is just a working
 * example generated for this project - swap it for your own random key
 * before you rely on this for anything beyond a bench demo:
 *   python3 -c "import secrets; print(secrets.token_hex(32))"
 */
static const uint8_t SECURE_CMD_KEY[32] = {
    0xb5, 0x7d, 0x00, 0x61, 0xc8, 0x62, 0x0b, 0x2d,
    0xe3, 0x2e, 0xfa, 0x04, 0x5f, 0x23, 0x9c, 0x5c,
    0xf1, 0x1e, 0x8e, 0x05, 0x8d, 0x04, 0x11, 0xcb,
    0x75, 0x41, 0x15, 0xa8, 0x1a, 0x38, 0x08, 0x29
};

#define NONCE_LEN   12
#define TAG_LEN     16
#define MAX_PLAIN   64
/* biggest packet we will ever recv/send: nonce + plaintext + tag */
#define MAX_PACKET  (NONCE_LEN + MAX_PLAIN + TAG_LEN)

#define BLINK_MAX   1000    /* sanity cap so a bogus "BLINK 999999999"
                                can't block the board for an hour */
#define BLINK_ON_MS 150
#define BLINK_OFF_MS 150

static uint8_t s_sock;
static uint32_t s_total_blinks = 0;
static RNG_HandleTypeDef hrng;

/* ------------------------------------------------------------------ */
/* STM32 hardware RNG, used only to make a fresh 12-byte nonce for each
 * reply we send. (Commands coming IN already carry their own nonce,
 * chosen by the Python tool via os.urandom(12).) */
static void RNG_Init(void)
{
    __HAL_RCC_RNG_CLK_ENABLE();
    hrng.Instance = RNG;
    HAL_RNG_Init(&hrng);
}

static void generate_nonce(uint8_t nonce[NONCE_LEN])
{
    uint32_t w;
    for (int i = 0; i < NONCE_LEN; i += 4)
    {
        HAL_RNG_GenerateRandomNumber(&hrng, &w);
        memcpy(&nonce[i], &w, (NONCE_LEN - i >= 4) ? 4 : (NONCE_LEN - i));
    }
}

/* ------------------------------------------------------------------ */
/* Encrypts `plain` (plaintext, `plain_len` bytes, no AAD) into `out`
 * as [12-byte nonce][ciphertext][16-byte tag]. Returns total bytes
 * written to `out`, or 0 on error. `out` must have room for
 * plain_len + NONCE_LEN + TAG_LEN bytes. */
static uint16_t encrypt_packet(const char *plain, uint16_t plain_len, uint8_t *out)
{
    Aes aes;
    uint8_t *nonce = out;
    uint8_t *cipher = out + NONCE_LEN;
    uint8_t *tag = out + NONCE_LEN + plain_len;
    int ret;

    generate_nonce(nonce);

    if (wc_AesInit(&aes, NULL, INVALID_DEVID) != 0)
        return 0;

    ret = wc_AesGcmSetKey(&aes, SECURE_CMD_KEY, sizeof(SECURE_CMD_KEY));
    if (ret == 0)
    {
        ret = wc_AesGcmEncrypt(&aes, cipher, (const uint8_t *)plain, plain_len,
                                nonce, NONCE_LEN, tag, TAG_LEN, NULL, 0);
    }
    wc_AesFree(&aes);

    if (ret != 0)
        return 0;

    return (uint16_t)(NONCE_LEN + plain_len + TAG_LEN);
}

/* Decrypts a received [nonce][ciphertext][tag] packet in place-ish:
 * writes the plaintext into `out` (which must have room for at least
 * pkt_len - NONCE_LEN - TAG_LEN + 1 bytes) and null-terminates it as
 * a C string. Returns plaintext length, or -1 on bad packet / bad tag. */
static int decrypt_packet(const uint8_t *pkt, uint16_t pkt_len, char *out, uint16_t out_cap)
{
    Aes aes;
    const uint8_t *nonce, *cipher, *tag;
    uint16_t cipher_len;
    int ret;

    if (pkt_len < (NONCE_LEN + TAG_LEN))
        return -1; /* too short to even hold nonce+tag with 0-byte payload */

    cipher_len = pkt_len - NONCE_LEN - TAG_LEN;
    if (cipher_len == 0 || cipher_len >= out_cap)
        return -1;

    nonce  = pkt;
    cipher = pkt + NONCE_LEN;
    tag    = pkt + NONCE_LEN + cipher_len;

    if (wc_AesInit(&aes, NULL, INVALID_DEVID) != 0)
        return -1;

    ret = wc_AesGcmSetKey(&aes, SECURE_CMD_KEY, sizeof(SECURE_CMD_KEY));
    if (ret == 0)
    {
        ret = wc_AesGcmDecrypt(&aes, (uint8_t *)out, cipher, cipher_len,
                                nonce, NONCE_LEN, tag, TAG_LEN, NULL, 0);
    }
    wc_AesFree(&aes);

    if (ret != 0)
        return -1; /* wrong key, corrupted packet, or tampered ciphertext */

    out[cipher_len] = '\0';
    return (int)cipher_len;
}

/* ------------------------------------------------------------------ */
static void do_blink(uint32_t n)
{
    if (n > BLINK_MAX)
        n = BLINK_MAX;

    for (uint32_t i = 0; i < n; i++)
    {
        HAL_GPIO_WritePin(LED_GPIO_Port, LED_Pin, GPIO_PIN_SET);
        HAL_Delay(BLINK_ON_MS);
        HAL_GPIO_WritePin(LED_GPIO_Port, LED_Pin, GPIO_PIN_RESET);
        HAL_Delay(BLINK_OFF_MS);
    }
    s_total_blinks += n;
}

/* Parses the decrypted command and fills `reply` with the plaintext
 * response. Returns the reply length. */
static uint16_t handle_command(const char *cmd, char *reply, uint16_t reply_cap)
{
    unsigned long n;
    char *endp;

    if (strncmp(cmd, "BLINK", 5) == 0)
    {
        n = strtoul(cmd + 5, &endp, 10);
        if (endp == cmd + 5 || n == 0)
        {
            return (uint16_t)snprintf(reply, reply_cap, "ERR BADCMD");
        }
        do_blink((uint32_t)n);
        return (uint16_t)snprintf(reply, reply_cap, "OK BLINKED %lu TOTAL %lu",
                                   n, (unsigned long)s_total_blinks);
    }
    else if (strncmp(cmd, "COUNT", 5) == 0)
    {
        return (uint16_t)snprintf(reply, reply_cap, "COUNT %lu",
                                   (unsigned long)s_total_blinks);
    }

    return (uint16_t)snprintf(reply, reply_cap, "ERR BADCMD");
}

/* ------------------------------------------------------------------ */
void SecureCmd_Init(uint8_t socket_num, uint16_t port)
{
    s_sock = socket_num;
    (void)port;
    RNG_Init();
}

void SecureCmd_Task(void)
{
    static uint16_t secure_port = 6000;
    uint8_t rx[MAX_PACKET];
    uint8_t tx[MAX_PACKET];
    char plain[MAX_PLAIN + 1];
    char reply[MAX_PLAIN];
    int32_t len;

    switch (getSn_SR(s_sock))
    {
        case SOCK_CLOSED:
            socket(s_sock, Sn_MR_TCP, secure_port, SF_IO_NONBLOCK);
            break;

        case SOCK_INIT:
            listen(s_sock);
            break;

        case SOCK_ESTABLISHED:
            if (getSn_IR(s_sock) & Sn_IR_CON)
            {
                setSn_IR(s_sock, Sn_IR_CON);
            }

            len = recv(s_sock, rx, sizeof(rx));
            if (len > 0)
            {
                int plain_len = decrypt_packet(rx, (uint16_t)len, plain, sizeof(plain));
                if (plain_len > 0)
                {
                    uint16_t reply_len = handle_command(plain, reply, sizeof(reply));
                    uint16_t pkt_len = encrypt_packet(reply, reply_len, tx);
                    if (pkt_len > 0)
                    {
                        send(s_sock, tx, pkt_len);
                    }
                    printf("secure_cmd: '%s' -> '%s'\r\n", plain, reply);
                }
                else
                {
                    /* Bad tag / malformed packet: say nothing, just log
                     * locally and drop the connection below. */
                    printf("secure_cmd: decrypt/auth failed (%ld bytes in)\r\n", (long)len);
                }
                disconnect(s_sock);
            }
            break;

        case SOCK_CLOSE_WAIT:
            disconnect(s_sock);
            break;

        default:
            break;
    }
}
