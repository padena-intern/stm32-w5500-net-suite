/*
 * secure_cmd.h
 *
 * Encrypted command channel: a raw TCP socket (separate from the plain
 * HTTP LED page in httpd_led.c) that accepts AES-256-GCM encrypted
 * commands and replies with AES-256-GCM encrypted responses.
 *
 * Wire format, in both directions, sent as ONE TCP write (this mirrors
 * how Hercules' "TCP client" panel sends whatever you paste into the Send
 * box as a single packet, and matches the existing HTTPD_LED_Task style
 * of "one recv -> handle -> one send -> disconnect" in this project):
 *
 *   [ 12 bytes nonce/IV ][ N bytes ciphertext ][ 16 bytes GCM tag ]
 *
 * The plaintext (before encryption / after decryption) is a short ASCII
 * command, no framing needed beyond that:
 *
 *   Commands you send in:
 *     "BLINK <n>"   - blink the LED n times (1-1000)
 *     "COUNT"       - ask for the total blink count since boot
 *
 *   Replies you get back:
 *     "OK BLINKED <n> TOTAL <total>"
 *     "COUNT <total>"
 *     "ERR BADCMD"
 *
 * On a decrypt/authentication failure the socket is just closed with no
 * reply (never "helpfully" tell an attacker whether the tag or the
 * plaintext was the problem).
 *
 * The pre-shared AES-256 key is defined in secure_cmd.c (SECURE_CMD_KEY).
 * The Python tool (hercules_crypto_tool.py) must use the exact same key.
 */

#ifndef __SECURE_CMD_H
#define __SECURE_CMD_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

/* Call once, after the W5500 has an IP address. Also brings up the STM32
 * hardware RNG peripheral (used to generate the nonce for each reply). */
void SecureCmd_Init(uint8_t socket_num, uint16_t port);

/* Call repeatedly from the main super-loop, alongside HTTPD_LED_Task(). */
void SecureCmd_Task(void);

#ifdef __cplusplus
}
#endif

#endif /* __SECURE_CMD_H */
