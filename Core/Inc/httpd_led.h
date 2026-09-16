#ifndef __HTTPD_LED_H
#define __HTTPD_LED_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

/* Call once, after the W5500 has an IP address (static or via DHCP). */
void HTTPD_LED_Init(uint8_t socket_num, uint16_t port);

/* Call repeatedly from the main super-loop. Non-blocking-ish: handles at
 * most one TCP connection at a time, which is enough for a status page
 * a person refreshes/clicks from a browser. */
void HTTPD_LED_Task(void);

#ifdef __cplusplus
}
#endif

#endif /* __HTTPD_LED_H */
