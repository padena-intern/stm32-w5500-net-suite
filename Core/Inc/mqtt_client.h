/*
 * mqtt_client.h
 *
 * A small, non-blocking MQTT v3.1.1-over-TLS client for the super-loop
 * in main.c, built on:
 *   - wolfSSL (real TLS 1.2 now, see user_settings.h) for the TLS session
 *   - mqtt_tls_socket.c to bridge wolfSSL's I/O to the W5500
 *   - Paho's MQTTPacket library (Drivers/Paho_MQTTPacket) for wire-format
 *     serialize/deserialize - see the top-level README for why the
 *     transport/threading parts of the full eclipse-paho/paho.mqtt.c repo
 *     aren't used as-is on this bare-metal target.
 *
 * Behaviour (QoS 0 only, matching secure_cmd.c's simplicity):
 *   - Connects to BROKER_IP:BROKER_PORT over TLS
 *   - Subscribes to "stm32/cmd"
 *   - Any message received on "stm32/cmd" is treated as a command, same
 *     set as secure_cmd.c ("BLINK <n>", "COUNT"), and the reply is
 *     published (QoS 0) to "stm32/status"
 *   - Sends PINGREQ often enough to stay under the keepalive interval
 *   - On any TLS/TCP error, tears the connection down and reconnects
 *     after a short backoff - never blocks the super-loop
 */

#ifndef __MQTT_CLIENT_H
#define __MQTT_CLIENT_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

/* Call once, after the W5500 has an IP address (same point in main.c
 * where you currently call SecureCmd_Init()). `sn` is the W5500 socket
 * number to use (pick one not already used by HTTP/secure_cmd/DHCP).
 * `broker_ip` is 4 bytes, e.g. {192,168,1,50}. */
void MQTT_Client_Init(uint8_t sn, const uint8_t broker_ip[4], uint16_t broker_port);

/* Call repeatedly from the main super-loop, alongside HTTPD_LED_Task()
 * and SecureCmd_Task(). Drives the whole connect/handshake/MQTT state
 * machine forward a little bit at a time - never blocks. */
void MQTT_Client_Task(void);

#ifdef __cplusplus
}
#endif

#endif /* __MQTT_CLIENT_H */
