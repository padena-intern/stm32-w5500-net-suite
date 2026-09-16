/*
 * mqtt_client.c
 *
 * See mqtt_client.h for the overview.
 */

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "mqtt_client.h"
#include "mqtt_tls_socket.h"
#include "socket.h"     /* WIZnet: socket()/connect()/getSn_SR()/... */
#include "main.h"       /* LED_GPIO_Port / LED_Pin, HAL_GetTick() */

#include "MQTTPacket.h"

/* ------------------------------------------------------------------ */
#define MQTT_CLIENT_ID      "stm32-board"
#define TOPIC_CMD           "stm32/cmd"
#define TOPIC_STATUS        "stm32/status"
#define KEEPALIVE_SEC       60
#define RECONNECT_BACKOFF_MS 3000

#define MAX_PLAIN   64      /* biggest command/reply we ever handle */
#define RX_BUF_LEN  256     /* one MQTT packet's worth - PUBLISH payloads
                               here are tiny (BLINK/COUNT commands) */
#define TX_BUF_LEN  256

#define BLINK_MAX    1000
#define BLINK_ON_MS  150
#define BLINK_OFF_MS 150

typedef enum
{
    MQTT_ST_IDLE = 0,
    MQTT_ST_SOCK_OPEN,
    MQTT_ST_TCP_CONNECTING,
    MQTT_ST_TLS_HANDSHAKE,
    MQTT_ST_SEND_CONNECT,
    MQTT_ST_WAIT_CONNACK,
    MQTT_ST_SEND_SUBSCRIBE,
    MQTT_ST_WAIT_SUBACK,
    MQTT_ST_CONNECTED,
    MQTT_ST_RECONNECT_WAIT,
} mqtt_state_t;

/* ------------------------------------------------------------------ */
static uint8_t      s_sn;
static uint8_t       s_broker_ip[4];
static uint16_t       s_broker_port;

static WOLFSSL_CTX  *s_ctx  = NULL;   /* created once, reused across reconnects */
static WOLFSSL      *s_ssl  = NULL;   /* fresh per TCP connection */

static mqtt_state_t  s_state = MQTT_ST_IDLE;
static uint32_t       s_state_deadline_ms;   /* used by RECONNECT_WAIT */
static uint32_t       s_last_activity_ms;    /* for PINGREQ keepalive */

/* Non-blocking outgoing write: filled once by mqtt_send(), then drained
 * a little bit at a time by mqtt_tx_pump() on however many Task() calls
 * it takes for wolfSSL to accept all of it. */
static uint8_t  s_tx_buf[TX_BUF_LEN];
static int      s_tx_len   = 0;
static int      s_tx_sent  = 0;

/* Non-blocking incoming packet reassembly (Paho's own state machine -
 * see MQTTPacket_readnb() in MQTTPacket.c). */
static uint8_t        s_rx_buf[RX_BUF_LEN];
static MQTTTransport   s_rx_trp;
static uint32_t         s_total_blinks = 0;

/* ------------------------------------------------------------------ */
/* getfn for MQTTPacket_readnb(): sck is our WOLFSSL* session, stashed in
 * s_rx_trp.sck. Returns -1 on real error, 0 for "no data yet, call me
 * again", or the number of bytes actually placed in buf (can be less
 * than count - MQTTPacket_readnb() copes with partial reads). */
static int mqtt_getfn(void *sck, unsigned char *buf, int count)
{
    WOLFSSL *ssl = (WOLFSSL *)sck;
    int n = wolfSSL_read(ssl, buf, count);

    if (n > 0)
        return n;

    {
        int err = wolfSSL_get_error(ssl, n);
        if (err == WOLFSSL_ERROR_WANT_READ)
            return 0;               /* nothing yet, try again next Task() */
        if (n == 0)
            return -1;               /* peer closed cleanly */
        printf("mqtt: wolfSSL_read error %d\r\n", err);
        return -1;
    }
}

/* Queues `len` bytes for sending. Only one packet may be in flight at a
 * time (fine for our tiny CONNECT/SUBSCRIBE/PUBLISH/PINGREQ traffic) -
 * caller must wait for the previous one to drain (s_tx_len == 0) first. */
static int mqtt_send(const uint8_t *buf, int len)
{
    if (len > TX_BUF_LEN)
        return -1;
    memcpy(s_tx_buf, buf, len);
    s_tx_len  = len;
    s_tx_sent = 0;
    return 0;
}

/* Call every Task() tick while s_tx_len > 0. Non-blocking: pushes as much
 * as wolfSSL/W5500 will currently accept, resets s_tx_len to 0 once the
 * whole buffer is out. */
static void mqtt_tx_pump(void)
{
    if (s_tx_len == 0 || s_ssl == NULL)
        return;

    int n = wolfSSL_write(s_ssl, s_tx_buf + s_tx_sent, s_tx_len - s_tx_sent);
    if (n > 0)
    {
        s_tx_sent += n;
        if (s_tx_sent >= s_tx_len)
        {
            s_tx_len = 0;
            s_tx_sent = 0;
            s_last_activity_ms = HAL_GetTick();
        }
        return;
    }

    int err = wolfSSL_get_error(s_ssl, n);
    if (err != WOLFSSL_ERROR_WANT_WRITE && err != WOLFSSL_ERROR_WANT_READ)
    {
        printf("mqtt: wolfSSL_write error %d\r\n", err);
        s_state = MQTT_ST_RECONNECT_WAIT;
        s_state_deadline_ms = HAL_GetTick() + RECONNECT_BACKOFF_MS;
    }
    /* else: try again next Task() call */
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

/* Same command set/behaviour as secure_cmd.c's handle_command(), just
 * carried over MQTT+TLS now instead of a raw AES-GCM socket. */
static int handle_command(const char *cmd, char *reply, int reply_cap)
{
    unsigned long n;
    char *endp;

    if (strncmp(cmd, "BLINK", 5) == 0)
    {
        n = strtoul(cmd + 5, &endp, 10);
        if (endp == cmd + 5 || n == 0)
            return snprintf(reply, reply_cap, "ERR BADCMD");
        do_blink((uint32_t)n);
        return snprintf(reply, reply_cap, "OK BLINKED %lu TOTAL %lu",
                         n, (unsigned long)s_total_blinks);
    }
    if (strncmp(cmd, "COUNT", 5) == 0)
        return snprintf(reply, reply_cap, "COUNT %lu", (unsigned long)s_total_blinks);

    return snprintf(reply, reply_cap, "ERR BADCMD");
}

/* Builds and queues a QoS-0 PUBLISH to TOPIC_STATUS. Serializes straight
 * into a local buffer, then hands it to mqtt_send() (which copies it
 * into s_tx_buf) - only called from MQTT_ST_CONNECTED, where nothing
 * else is mid-flight when a command reply needs to go out. */
static void publish_status(const char *payload, int payload_len)
{
    uint8_t buf[TX_BUF_LEN];
    MQTTString topic = MQTTString_initializer;
    topic.cstring = TOPIC_STATUS;

    int len = MQTTSerialize_publish(buf, TX_BUF_LEN,
                                     0 /*dup*/, 0 /*qos*/, 0 /*retained*/, 0 /*packetid, unused for qos0*/,
                                     topic, (unsigned char *)payload, payload_len);
    if (len > 0)
        mqtt_send(buf, len);
}

/* Handles one fully-received incoming packet (buf/len from s_rx_buf). */
static void handle_incoming_publish(unsigned char *buf, int len)
{
    unsigned char dup, retained;
    unsigned short packetid;
    int qos;
    MQTTString topicName;
    unsigned char *payload;
    int payloadlen;
    char cmd[MAX_PLAIN + 1];
    char reply[MAX_PLAIN];

    if (!MQTTDeserialize_publish(&dup, &qos, &retained, &packetid, &topicName,
                                  &payload, &payloadlen, buf, len))
        return;

    if (!MQTTPacket_equals(&topicName, TOPIC_CMD))
        return; /* not for us */

    if (payloadlen <= 0 || payloadlen > MAX_PLAIN)
        return;
    memcpy(cmd, payload, payloadlen);
    cmd[payloadlen] = '\0';

    int reply_len = handle_command(cmd, reply, sizeof(reply));
    printf("mqtt: '%s' -> '%s'\r\n", cmd, reply);
    publish_status(reply, reply_len);
}

/* ------------------------------------------------------------------ */
static void teardown_connection(void)
{
    if (s_ssl)
    {
        wolfSSL_free(s_ssl);
        s_ssl = NULL;
    }
    disconnect(s_sn);
    close(s_sn);
    s_tx_len = 0;
    s_tx_sent = 0;
    memset(&s_rx_trp, 0, sizeof(s_rx_trp));
}

static void go_reconnect(const char *why)
{
    printf("mqtt: %s - reconnecting in %d ms\r\n", why, RECONNECT_BACKOFF_MS);
    teardown_connection();
    s_state = MQTT_ST_RECONNECT_WAIT;
    s_state_deadline_ms = HAL_GetTick() + RECONNECT_BACKOFF_MS;
}

/* ------------------------------------------------------------------ */
void MQTT_Client_Init(uint8_t sn, const uint8_t broker_ip[4], uint16_t broker_port)
{
    s_sn = sn;
    memcpy(s_broker_ip, broker_ip, 4);
    s_broker_port = broker_port;

    s_ctx = MQTT_TLS_NewContext();
    if (s_ctx == NULL)
    {
        printf("mqtt: TLS context init failed - MQTT client disabled\r\n");
        s_state = MQTT_ST_IDLE;
        return;
    }

    s_state = MQTT_ST_SOCK_OPEN;
}

void MQTT_Client_Task(void)
{
    if (s_ctx == NULL)
        return; /* init failed, nothing to do */

    switch (s_state)
    {
    case MQTT_ST_IDLE:
        break;

    case MQTT_ST_SOCK_OPEN:
        if (socket(s_sn, Sn_MR_TCP, 0, SF_IO_NONBLOCK) == s_sn)
        {
            s_state = MQTT_ST_TCP_CONNECTING;
        }
        break;

    case MQTT_ST_TCP_CONNECTING:
    {
        uint8_t status = getSn_SR(s_sn);

        printf("mqtt: socket status = 0x%02X\r\n", status);

        if (status == SOCK_INIT)
        {
            int32_t rc = connect(s_sn, s_broker_ip, s_broker_port);

            printf("mqtt: connect() returned = %ld\r\n", (long)rc);
            printf("mqtt: DIPR=%d.%d.%d.%d\r\n",
                   s_broker_ip[0], s_broker_ip[1],
                   s_broker_ip[2], s_broker_ip[3]);
            printf("mqtt: DPORT=%u\r\n", s_broker_port);
        }
        else if (status == SOCK_ESTABLISHED)
        {
            printf("mqtt: TCP ESTABLISHED\r\n");

            s_ssl = MQTT_TLS_NewSession(s_ctx, s_sn);

            if (s_ssl == NULL)
            {
                go_reconnect("wolfSSL_new failed");
                break;
            }

            s_state = MQTT_ST_TLS_HANDSHAKE;
        }
        else if (status == SOCK_CLOSED)
        {
            printf("mqtt: socket CLOSED\r\n");
            printf("mqtt: Sn_IR=0x%02X\r\n", getSn_IR(s_sn));
            printf("mqtt: Sn_SR=0x%02X\r\n", getSn_SR(s_sn));
            go_reconnect("TCP connect failed");
        }

        break;
    }

    case MQTT_ST_TLS_HANDSHAKE:
    {
        int rc = wolfSSL_connect(s_ssl);
        if (rc == WOLFSSL_SUCCESS)
        {
            printf("mqtt: TLS handshake OK (cipher: %s)\r\n",
                   wolfSSL_get_cipher(s_ssl));
            s_state = MQTT_ST_SEND_CONNECT;
        }
        else
        {
            int err = wolfSSL_get_error(s_ssl, rc);
            if (err != WOLFSSL_ERROR_WANT_READ && err != WOLFSSL_ERROR_WANT_WRITE)
            {
                char errbuf[80];
                wolfSSL_ERR_error_string(err, errbuf);
                printf("mqtt: TLS handshake failed: %s\r\n", errbuf);
                go_reconnect("TLS handshake failed");
            }
            /* else: handshake in progress, call wolfSSL_connect() again
             * next Task() tick */
        }
        break;
    }

    case MQTT_ST_SEND_CONNECT:
    {
        MQTTPacket_connectData data = MQTTPacket_connectData_initializer;
        data.MQTTVersion = 4; /* MQTT 3.1.1 */
        data.clientID.cstring = MQTT_CLIENT_ID;
        data.keepAliveInterval = KEEPALIVE_SEC;
        data.cleansession = 1;

        int len = MQTTSerialize_connect(s_tx_buf, TX_BUF_LEN, &data);
        if (len <= 0 || mqtt_send(s_tx_buf, len) != 0)
        {
            go_reconnect("failed to build CONNECT packet");
            break;
        }
        memset(&s_rx_trp, 0, sizeof(s_rx_trp));
        s_rx_trp.getfn = mqtt_getfn;
        s_rx_trp.sck = s_ssl;
        s_state = MQTT_ST_WAIT_CONNACK;
        break;
    }

    case MQTT_ST_WAIT_CONNACK:
        mqtt_tx_pump();
        if (s_state != MQTT_ST_WAIT_CONNACK)
            break; /* mqtt_tx_pump() bailed us out to RECONNECT_WAIT */
        if (s_tx_len != 0)
            break; /* still sending the CONNECT packet */

        {
            int ptype = MQTTPacket_readnb(s_rx_buf, RX_BUF_LEN, &s_rx_trp);
            if (ptype < 0)
            {
                go_reconnect("error waiting for CONNACK");
            }
            else if (ptype == CONNACK)
            {
                unsigned char sessionPresent, connack_rc;
                if (MQTTDeserialize_connack(&sessionPresent, &connack_rc,
                                             s_rx_buf, RX_BUF_LEN) != 1
                    || connack_rc != 0)
                {
                    go_reconnect("broker rejected CONNECT");
                }
                else
                {
                    printf("mqtt: CONNACK OK\r\n");
                    s_state = MQTT_ST_SEND_SUBSCRIBE;
                }
            }
            /* ptype == 0: nothing yet, keep waiting */
        }
        break;

    case MQTT_ST_SEND_SUBSCRIBE:
    {
        MQTTString topic = MQTTString_initializer;
        topic.cstring = TOPIC_CMD;
        int reqQos = 0;

        int len = MQTTSerialize_subscribe(s_tx_buf, TX_BUF_LEN, 0 /*dup*/,
                                           1 /*packetid*/, 1 /*count*/, &topic, &reqQos);
        if (len <= 0 || mqtt_send(s_tx_buf, len) != 0)
        {
            go_reconnect("failed to build SUBSCRIBE packet");
            break;
        }
        s_state = MQTT_ST_WAIT_SUBACK;
        break;
    }

    case MQTT_ST_WAIT_SUBACK:
        mqtt_tx_pump();
        if (s_state != MQTT_ST_WAIT_SUBACK)
            break;
        if (s_tx_len != 0)
            break;

        {
            int ptype = MQTTPacket_readnb(s_rx_buf, RX_BUF_LEN, &s_rx_trp);
            if (ptype < 0)
            {
                go_reconnect("error waiting for SUBACK");
            }
            else if (ptype == SUBACK)
            {
                unsigned short packetid;
                int count, grantedQoS;
                if (MQTTDeserialize_suback(&packetid, 1, &count, &grantedQoS,
                                            s_rx_buf, RX_BUF_LEN) != 1)
                {
                    go_reconnect("bad SUBACK");
                }
                else
                {
                    printf("mqtt: subscribed to %s (granted QoS %d)\r\n",
                           TOPIC_CMD, grantedQoS);
                    s_last_activity_ms = HAL_GetTick();
                    s_state = MQTT_ST_CONNECTED;
                }
            }
        }
        break;

    case MQTT_ST_CONNECTED:
    {
        mqtt_tx_pump();
        if (s_state != MQTT_ST_CONNECTED)
            break;

        /* Keepalive: send PINGREQ well before KEEPALIVE_SEC elapses,
         * but only once any previous outgoing packet has drained. */
        if (s_tx_len == 0 &&
            (HAL_GetTick() - s_last_activity_ms) > (uint32_t)(KEEPALIVE_SEC * 1000 / 2))
        {
            int len = MQTTSerialize_pingreq(s_tx_buf, TX_BUF_LEN);
            if (len > 0)
                mqtt_send(s_tx_buf, len);
        }

        int ptype = MQTTPacket_readnb(s_rx_buf, RX_BUF_LEN, &s_rx_trp);
        if (ptype < 0)
        {
            go_reconnect("connection lost");
        }
        else if (ptype == PUBLISH)
        {
            handle_incoming_publish(s_rx_buf, RX_BUF_LEN);
        }
        else if (ptype == PINGRESP)
        {
            s_last_activity_ms = HAL_GetTick();
        }
        /* ptype == 0: nothing arrived this tick, that's normal */
        break;
    }

    case MQTT_ST_RECONNECT_WAIT:
        if ((int32_t)(HAL_GetTick() - s_state_deadline_ms) >= 0)
            s_state = MQTT_ST_SOCK_OPEN;
        break;
    }
}
