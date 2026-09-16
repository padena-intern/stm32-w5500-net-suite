#include <string.h>
#include <stdio.h>
#include "httpd_led.h"
#include "socket.h"
#include "main.h"

/* The LED pin (LED_Pin / LED_GPIO_Port) is defined in main.h. See the
 * comment there for why PB1 was picked instead of the on-board LD1. */

static uint8_t s_sock;

static const char HTTP_200_HDR[] =
    "HTTP/1.1 200 OK\r\n"
    "Content-Type: text/html; charset=utf-8\r\n"
    "Connection: close\r\n\r\n";

/* Kept short and dependency-free on purpose: a single self-contained page
 * with two buttons that just navigate to /led/on and /led/off. The page
 * also shows the LED's current state. */
static void build_page(char *out, size_t out_size, uint8_t led_is_on)
{
    snprintf(out, out_size,
        "%s"
        "<!DOCTYPE html><html lang=\"fa\" dir=\"rtl\"><head>"
        "<meta charset=\"UTF-8\">"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
        "<title>STM32 W5500 LED Control</title>"
        "<style>"
        "body{font-family:Tahoma,Arial,sans-serif;background:#111;color:#eee;"
        "display:flex;flex-direction:column;align-items:center;justify-content:center;"
        "height:100vh;margin:0;text-align:center}"
        "h1{font-size:1.4rem;margin-bottom:0.3rem}"
        ".state{font-size:1.1rem;margin-bottom:1.5rem}"
        ".on{color:#4caf50;font-weight:bold}"
        ".off{color:#f44336;font-weight:bold}"
        "a{display:inline-block;margin:0.5rem;padding:1rem 2rem;font-size:1.1rem;"
        "border-radius:10px;text-decoration:none;color:#fff;min-width:120px}"
        ".btn-on{background:#2e7d32}"
        ".btn-off{background:#c62828}"
        "</style></head><body>"
        "<h1>STM32F746 + W5500 &mdash; LED Control</h1>"
        "<div class=\"state\">LED: <span class=\"%s\">%s</span></div>"
        "<div>"
        "<a class=\"btn-on\" href=\"/led/on\">Turn ON</a>"
        "<a class=\"btn-off\" href=\"/led/off\">Turn OFF</a>"
        "</div>"
        "</body></html>",
        HTTP_200_HDR,
        led_is_on ? "on" : "off",
        led_is_on ? "ON" : "OFF");
}

void HTTPD_LED_Init(uint8_t socket_num, uint16_t port)
{
    s_sock = socket_num;
    /* Socket is (re)opened lazily inside HTTPD_LED_Task() once its state
     * machine sees SOCK_CLOSED, so we just remember sn/port here. */
    (void)port;
}

void HTTPD_LED_Task(void)
{
    static uint16_t http_port = 80;
    uint8_t buf[512];
    int32_t len;
    char page[1400];

    switch (getSn_SR(s_sock))
    {
        case SOCK_CLOSED:
            socket(s_sock, Sn_MR_TCP, http_port, SF_IO_NONBLOCK);
            break;

        case SOCK_INIT:
            listen(s_sock);
            break;

        case SOCK_ESTABLISHED:
            if (getSn_IR(s_sock) & Sn_IR_CON)
            {
                setSn_IR(s_sock, Sn_IR_CON);
            }

            len = recv(s_sock, buf, sizeof(buf) - 1);
            if (len > 0)
            {
                buf[len] = '\0';

                if (strstr((char *)buf, "GET /led/on") != NULL)
                {
                    HAL_GPIO_WritePin(LED_GPIO_Port, LED_Pin, GPIO_PIN_SET);
                }
                else if (strstr((char *)buf, "GET /led/off") != NULL)
                {
                    HAL_GPIO_WritePin(LED_GPIO_Port, LED_Pin, GPIO_PIN_RESET);
                }
                /* any other path (e.g. "/") just falls through and shows
                 * the current state without changing it */

                uint8_t led_is_on =
                    (HAL_GPIO_ReadPin(LED_GPIO_Port, LED_Pin) == GPIO_PIN_SET);
                build_page(page, sizeof(page), led_is_on);

                send(s_sock, (uint8_t *)page, (uint16_t)strlen(page));
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
