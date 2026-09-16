/*
 * w5500_port.h
 *
 * Low level glue between the STM32 HAL (SPI2 + GPIO) and WIZnet's
 * ioLibrary_Driver (wizchip_conf / socket / W5500 register driver).
 *
 * Wiring used in this project (from the CubeMX .ioc):
 *   SPI2_SCK  -> PI1
 *   SPI2_MISO -> PB14
 *   SPI2_MOSI -> PB15
 *   SCS (CS)  -> PA8   (soft NSS, manual GPIO)
 *   RST       -> PA15  (manual GPIO)
 */

#ifndef __W5500_PORT_H
#define __W5500_PORT_H

#ifdef __cplusplus
extern "C" {
#endif

#include "main.h"

/* Give the port layer a pointer to the SPI handle used for the W5500. */
void W5500_Port_Init(SPI_HandleTypeDef *hspi);

/* Hardware-resets the W5500 using the RST pin and registers all the
 * wizchip_conf callbacks (CS select/deselect, SPI byte/burst r/w,
 * critical section enter/exit). Call this once, after MX_SPI2_Init(). */
void W5500_HW_Reset(void);

/* Runs wizchip_init() with default 2KB/2KB per-socket buffers and
 * sets the local MAC address. Call after W5500_HW_Reset(). */
void W5500_ChipInit(uint8_t mac[6]);

#ifdef __cplusplus
}
#endif

#endif /* __W5500_PORT_H */
