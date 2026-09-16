#include <string.h>
#include "w5500_port.h"
#include "wizchip_conf.h"
#include "w5500.h"

static SPI_HandleTypeDef *w5500_hspi = NULL;

/* ---- critical section (used while a single SPI transaction is in
 * progress so interrupts can't split a multi-byte register access) ---- */
static void W5500_CrisEnter(void)  { __disable_irq(); }
static void W5500_CrisExit(void)   { __enable_irq();  }

/* ---- chip select ---- */
static void W5500_CS_Select(void)   { HAL_GPIO_WritePin(SCS_GPIO_Port, SCS_Pin, GPIO_PIN_RESET); }
static void W5500_CS_Deselect(void) { HAL_GPIO_WritePin(SCS_GPIO_Port, SCS_Pin, GPIO_PIN_SET);   }

/* ---- single byte SPI read/write ---- */
static uint8_t W5500_SPI_ReadByte(void)
{
    uint8_t rx = 0xFF;
    uint8_t tx = 0xFF;
    HAL_SPI_TransmitReceive(w5500_hspi, &tx, &rx, 1, HAL_MAX_DELAY);
    return rx;
}

static void W5500_SPI_WriteByte(uint8_t wb)
{
    uint8_t rx;
    HAL_SPI_TransmitReceive(w5500_hspi, &wb, &rx, 1, HAL_MAX_DELAY);
}

/* ---- burst (multi-byte) SPI read/write, much faster than the
 * byte-at-a-time callbacks above ---- */
static void W5500_SPI_ReadBurst(uint8_t *pBuf, uint16_t len)
{
    uint8_t dummy = 0xFF;
    /* Send dummy bytes while shifting in the real data. HAL_SPI_TransmitReceive
     * would also work but needs a same-size TX buffer; using a 1-byte dummy
     * source repeated is not directly supported by the HAL, so fall back to
     * per-byte transmit/receive using the SPI peripheral directly. */
    for (uint16_t i = 0; i < len; i++)
    {
        HAL_SPI_TransmitReceive(w5500_hspi, &dummy, &pBuf[i], 1, HAL_MAX_DELAY);
    }
}

static void W5500_SPI_WriteBurst(uint8_t *pBuf, uint16_t len)
{
    uint8_t rx;
    for (uint16_t i = 0; i < len; i++)
    {
        HAL_SPI_TransmitReceive(w5500_hspi, &pBuf[i], &rx, 1, HAL_MAX_DELAY);
    }
}

void W5500_Port_Init(SPI_HandleTypeDef *hspi)
{
    w5500_hspi = hspi;
}

void W5500_HW_Reset(void)
{
    /* W5500 datasheet: RSTn must be held low for at least 500us, and the
     * chip needs some time after release before the host can access it. */
    HAL_GPIO_WritePin(RST_GPIO_Port, RST_Pin, GPIO_PIN_RESET);
    HAL_Delay(2);
    HAL_GPIO_WritePin(RST_GPIO_Port, RST_Pin, GPIO_PIN_SET);
    HAL_Delay(2);

    HAL_GPIO_WritePin(SCS_GPIO_Port, SCS_Pin, GPIO_PIN_SET);

    reg_wizchip_cris_cbfunc(W5500_CrisEnter, W5500_CrisExit);
    reg_wizchip_cs_cbfunc(W5500_CS_Select, W5500_CS_Deselect);
    reg_wizchip_spi_cbfunc(W5500_SPI_ReadByte, W5500_SPI_WriteByte);
    reg_wizchip_spiburst_cbfunc(W5500_SPI_ReadBurst, W5500_SPI_WriteBurst);
}

void W5500_ChipInit(uint8_t mac[6])
{
    /* 2KB RX/TX buffer per socket x 8 sockets = 16KB, matches the W5500's
     * total 32KB (16KB TX + 16KB RX) internal memory. */
    uint8_t memsize[2][8] = { {2,2,2,2,2,2,2,2}, {2,2,2,2,2,2,2,2} };

    wizchip_init(memsize[0], memsize[1]);

    /* IP/GW/SN/DNS are filled in by main.c, either statically or via DHCP,
     * using wizchip_setnetinfo(). We only set the MAC here so an early
     * setSHAR() is available before DHCP sends its DISCOVER packet. */
    setSHAR(mac);
}
