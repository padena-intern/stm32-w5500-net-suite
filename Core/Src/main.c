/* USER CODE BEGIN Header */
/**
  ******************************************************************************
  * @file           : main.c
  * @brief          : Main program body
  *                   STM32F746 + W5500 (SPI2) web-controlled LED demo.
  ******************************************************************************
  */
/* USER CODE END Header */
/* Includes ------------------------------------------------------------------*/
#include "main.h"

/* Private includes ----------------------------------------------------------*/
/* USER CODE BEGIN Includes */
#include <string.h>
#include <stdio.h>
#include "wizchip_conf.h"
#include "socket.h"
#include "dhcp.h"
#include "w5500_port.h"
#include "httpd_led.h"
#include "secure_cmd.h"
#include "mqtt_client.h"
/* USER CODE END Includes */

/* Private typedef -----------------------------------------------------------*/
/* Private define ------------------------------------------------------------*/
/* USER CODE BEGIN PD */

/* Pick ONE network mode: */
#define USE_DHCP            1   /* 1 = get IP automatically from the WiFi router
                                   0 = use the STATIC_* settings below instead */

/* Only used if USE_DHCP is 0. Must be inside your router's LAN/WiFi subnet. */
static uint8_t STATIC_IP[4]  = {192, 168, 1, 177};
static uint8_t STATIC_GW[4]  = {192, 168, 1, 1};
static uint8_t STATIC_SN[4]  = {255, 255, 255, 0};
static uint8_t STATIC_DNS[4] = {192, 168, 1, 1};

/* Any locally-administered MAC is fine as long as it's unique on your LAN. */
static uint8_t MAC_ADDR[6] = {0x00, 0x08, 0xDC, 0x01, 0x02, 0x03};

#define HTTP_SOCKET   0
#define HTTP_PORT     80

/* Raw TCP socket carrying AES-256-GCM encrypted LED-blink commands - see
 * secure_cmd.h. Talk to it from hercules_crypto_tool.py + the Hercules
 * TCP client (Hex send/receive mode), not from a browser. */
#define SECURE_SOCKET 2
#define SECURE_PORT   6000

/* MQTT-over-TLS client socket - talks to a broker on your laptop
 * (tools/mosquitto_test.conf). Set this to your laptop's actual LAN IP
 * and re-run tools/gen_certs.sh <that-ip> before building. */
#define MQTT_SOCKET   3
#define MQTT_PORT     8883
static uint8_t MQTT_BROKER_IP[4] = {192, 168, 1, 10};

#if USE_DHCP
#define DHCP_SOCKET   1
static uint8_t dhcp_buffer[548];
static volatile uint8_t g_ip_assigned = 0;
#endif
/* USER CODE END PD */

/* Private macro -------------------------------------------------------------*/
/* Private variables ---------------------------------------------------------*/

SPI_HandleTypeDef hspi2;

/* USER CODE BEGIN PV */
/* USART1 on PA9(TX)/PB7(RX) is the STM32F746G-DISCOVERY's ST-LINK Virtual
 * COM Port - open it in a serial terminal (115200 8N1) to see debug prints. */
UART_HandleTypeDef huart1;
/* USER CODE END PV */

/* Private function prototypes -----------------------------------------------*/
void SystemClock_Config(void);
static void MPU_Config(void);
static void MX_GPIO_Init(void);
static void MX_SPI2_Init(void);
static void MX_USART1_UART_Init(void);
/* USER CODE BEGIN PFP */
#if USE_DHCP
static void DHCP_IP_Assigned(void);
static void DHCP_IP_Updated(void);
static void DHCP_IP_Conflict(void);
/* Declared (non-static) in dhcp.c but not exposed via dhcp.h - these are
 * the real handlers our callbacks below need to still call. */
extern void default_ip_assign(void);
extern void default_ip_update(void);
extern void default_ip_conflict(void);
#endif
static void Network_Config(void);
/* USER CODE END PFP */

/* Private user code ---------------------------------------------------------*/
/* USER CODE BEGIN 0 */

/* Redirects printf() to USART1 (ST-LINK VCP). Open a serial terminal at
 * 115200 8N1 on the ST-LINK's COM port to see these messages. */
int __io_putchar(int ch)
{
    HAL_UART_Transmit(&huart1, (uint8_t *)&ch, 1, HAL_MAX_DELAY);
    return ch;
}

#if USE_DHCP
static void DHCP_IP_Assigned(void)
{
    /* Must still perform the real register writes the DHCP library expects
     * (SIPR/SUBR/GAR) - the default handler this replaces would otherwise
     * do that for us. Skipping it is why IP/SN/GW stayed 0.0.0.0 even
     * though DHCP itself succeeded. */
    default_ip_assign();
    g_ip_assigned = 1;
}

static void DHCP_IP_Updated(void)
{
    /* Called on lease renewal / IP change - default_ip_update() does its
     * own chip reset + re-applies SIPR/SUBR/GAR/SHAR, so call it instead
     * of just default_ip_assign(). */
    default_ip_update();
    g_ip_assigned = 1;
}

static void DHCP_IP_Conflict(void)
{
    default_ip_conflict();
    g_ip_assigned = 0;
}
#endif

/* Brings up the W5500 chip and gives it an IP address, either from the
 * router's DHCP server (USE_DHCP=1) or from the STATIC_* constants above. */
static void Network_Config(void)
{
    W5500_Port_Init(&hspi2);
    W5500_HW_Reset();
    W5500_ChipInit(MAC_ADDR);

    /* Sanity check: this MUST read back 0x04 on a real W5500. If it reads
     * 0x00 or 0xFF, the STM32 is not actually talking to the chip over SPI
     * (wrong wiring, chip not powered, MISO floating, CS/RST swapped, etc.)
     * and nothing past this point (DHCP, static IP, HTTP) can work. */
    printf("W5500 VERSIONR = 0x%02X (expected 0x04)\r\n", getVERSIONR());

#if USE_DHCP
    wiz_NetInfo net = {0};
    memcpy(net.mac, MAC_ADDR, 6);
    net.dhcp = NETINFO_DHCP;
    wizchip_setnetinfo(&net);

    reg_dhcp_cbfunc(DHCP_IP_Assigned, DHCP_IP_Updated, DHCP_IP_Conflict);
    DHCP_init(DHCP_SOCKET, dhcp_buffer);

    /* Poll DHCP until we get a lease, calling DHCP_time_handler() once per
     * second as required by the library. Times out after ~15s and falls
     * back to the static configuration so the board still boots even
     * without a DHCP server. */
    /* NOTE: DHCP_time_handler() is now called once per second from
     * SysTick_Handler() (see stm32f7xx_it.c), not here. It MUST run from
     * an interrupt that keeps ticking even if DHCP_run() itself blocks
     * (e.g. inside the IP-conflict ARP check), otherwise dhcp_tick_1s can
     * never advance and the firmware hangs forever. */
    uint32_t start = HAL_GetTick();
    while (!g_ip_assigned && (HAL_GetTick() - start) < 15000)
    {
        DHCP_run();
    }

    if (!g_ip_assigned)
    {
        /* DHCP failed: fall back to static configuration below. */
        memcpy(net.mac, MAC_ADDR, 6);
        memcpy(net.ip,  STATIC_IP,  4);
        memcpy(net.sn,  STATIC_SN,  4);
        memcpy(net.gw,  STATIC_GW,  4);
        memcpy(net.dns, STATIC_DNS, 4);
        net.dhcp = NETINFO_STATIC;
        wizchip_setnetinfo(&net);
    }
#else
    wiz_NetInfo net = {0};
    memcpy(net.mac, MAC_ADDR, 6);
    memcpy(net.ip,  STATIC_IP,  4);
    memcpy(net.sn,  STATIC_SN,  4);
    memcpy(net.gw,  STATIC_GW,  4);
    memcpy(net.dns, STATIC_DNS, 4);
    net.dhcp = NETINFO_STATIC;
    wizchip_setnetinfo(&net);
#endif
}
/* USER CODE END 0 */

/**
  * @brief  The application entry point.
  * @retval int
  */
int main(void)
{

  /* USER CODE BEGIN 1 */

  /* USER CODE END 1 */

  /* MPU Configuration--------------------------------------------------------*/
  MPU_Config();

  /* MCU Configuration--------------------------------------------------------*/

  /* Reset of all peripherals, Initializes the Flash interface and the Systick. */
  HAL_Init();

  /* USER CODE BEGIN Init */

  /* USER CODE END Init */

  /* Configure the system clock */
  SystemClock_Config();

  /* USER CODE BEGIN SysInit */

  /* USER CODE END SysInit */

  /* Initialize all configured peripherals */
  MX_GPIO_Init();
  MX_SPI2_Init();
  MX_USART1_UART_Init();
  /* USER CODE BEGIN 2 */

  printf("\r\n\r\n--- STM32F746 + W5500 Web LED demo booting ---\r\n");

  Network_Config();
  HTTPD_LED_Init(HTTP_SOCKET, HTTP_PORT);
  SecureCmd_Init(SECURE_SOCKET, SECURE_PORT);
  MQTT_Client_Init(MQTT_SOCKET, MQTT_BROKER_IP, MQTT_PORT);

  {
      wiz_NetInfo net;
      wizchip_getnetinfo(&net);
      printf("Network mode : %s\r\n", (net.dhcp == NETINFO_DHCP) ? "DHCP" : "STATIC");
      printf("IP address   : %d.%d.%d.%d\r\n", net.ip[0], net.ip[1], net.ip[2], net.ip[3]);
      printf("Subnet mask  : %d.%d.%d.%d\r\n", net.sn[0], net.sn[1], net.sn[2], net.sn[3]);
      printf("Gateway      : %d.%d.%d.%d\r\n", net.gw[0], net.gw[1], net.gw[2], net.gw[3]);
      printf("Open this in a browser: http://%d.%d.%d.%d/\r\n",
             net.ip[0], net.ip[1], net.ip[2], net.ip[3]);
      printf("Encrypted command port: %d.%d.%d.%d:%d (use hercules_crypto_tool.py)\r\n",
             net.ip[0], net.ip[1], net.ip[2], net.ip[3], SECURE_PORT);
      printf("MQTT-over-TLS broker  : %d.%d.%d.%d:%d (run tools/mqtt_tls_test.py)\r\n",
             MQTT_BROKER_IP[0], MQTT_BROKER_IP[1], MQTT_BROKER_IP[2], MQTT_BROKER_IP[3], MQTT_PORT);
  }

  /* USER CODE END 2 */

  /* Infinite loop */
  /* USER CODE BEGIN WHILE */
  while (1)
  {
    HTTPD_LED_Task();
    SecureCmd_Task();
    MQTT_Client_Task();

#if USE_DHCP
    /* Keep renewing the DHCP lease while the board is running.
     * DHCP_time_handler() is called from SysTick_Handler() now - see the
     * note in Network_Config() above. */
    DHCP_run();
#endif

    /* USER CODE END WHILE */

    /* USER CODE BEGIN 3 */
  }
  /* USER CODE END 3 */
}

/**
  * @brief System Clock Configuration
  * @retval None
  */
void SystemClock_Config(void)
{
  RCC_OscInitTypeDef RCC_OscInitStruct = {0};
  RCC_ClkInitTypeDef RCC_ClkInitStruct = {0};

  /** Configure the main internal regulator output voltage
  */
  __HAL_RCC_PWR_CLK_ENABLE();
  __HAL_PWR_VOLTAGESCALING_CONFIG(PWR_REGULATOR_VOLTAGE_SCALE1);

  /** Initializes the RCC Oscillators according to the specified parameters
  * in the RCC_OscInitTypeDef structure.
  */
  RCC_OscInitStruct.OscillatorType = RCC_OSCILLATORTYPE_HSI;
  RCC_OscInitStruct.HSIState = RCC_HSI_ON;
  RCC_OscInitStruct.HSICalibrationValue = RCC_HSICALIBRATION_DEFAULT;
  RCC_OscInitStruct.PLL.PLLState = RCC_PLL_ON;
  RCC_OscInitStruct.PLL.PLLSource = RCC_PLLSOURCE_HSI;
  RCC_OscInitStruct.PLL.PLLM = 8;
  RCC_OscInitStruct.PLL.PLLN = 216;
  RCC_OscInitStruct.PLL.PLLP = RCC_PLLP_DIV2;
  RCC_OscInitStruct.PLL.PLLQ = 9;
  if (HAL_RCC_OscConfig(&RCC_OscInitStruct) != HAL_OK)
  {
    Error_Handler();
  }

  /** Activate the Over-Drive mode
  */
  if (HAL_PWREx_EnableOverDrive() != HAL_OK)
  {
    Error_Handler();
  }

  /** Initializes the CPU, AHB and APB buses clocks
  */
  RCC_ClkInitStruct.ClockType = RCC_CLOCKTYPE_HCLK|RCC_CLOCKTYPE_SYSCLK
                              |RCC_CLOCKTYPE_PCLK1|RCC_CLOCKTYPE_PCLK2;
  RCC_ClkInitStruct.SYSCLKSource = RCC_SYSCLKSOURCE_PLLCLK;
  RCC_ClkInitStruct.AHBCLKDivider = RCC_SYSCLK_DIV1;
  RCC_ClkInitStruct.APB1CLKDivider = RCC_HCLK_DIV4;
  RCC_ClkInitStruct.APB2CLKDivider = RCC_HCLK_DIV2;

  if (HAL_RCC_ClockConfig(&RCC_ClkInitStruct, FLASH_LATENCY_7) != HAL_OK)
  {
    Error_Handler();
  }
}

/**
  * @brief SPI2 Initialization Function
  * @param None
  * @retval None
  */
static void MX_SPI2_Init(void)
{

  /* USER CODE BEGIN SPI2_Init 0 */

  /* USER CODE END SPI2_Init 0 */

  /* USER CODE BEGIN SPI2_Init 1 */

  /* USER CODE END SPI2_Init 1 */
  /* SPI2 parameter configuration*/
  hspi2.Instance = SPI2;
  hspi2.Init.Mode = SPI_MODE_MASTER;
  hspi2.Init.Direction = SPI_DIRECTION_2LINES;
  hspi2.Init.DataSize = SPI_DATASIZE_8BIT;
  hspi2.Init.CLKPolarity = SPI_POLARITY_LOW;
  hspi2.Init.CLKPhase = SPI_PHASE_1EDGE;
  hspi2.Init.NSS = SPI_NSS_SOFT;
  hspi2.Init.BaudRatePrescaler = SPI_BAUDRATEPRESCALER_32;
  hspi2.Init.FirstBit = SPI_FIRSTBIT_MSB;
  hspi2.Init.TIMode = SPI_TIMODE_DISABLE;
  hspi2.Init.CRCCalculation = SPI_CRCCALCULATION_DISABLE;
  hspi2.Init.CRCPolynomial = 7;
  hspi2.Init.CRCLength = SPI_CRC_LENGTH_DATASIZE;
  hspi2.Init.NSSPMode = SPI_NSS_PULSE_ENABLE;
  if (HAL_SPI_Init(&hspi2) != HAL_OK)
  {
    Error_Handler();
  }
  /* USER CODE BEGIN SPI2_Init 2 */

  /* USER CODE END SPI2_Init 2 */

}

/**
  * @brief USART1 Initialization Function (ST-LINK Virtual COM Port)
  * @param None
  * @retval None
  */
static void MX_USART1_UART_Init(void)
{
  huart1.Instance = USART1;
  huart1.Init.BaudRate = 115200;
  huart1.Init.WordLength = UART_WORDLENGTH_8B;
  huart1.Init.StopBits = UART_STOPBITS_1;
  huart1.Init.Parity = UART_PARITY_NONE;
  huart1.Init.Mode = UART_MODE_TX_RX;
  huart1.Init.HwFlowCtl = UART_HWCONTROL_NONE;
  huart1.Init.OverSampling = UART_OVERSAMPLING_16;
  if (HAL_UART_Init(&huart1) != HAL_OK)
  {
    Error_Handler();
  }
}

/**
  * @brief GPIO Initialization Function
  * @param None
  * @retval None
  */
static void MX_GPIO_Init(void)
{
  GPIO_InitTypeDef GPIO_InitStruct = {0};
  /* USER CODE BEGIN MX_GPIO_Init_1 */

  /* USER CODE END MX_GPIO_Init_1 */

  /* GPIO Ports Clock Enable */
  __HAL_RCC_GPIOA_CLK_ENABLE();
  __HAL_RCC_GPIOI_CLK_ENABLE();
  __HAL_RCC_GPIOB_CLK_ENABLE();

  /*Configure GPIO pin Output Level */
  HAL_GPIO_WritePin(GPIOA, RST_Pin|SCS_Pin, GPIO_PIN_SET);

  /*Configure GPIO pin : RST_Pin */
  GPIO_InitStruct.Pin = RST_Pin;
  GPIO_InitStruct.Mode = GPIO_MODE_OUTPUT_PP;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_LOW;
  HAL_GPIO_Init(RST_GPIO_Port, &GPIO_InitStruct);

  /*Configure GPIO pin : SCS_Pin */
  GPIO_InitStruct.Pin = SCS_Pin;
  GPIO_InitStruct.Mode = GPIO_MODE_OUTPUT_PP;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_VERY_HIGH;
  HAL_GPIO_Init(SCS_GPIO_Port, &GPIO_InitStruct);

  /* USER CODE BEGIN MX_GPIO_Init_2 */

  /* LED pin used by the web page - see LED_Pin/LED_GPIO_Port in main.h. */
  HAL_GPIO_WritePin(LED_GPIO_Port, LED_Pin, GPIO_PIN_RESET);
  GPIO_InitStruct.Pin = LED_Pin;
  GPIO_InitStruct.Mode = GPIO_MODE_OUTPUT_PP;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_LOW;
  HAL_GPIO_Init(LED_GPIO_Port, &GPIO_InitStruct);

  /* USER CODE END MX_GPIO_Init_2 */
}

/* USER CODE BEGIN 4 */

/* USER CODE END 4 */

 /* MPU Configuration */

void MPU_Config(void)
{
  MPU_Region_InitTypeDef MPU_InitStruct = {0};

  /* Disables the MPU */
  HAL_MPU_Disable();

  /** Initializes and configures the Region and the memory to be protected
  */
  MPU_InitStruct.Enable = MPU_REGION_ENABLE;
  MPU_InitStruct.Number = MPU_REGION_NUMBER0;
  MPU_InitStruct.BaseAddress = 0x0;
  MPU_InitStruct.Size = MPU_REGION_SIZE_4GB;
  MPU_InitStruct.SubRegionDisable = 0x87;
  MPU_InitStruct.TypeExtField = MPU_TEX_LEVEL0;
  MPU_InitStruct.AccessPermission = MPU_REGION_NO_ACCESS;
  MPU_InitStruct.DisableExec = MPU_INSTRUCTION_ACCESS_DISABLE;
  MPU_InitStruct.IsShareable = MPU_ACCESS_SHAREABLE;
  MPU_InitStruct.IsCacheable = MPU_ACCESS_NOT_CACHEABLE;
  MPU_InitStruct.IsBufferable = MPU_ACCESS_NOT_BUFFERABLE;

  HAL_MPU_ConfigRegion(&MPU_InitStruct);
  /* Enables the MPU */
  HAL_MPU_Enable(MPU_PRIVILEGED_DEFAULT);

}

/**
  * @brief  This function is executed in case of error occurrence.
  * @retval None
  */
void Error_Handler(void)
{
  /* USER CODE BEGIN Error_Handler_Debug */
  /* User can add his own implementation to report the HAL error return state */
  __disable_irq();
  while (1)
  {
  }
  /* USER CODE END Error_Handler_Debug */
}
#ifdef USE_FULL_ASSERT
/**
  * @brief  Reports the name of the source file and the source line number
  *         where the assert_param error has occurred.
  * @param  file: pointer to the source file name
  * @param  line: assert_param error line source number
  * @retval None
  */
void assert_failed(uint8_t *file, uint32_t line)
{
  /* USER CODE BEGIN 6 */
  /* User can add his own implementation to report the file name and line number,
     ex: printf("Wrong parameters value: file %s on line %d\r\n", file, line) */
  /* USER CODE END 6 */
}
#endif /* USE_FULL_ASSERT */
