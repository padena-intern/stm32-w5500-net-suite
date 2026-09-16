# STM32F746 + W5500 — Web LED, Encrypted TCP Commands, and MQTT over TLS

Firmware for an STM32F746 (Discovery board) with a W5500 Ethernet module on
SPI2. It runs three independent network services out of the same
super-loop, each reachable on its own TCP port:

| Service | Port | What it's for | Talk to it with |
|---|---|---|---|
| Web LED control | 80 | Turn an LED on/off from a browser | Any browser |
| Encrypted command channel | 6000 | AES-256-GCM encrypted `BLINK`/`COUNT` commands over raw TCP | `hercules_crypto_tool.py` + Hercules |
| MQTT over TLS | 8883 | Same `BLINK`/`COUNT` commands over MQTT, TLS 1.2 | Any MQTT client, or `tools/mqtt_tls_test.py` |

None of these depend on each other — you can wire up just the one you care
about and ignore the rest.

## Hardware

- STM32F746 Discovery (or any STM32F746 board with the pins below free)
- A WIZnet W5500 module on SPI2

Wiring:

| Signal | STM32 pin |
|---|---|
| SPI2_SCK | PI1 |
| SPI2_MISO | PB14 |
| SPI2_MOSI | PB15 |
| CS (soft NSS) | PA8 |
| RST | PA15 |
| LED (web-controlled) | PI2 |
| Debug UART (ST-LINK VCP) | PA9 (TX) / PB7 (RX), 115200 8N1 |

Open a serial terminal on the ST-LINK's virtual COM port at boot — the
firmware prints the assigned IP and a one-line summary of how to reach
each of the three services.

**Finding the right serial port:** the ST-LINK on these Discovery boards
enumerates as a USB virtual COM port the moment you plug it in, separate
from any Ethernet connection — you don't need the network up to see it.

- **Windows:** open Device Manager → "Ports (COM & LPT)" → look for
  "STMicroelectronics STLink Virtual COM Port", it'll show something like
  `COM5`.
- **Linux:** it shows up as `/dev/ttyACM0` (or `ttyACM1`, etc. if you have
  other serial devices plugged in) — `dmesg | tail` right after plugging
  in will tell you exactly which one.
- **macOS:** look under `/dev/tty.usbmodem*`.

Open that port at 115200 8N1 (PuTTY, `screen`, `minicom`, Tera Term — any
of them work) *before* powering on or resetting the board, so you catch
the boot log from the start. That's where you'll see the DHCP-assigned
(or static) IP address printed — the board doesn't have a display, so
this serial log is the only way to find out what address it landed on.

## What's in this repo, and what you need to add

This repo has the application code (`Core/`) and the host-side tooling
(`tools/`), but it does **not** vendor the third-party libraries it
depends on. Before this builds, your STM32CubeIDE project also needs:

- **WIZnet `ioLibrary_Driver`** — the `socket.h` / `wizchip_conf.h` /
  `dhcp.h` API used throughout `Core/Src`. `w5500_port.c` is the glue
  between this library and the STM32 HAL.
- **wolfSSL / wolfCrypt** — `secure_cmd.c` uses wolfCrypt's AES-GCM
  directly; the MQTT client uses full wolfSSL for the TLS session.
  `Core/Inc/user_settings.h` is wolfSSL's build config for this project —
  make sure `WOLFSSL_USER_SETTINGS` is defined project-wide (Project
  Properties → C/C++ Build → Settings → MCU GCC Compiler → Preprocessor)
  so wolfSSL actually picks it up.
- **Paho's `MQTTPacket` module**, from
  [`eclipse-paho/paho.mqtt.embedded-c`](https://github.com/eclipse/paho.mqtt.embedded-c).
  Only the client-side files (`MQTTPacket.c` and friends) are needed —
  it's a plain serialize/deserialize library with no socket or threading
  dependency, which is why it's used here instead of the full
  `paho.mqtt.c` client (that one assumes pthreads/Win32 threads and real
  BSD sockets — none of which exist on this bare-metal target). Add its
  `MQTTPacket/src` folder to your project and put `MQTTPacket/src` on the
  include path.

Once those three are in place, `main.c` wires everything together:
`Network_Config()` brings up the W5500, then `HTTPD_LED_Init()`,
`SecureCmd_Init()`, and `MQTT_Client_Init()` each grab their own socket
number, and the three matching `*_Task()` functions get called every
pass through the main `while(1)` loop.

## Network setup

By default the board asks your router for an address over DHCP
(`USE_DHCP` in `main.c`). If you'd rather give it a fixed address, set
`USE_DHCP` to `0` and edit the `STATIC_IP` / `STATIC_GW` / `STATIC_SN` /
`STATIC_DNS` arrays right above it. Either way, whatever IP it ends up
with gets printed over the debug UART at boot.

## Service 1 — Web LED control (port 80)

The simplest of the three. Point a browser at the board's IP and you'll
get a small page with an ON/OFF button and the LED's current state. No
setup needed beyond the network config above.

## Service 2 — Encrypted command channel (port 6000)

A raw TCP socket that only accepts AES-256-GCM encrypted packets — no
plaintext protocol, no HTTP. It's meant to be driven from
[Hercules](https://www.hw-group.com/software/hercules-setup-utility)'
TCP client panel together with `hercules_crypto_tool.py`, which handles
the encryption/decryption for you.

Wire format, same in both directions, sent as a single TCP write:

```
[ 12 bytes nonce ][ ciphertext ][ 16 bytes GCM tag ]
```

The decrypted plaintext is just a short ASCII command:

- `BLINK <n>` — blink the LED n times (1–1000), replies `OK BLINKED <n> TOTAL <total>`
- `COUNT` — ask for the total blink count since boot, replies `COUNT <total>`
- anything else, or a packet that fails to decrypt/authenticate — the
  socket just closes with no reply. It won't tell you whether the
  problem was the key or the command, on purpose.

To use it:

1. Install the one dependency: `pip install cryptography`
2. Open Hercules, go to the TCP client tab, connect to `<board-ip>:6000`
3. Run `python3 hercules_crypto_tool.py` and pick option 1 or 2 to get a
   hex string
4. In Hercules, turn HEX mode on in the Send box, paste that string, hit
   Send
5. Copy whatever Hercules shows you got back, run the script again,
   option 3, paste it in — it'll decrypt and print the board's reply

The AES-256 key is hardcoded in both `Core/Src/secure_cmd.c`
(`SECURE_CMD_KEY`) and `hercules_crypto_tool.py` (`KEY_HEX`) — they have
to match exactly. The one in this repo is just a working example; swap
it for your own before this leaves the bench:

```
python3 -c "import secrets; print(secrets.token_hex(32))"
```

## Service 3 — MQTT over TLS (port 8883)

The board connects out to an MQTT broker on your laptop, over TLS 1.2,
verifying the broker's certificate against a CA baked into the firmware.
Once connected it subscribes to `stm32/cmd` and publishes replies to
`stm32/status` — same command set as the encrypted TCP channel above
(`BLINK <n>`, `COUNT`), just carried over MQTT instead.

Setup:

1. **Generate certificates.** On your laptop (needs `openssl`):

   ```
   tools/gen_certs.sh <your-laptop-LAN-IP>
   ```

   Here's what that script actually does, step by step:

   - Creates a throwaway self-signed CA (`ca.key` + `ca.crt`, RSA 2048,
     valid 10 years). This stands in for a real Certificate Authority —
     since the board has no root-CA store and isn't going out to the
     public internet, it just needs *some* CA it trusts, and this is that
     CA.
   - Creates a key + cert for the broker itself (`server.key` +
     `server.crt`), signed by that CA, with the IP you passed in set as
     the certificate's Subject Alternative Name (SAN). That's the IP the
     board will actually connect to, so the cert has to match it — a
     hostname wouldn't work here since the board connects by raw IP.
   - Converts `ca.crt` to DER (binary ASN.1) form and writes it out as a
     C byte array in `Core/Inc/ca_cert.h`. This is the only piece that
     ends up on the board: it embeds just the CA certificate (a public
     key, not a secret) so that when the broker presents `server.crt`
     during the TLS handshake, the firmware can verify it was signed by
     a CA it recognizes.

   The private keys (`ca.key`, `server.key`) and the broker's cert stay
   on your laptop, in `tools/certs/` — only the CA's *public* cert makes
   it into the firmware. Re-run this script (it overwrites everything)
   any time your laptop's IP changes.

2. **Point the firmware at your broker.** In `Core/Src/main.c`, set
   `MQTT_BROKER_IP` to the same IP you gave `gen_certs.sh`, then rebuild
   and flash.

3. **Run the broker:**

   ```
   mosquitto -c tools/mosquitto_test.conf -v
   ```

4. **Send it commands** from your laptop:

   ```
   pip install paho-mqtt>=2.0
   python3 tools/mqtt_tls_test.py --host <your-laptop-IP> --ca tools/certs/ca.crt
   ```

   This subscribes to `stm32/status` and drops you into a prompt where
   typing `BLINK 5` or `COUNT` publishes to `stm32/cmd`.

Watch the debug UART on first boot — if the TLS handshake fails or the
broker rejects the connection you'll see exactly why there.

### Things worth knowing before this goes anywhere beyond your bench

- **Server-auth TLS only** — the board doesn't present a client
  certificate, and mosquitto is configured with `require_certificate
  false`. Fine for a LAN bench setup; revisit before this ever faces a
  real network.
- **No RTC on the board**, so certificate expiry isn't checked
  (`NO_ASN_TIME` in `user_settings.h`). Add an RTC + NTP before relying
  on this for anything long-lived.
- **Hostname checking is off** — the board connects by static IP with an
  IP-SAN test cert, so `wolfSSL_check_domain_name(ssl, 0)` is set. The CA
  chain check is what's actually authenticating the broker.
- **Static-RSA cipher suite, no forward secrecy** — chosen to avoid
  needing ECC/DH for a first working version. Swap to an ECDHE_RSA suite
  (plus `HAVE_ECC`) later if you want forward secrecy.
- **QoS 0 only, one packet in flight at a time**, small buffers
  (`RX_BUF_LEN`/`TX_BUF_LEN` = 256 bytes) — plenty for short commands,
  but revisit if you need bigger payloads or overlapping publishes.
- wolfSSL's API shifts a bit between versions. If the linker complains
  about a missing symbol, check the function you're missing against your
  installed wolfSSL headers (`wolfssl/ssl.h`, `wolfssl/wolfio.h`).

## Repo layout

```
Core/Inc, Core/Src   — application + HAL glue code
Core/Startup         — startup assembly, linker-related
tools/certs          — CA + broker certs (regenerated by gen_certs.sh)
tools/gen_certs.sh   — generates the TLS test certs and ca_cert.h
tools/mosquitto_test.conf — minimal TLS-only mosquitto config
tools/mqtt_tls_test.py    — laptop-side MQTT+TLS test client
hercules_crypto_tool.py   — laptop-side helper for the encrypted TCP channel
```
 
 
