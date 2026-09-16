/*
 * user_settings.h
 *
 * wolfSSL build configuration for this project.
 *
 * Used to be WOLFCRYPT_ONLY (just AES-256-GCM for secure_cmd.c, no real
 * TLS). Now it's a minimal TLS 1.2 client config so the board can open a
 * proper TLS session to an MQTT broker via mqtt_tls_socket.c + Paho's
 * MQTTPacket. secure_cmd.c keeps working unchanged - wolfCrypt's AES-GCM
 * is still built in, we've just turned on the TLS layer on top of it.
 *
 * Cipher suite: TLS_RSA_WITH_AES_128_GCM_SHA256 - RSA cert, static RSA
 * key exchange (no ECC/DH needed, smaller flash), AES-128-GCM + SHA-256.
 *
 * This file must stay on the include path with WOLFSSL_USER_SETTINGS
 * defined project-wide (STM32CubeIDE: Project Properties -> C/C++ Build
 * -> Settings -> MCU GCC Compiler -> Preprocessor -> Defined symbols),
 * so wolfssl/wolfcrypt/settings.h auto-includes this file.
 */

#ifndef WOLFSSL_USER_SETTINGS_H
#define WOLFSSL_USER_SETTINGS_H

/* ---- Platform ---- */
#define SINGLE_THREADED        /* no RTOS/mutexes in this project */
#define WOLFSSL_USER_IO        /* we supply the I/O callbacks (mqtt_tls_socket.c
                                   bridges them to the W5500 socket.c API) */
#define WOLFSSL_NO_SOCK        /* no BSD-socket layer on this target at all -
                                   without this, wolfio.h still tries to
                                   #include <sys/socket.h> just to declare
                                   SOCKET_T / error codes */
#define NO_WOLFSSL_DIR         /* no dirent.h on bare metal */
#define NO_WRITEV              /* no sys/uio.h on bare metal */
#define NO_FILESYSTEM          /* certs are compiled in as DER byte arrays
                                   (ca_cert.h), loaded with
                                   wolfSSL_CTX_load_verify_buffer() */
#define NO_MAIN_DRIVER

/* ---- TLS client only ---- */
#define NO_WOLFSSL_SERVER       /* board is always the TLS client */

/* Leaving WOLFSSL_TLS13 undefined keeps the build at TLS 1.2, which is
 * enough here and smaller in flash. Broker side is pinned to TLS 1.2 too,
 * see tools/mosquitto_test.conf. */

/* ---- Certificates / ASN.1 ---- */
#define NO_PWDBASED             /* no PKCS#12/PBKDF, no encrypted key files */

/* ---- Public-key crypto ---- */
#define NO_DH
#define NO_DSA
#define WOLFSSL_STATIC_RSA      /* wolfSSL disables plain RSA key-exchange
                                   suites by default (no forward secrecy) -
                                   this turns TLS_RSA_WITH_* back on. Fine
                                   for a local test broker; swap to an
                                   ECDHE_RSA suite + HAVE_ECC later if you
                                   need forward secrecy. */

/* ---- Hashing ---- */
#define NO_MD5                  /* not used by our chosen cipher suite */

/* ---- AES-GCM (shared by the TLS record layer and secure_cmd.c) ---- */
#define HAVE_AESGCM
#define WOLFSSL_AES_256
#define GCM_TABLE_4BIT          /* smaller/slower GHASH tables - better
                                   tradeoff on a Cortex-M with limited flash */

/* No RTC on this board, so certificate expiry can't be checked against
 * wall-clock time (would fail every handshake with "not yet valid" even
 * on a good cert). Fine for the bench; remove this once there's an
 * RTC + NTP source. */
#define NO_ASN_TIME

#define NO_SESSION_CACHE        /* one connection at a time */
#define NO_OLD_TLS              /* no SSLv3/TLS1.0/TLS1.1 */
#define NO_OLD_RNGNAME

/* No OS entropy source on bare metal, so wolfSSL needs a seed callback or
 * every wolfSSL_new() fails in wc_GenerateSeed(). Routed to the STM32
 * hardware TRNG - see MQTT_TLS_SeedRNG() in mqtt_tls_socket.c.
 *
 * wolfcrypt/src/random.c calls this by name and doesn't include
 * mqtt_tls_socket.h, so the prototype needs to be visible here too. */
extern int MQTT_TLS_SeedRNG(unsigned char *output, unsigned int sz);
#define CUSTOM_RAND_GENERATE_SEED MQTT_TLS_SeedRNG

/* ---- Misc ---- */
#define WOLFSSL_SMALL_STACK    /* keep AES/RSA working buffers off the stack -
                                   there's already a lot else in play
                                   (Ethernet, MQTT buffers) */

#endif /* WOLFSSL_USER_SETTINGS_H */
