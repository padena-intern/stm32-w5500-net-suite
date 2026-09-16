#!/usr/bin/env python3
"""
mqtt_tls_test.py

Laptop-side test tool for the STM32 MQTT-over-TLS firmware.

Connects to your local mosquitto (tools/mosquitto_test.conf) over TLS,
subscribes to the board's status topic, and lets you interactively send
it commands - same command set as the old hercules_crypto_tool.py /
secure_cmd.c, just carried over MQTT+TLS now instead of a raw AES-GCM
socket:

    BLINK <n>   - board blinks its LED n times, replies "OK BLINKED n TOTAL n"
    COUNT       - board replies "COUNT <total>"

Requires:
    pip install paho-mqtt>=2.0

Usage:
    python3 mqtt_tls_test.py --host 192.168.1.50 --ca certs/ca.crt
"""

import argparse
import ssl
import sys
import threading

import paho.mqtt.client as mqtt

TOPIC_CMD = "stm32/cmd"
TOPIC_STATUS = "stm32/status"


def on_connect(client, userdata, flags, reason_code, properties):
    if reason_code != 0:
        print(f"connect failed: {reason_code}")
        return
    print(f"connected (TLS) - subscribing to {TOPIC_STATUS}")
    client.subscribe(TOPIC_STATUS, qos=0)


def on_message(client, userdata, msg):
    print(f"\n[{msg.topic}] {msg.payload.decode(errors='replace')}\n> ", end="", flush=True)


def on_disconnect(client, userdata, flags, reason_code, properties):
    print(f"\ndisconnected: {reason_code}")


def input_loop(client):
    print("Type commands to send to the board (BLINK <n> / COUNT), Ctrl-C to quit.")
    while True:
        try:
            line = input("> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not line:
            continue
        client.publish(TOPIC_CMD, line, qos=0)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", required=True, help="broker IP (same one baked into ca_cert.h)")
    ap.add_argument("--port", type=int, default=8883)
    ap.add_argument("--ca", default="certs/ca.crt", help="path to the CA cert from gen_certs.sh")
    args = ap.parse_args()

    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="laptop-tester")
    client.on_connect = on_connect
    client.on_message = on_message
    client.on_disconnect = on_disconnect

    # Match the firmware: TLS 1.2, TLS_RSA_WITH_AES_128_GCM_SHA256, verify
    # the broker cert against our own test CA. We connect by IP (not
    # hostname), same as the board, so hostname checking is turned off -
    # the CA-chain check is what's actually proving it's our test broker.
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations(cafile=args.ca)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    ctx.set_ciphers("AES128-GCM-SHA256")
    client.tls_set_context(ctx)

    client.connect(args.host, args.port, keepalive=60)
    client.loop_start()

    try:
        input_loop(client)
    finally:
        client.loop_stop()
        client.disconnect()


if __name__ == "__main__":
    sys.exit(main())
