#!/usr/bin/env python3
"""
hercules_crypto_tool.py

Helper for talking to the STM32F746 + W5500 encrypted LED-blink command
server through Hercules' TCP client.

Workflow:
  1. In Hercules, open the "TCP Client" tab and connect to the board.
  2. To send a command:
       - Enable HEX in the Send box.
       - Paste the HEX this script gives you.
       - Click Send.
  3. To read a reply:
       - Hercules shows raw bytes like {32}{85}{FC}{D8}{F5}#DC2{D5}{69}...
       - Copy that text exactly and paste it into option 3 below.
       - The script turns it back into bytes and decrypts it.

Wire format: [ 12 bytes nonce ][ N bytes ciphertext ][ 16 bytes GCM tag ]
AES-256-GCM, no associated data.

Requires:
    pip install cryptography
"""

import os
import re
import sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Must match SECURE_CMD_KEY in Core/Src/secure_cmd.c exactly (32 bytes /
# 64 hex chars).
KEY_HEX = "b57d0061c8620b2de32efa045f239c5cf11e8e058d0411cb754115a81a380829"

NONCE_LEN = 12
TAG_LEN = 16

# Hercules shows non-printable bytes as names like #NUL, #BEL, #ESC
# instead of a raw hex value. Map those back to their byte values.
HERCULES_CONTROL_CODES = {
    "NUL": 0x00, "SOH": 0x01, "STX": 0x02, "ETX": 0x03, "EOT": 0x04,
    "ENQ": 0x05, "ACK": 0x06, "BEL": 0x07, "BS": 0x08, "HT": 0x09,
    "LF": 0x0A, "VT": 0x0B, "FF": 0x0C, "CR": 0x0D, "SO": 0x0E,
    "SI": 0x0F, "DLE": 0x10, "DC1": 0x11, "DC2": 0x12, "DC3": 0x13,
    "DC4": 0x14, "NAK": 0x15, "SYN": 0x16, "ETB": 0x17, "CAN": 0x18,
    "EM": 0x19, "SUB": 0x1A, "ESC": 0x1B, "FS": 0x1C, "GS": 0x1D,
    "RS": 0x1E, "US": 0x1F, "DEL": 0x7F,
}


def get_key() -> bytes:
    """Decode KEY_HEX into a 32-byte AES-256 key."""
    try:
        key = bytes.fromhex(KEY_HEX)
    except ValueError as e:
        raise ValueError("KEY_HEX is not valid hexadecimal.") from e

    if len(key) != 32:
        raise ValueError(f"KEY_HEX must decode to 32 bytes, got {len(key)}.")

    return key


def encrypt_command(plaintext: str) -> str:
    """Encrypt plaintext, return nonce||ciphertext||tag as uppercase hex,
    ready to paste into Hercules with HEX mode enabled."""
    key = get_key()
    aesgcm = AESGCM(key)
    nonce = os.urandom(NONCE_LEN)
    ct_and_tag = aesgcm.encrypt(nonce, plaintext.encode("ascii"), None)
    return (nonce + ct_and_tag).hex().upper()


def parse_hercules_output(text: str) -> bytes:
    """
    Convert what Hercules shows on screen back into raw bytes.

    Recognized tokens:
      {XX}   - a raw hex byte
      #NAME  - a control-character name (#NUL, #BEL, #ESC, ...)

    Whitespace between tokens is ignored; anything else raises.
    """
    text = text.strip()
    if not text:
        raise ValueError("No Hercules data was entered.")

    output = bytearray()
    token_pattern = re.compile(r"\{([0-9A-Fa-f]{2})\}|#([A-Za-z0-9]+)")
    position = 0

    for match in token_pattern.finditer(text):
        ignored = text[position:match.start()]
        if ignored.strip():
            raise ValueError(f"Unknown Hercules text near: {ignored!r}")

        hex_byte, control_name = match.group(1), match.group(2)
        if hex_byte is not None:
            output.append(int(hex_byte, 16))
        else:
            name = control_name.upper()
            if name not in HERCULES_CONTROL_CODES:
                raise ValueError(f"Unknown Hercules control code: #{control_name}")
            output.append(HERCULES_CONTROL_CODES[name])

        position = match.end()

    remaining = text[position:]
    if remaining.strip():
        raise ValueError(f"Unknown Hercules text at end: {remaining!r}")

    return bytes(output)


def decrypt_reply(hercules_text: str) -> str:
    """Parse Hercules' displayed output and AES-256-GCM decrypt it."""
    packet = parse_hercules_output(hercules_text)
    print(f"\nParsed packet length: {len(packet)} bytes")
    print(f"Parsed HEX: {packet.hex().upper()}")

    if len(packet) < NONCE_LEN + TAG_LEN:
        raise ValueError(
            f"Packet too short: {len(packet)} bytes, need at least "
            f"{NONCE_LEN + TAG_LEN}."
        )

    nonce = packet[:NONCE_LEN]
    ct_and_tag = packet[NONCE_LEN:]

    aesgcm = AESGCM(get_key())
    plaintext = aesgcm.decrypt(nonce, ct_and_tag, None)
    return plaintext.decode("ascii", errors="replace")


def prompt_menu():
    while True:
        print()
        print("1) Encrypt a BLINK command  (blink LED N times)")
        print("2) Encrypt a COUNT command  (ask total blink count)")
        print("3) Decrypt a Hercules reply")
        print("4) Quit")

        choice = input("> ").strip()

        if choice == "1":
            n = input("Blink how many times? ").strip()
            if not n.isdigit() or int(n) == 0:
                print("Enter a positive integer.")
                continue
            packet_hex = encrypt_command(f"BLINK {n}")
            print("\nPaste this into Hercules' Send box (HEX mode on):\n")
            print(packet_hex)

        elif choice == "2":
            packet_hex = encrypt_command("COUNT")
            print("\nPaste this into Hercules' Send box (HEX mode on):\n")
            print(packet_hex)

        elif choice == "3":
            print("\nPaste the Hercules receive output exactly as shown.")
            print("Example: {32}{85}{FC}{D8}{F5}#DC2{D5}{69}\n")
            hercules_text = input("Hercules > ")
            try:
                plaintext = decrypt_reply(hercules_text)
                print("\nDecrypted reply:")
                print(plaintext)
            except Exception as e:
                print("\nCould not decrypt/authenticate that packet:")
                print(e)

        elif choice == "4":
            break

        else:
            print("Not a valid choice.")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] in ("-h", "--help"):
        print(__doc__)
        sys.exit(0)
    prompt_menu()
