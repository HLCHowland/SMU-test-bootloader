# 2022 eCTF
# Host Tool Utility File
# Kyle Scaplen
#
# (c) 2022 The MITRE Corporation
#
# This source file is part of an example system for MITRE's 2022 Embedded System
# CTF (eCTF). This code is being provided only for educational purposes for the
# 2022 MITRE eCTF competition, and may not meet MITRE standards for quality.
# Use this code at your own risk!

import logging
from pathlib import Path
import socket
from sys import stderr

NONCE_SIZE = 24
MAC_SIZE = 16

LOG_FORMAT = "%(asctime)s:%(name)-12s%(levelname)-8s %(message)s"
log = logging.getLogger(Path(__file__).name)

CONFIGURATION_ROOT = Path("/configuration")
FIRMWARE_ROOT = Path("/firmware")
RELEASE_MESSAGES_ROOT = Path("/messages")

RESP_OK = b"\x00"

MAX_RELEASE_MSG_SIZE = 1024
MAX_FIRMWARE_SIZE = 1024 * 16
MAX_CONFIG_SIZE = 1024 * 64


def print_banner(s: str) -> None:
    """Print an underlined string to stdout

    Args:
        s (str): the string to print
    """
    width = len(s)
    line = "-" * width
    banner = f"\n{line}\n{s}\n{line}"
    print(banner, file=stderr)


class PacketIterator:
    BLOCK_SIZE = 0x400 + MAC_SIZE

    def __init__(self, data: bytes):
        self.data = data
        self.index = 0
        self.size = len(data)

    def __iter__(self):
        return [
            self.data[i : i + self.BLOCK_SIZE]
            for i in range(0, len(self.data), self.BLOCK_SIZE)
        ].__iter__()


# To cater for the unique packing method of the encrypted payload, the send_packets function
# has been modified to first send the nonce and receive a response. After confirmation, it will
# send the packets in sizes of 1024 (PAGE_SIZE) + 16 (MAC_SIZE) = 1040 / packet.
def send_packets(sock: socket.socket, data: bytes):
    # Send the nonce first
    log.info("Sending nonce over...")
    nonce = data[:NONCE_SIZE]
    sock.send(nonce)
    resp = sock.recv(1)
    if resp != RESP_OK:
        exit(f"ERROR: Bootloader responded with {repr(resp)}")

    packets = PacketIterator(data[NONCE_SIZE:])

    for num, packet in enumerate(packets):
        log.info(f"Sending Packet {num} ({len(packet)} bytes)...")
        sock.sendall(packet)

        resp = sock.recv(1)
        if resp != RESP_OK:
            exit(f"ERROR: Bootloader responded with {repr(resp)}")
