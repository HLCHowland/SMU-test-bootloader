#!/usr/bin/python3 -u

# 2022 eCTF
# Provides Crypto functionalities
# SMU Whitehats

import os
import monocypher
from hashlib import blake2b
from copy import deepcopy
import logging
from pathlib import Path
from util import LOG_FORMAT

KEY_SIZE = 32
NONCE_SIZE = 24
MAC_SIZE = 16
PAGE_SIZE = 1024

logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)
log = logging.getLogger(Path(__file__).name)


def get_mac(data: bytes, digest_size=MAC_SIZE) -> bytes:
    """
    This function simply takes in bytes and obtain a MAC.

    It takes in the digest size if provided.
    Else it will default to 16 bytes.
    """

    secrets = Path("/secrets/secrets.bin").read_bytes()
    key_mac = secrets[32 : 32 + 32]

    h = blake2b(key=key_mac, digest_size=digest_size)
    h.update(data)

    return h.digest()


def encrypt(data: bytes, AD=None):
    """
    The encrypt function has the functionality to take in an optional AD parameter.
    Note that an additional MAC is added to the plaintext to allow for the bootloader to
    check for the integrity of the firmware or config files prior to boot.
    It acts as a protective measure.

    :param data: Data to encrypt that should be in bytes. Will be broken into chunks of 1024 bytes.
    :param AD: Optional associate data that could be transmitted in plaintext
    :return: The encrypted data in bytes and the macs for each page appended
    """

    secrets = Path("/secrets/secrets.bin").read_bytes()
    if len(secrets) < KEY_SIZE * 3:
        log.error("Secrets not fully populated. Please rebuild bootloader.")
        return False

    key_enc = secrets[:32]

    # Generate the nonce
    nonce = bytearray(os.urandom(NONCE_SIZE))

    assert len(nonce) == NONCE_SIZE

    nonce_dup = deepcopy(nonce)

    ctx = b""

    page_cnt = 1
    for size in range(0, len(data), PAGE_SIZE):
        chunk = data[size : size + PAGE_SIZE]
        mac_enc, ciphertext = monocypher.lock(key_enc, bytes(nonce), chunk, AD)
        ctx += mac_enc
        ctx += ciphertext
        nonce[10] ^= page_cnt
        page_cnt += 1

    # Return the values
    return nonce_dup + ctx
