/**
 * @file bootloader.c
 * @author Kyle Scaplen
 * @brief Bootloader implementation
 * @date 2022
 *
 * This source file is part of an example system for MITRE's 2022 Embedded
 * System CTF (eCTF). This code is being provided only for educational purposes
 * for the 2022 MITRE eCTF competition, and may not meet MITRE standards for
 * quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2022 The MITRE Corporation
 */

#include <stdint.h>
#include <string.h>
#include <stdbool.h>

#include "driverlib/interrupt.h"
#include "driverlib/eeprom.h"
#include "driverlib/sysctl.h"

#include "flash.h"
#include "uart.h"
#include "monocypher.h"

/*
 * Firmware:
 *      FW Mac:  0x0002B400 : 0x0002B410 (16B)
 *      Size:    0x0002B410 : 0x0002B414 (4B)
 *      Version: 0x0002B414 : 0x0002B418 (4B)
 *      Msg:     0x0002B418 : 0x0002BC00 (~2KB = 1KB + 1B + pad)
 *      Fw:      0x0002BC00 : 0x0002FC00 (16KB)
 * Configuration:
 *      Cfg Mac  0x0002FC00 : 0x0002FC10 (16B)
 *      Size:    0x0002FC10 : 0x00030000 (~1KB = 4B + pad)
 *      Cfg:     0x00030000 : 0x00040000 (64KB)
 */
// Firmware page 1
#define FIRMWARE_METADATA_PTR ((uint32_t)(FLASH_START + 0x0002B400))
#define FIRMWARE_MAC_PTR ((uint32_t)(FIRMWARE_METADATA_PTR + 0))
#define FIRMWARE_SIZE_PTR ((uint32_t)(FIRMWARE_METADATA_PTR + 16))
#define FIRMWARE_VERSION_PTR ((uint32_t)(FIRMWARE_METADATA_PTR + 20))
#define FIRMWARE_RELEASE_MSG_PTR ((uint32_t)(FIRMWARE_METADATA_PTR + 24))

// Firmware page 2 (if required)
#define FIRMWARE_RELEASE_MSG_PTR2 \
    ((uint32_t)(FIRMWARE_METADATA_PTR + FLASH_PAGE_SIZE))

// 16 pages for the actual config
#define FIRMWARE_STORAGE_PTR \
    ((uint32_t)(FIRMWARE_METADATA_PTR + (FLASH_PAGE_SIZE * 2)))

// Config page 1
#define CONFIGURATION_METADATA_PTR \
    ((uint32_t)(FIRMWARE_STORAGE_PTR + (FLASH_PAGE_SIZE * 16)))
#define CONFIGURATION_MAC_PTR ((uint32_t)(CONFIGURATION_METADATA_PTR + 0))
#define CONFIGURATION_SIZE_PTR ((uint32_t)(CONFIGURATION_METADATA_PTR + 16))

// Config page 2 onwards
#define CONFIGURATION_STORAGE_PTR \
    ((uint32_t)(CONFIGURATION_METADATA_PTR + FLASH_PAGE_SIZE))

#define FIRMWARE_BOOT_PTR ((uint32_t)0x20004000)

// Firmware update constants
#define FRAME_OK 0x00
#define FRAME_BAD 0x01
#define BAD_ENC 0x02

// Other crypto constants
#define KEY_SIZE 0x20
#define NONCE_SIZE 0x18
#define MAC_SIZE 0x10

/**
 * @brief Boot the firmware.
 */
void handle_boot(void) {
    uint32_t size_fw;
    uint32_t size_cfg;
    uint8_t *rel_msg;

    // Acknowledge the host
    uart_writeb(HOST_UART, 'B');

    // Find the metadata
    size_fw = *((uint32_t *)FIRMWARE_SIZE_PTR);
    size_cfg = *((uint32_t *)CONFIGURATION_SIZE_PTR);

    // Quick sanity checks
    if (size_fw > 0x4000 || size_cfg > 0x10000) {
        uart_writeb(HOST_UART, FRAME_BAD);
        return;
    }

    // Perform the MAC verifications prior to loading to RAM
    // Retrieve the MAC SECRETS and perform MAC verifications
    uint8_t mac_key[KEY_SIZE];
    uint8_t hash[MAC_SIZE];
    EEPROMRead((uint32_t *)mac_key, KEY_SIZE, KEY_SIZE);

    crypto_blake2b_general(hash, MAC_SIZE, mac_key, KEY_SIZE,
                           (uint8_t *)FIRMWARE_STORAGE_PTR, size_fw);

    if (crypto_verify16(hash, (uint8_t *)FIRMWARE_MAC_PTR)) {
        uart_writeb(HOST_UART, BAD_ENC);
        crypto_wipe(mac_key, KEY_SIZE);
        return;
    }

    crypto_blake2b_general(hash, MAC_SIZE, mac_key, KEY_SIZE,
                           (uint8_t *)CONFIGURATION_STORAGE_PTR, size_cfg);

    if (crypto_verify16(hash, (uint8_t *)CONFIGURATION_MAC_PTR)) {
        uart_writeb(HOST_UART, BAD_ENC);
        crypto_wipe(mac_key, KEY_SIZE);
        return;
    }

    uart_writeb(HOST_UART, FRAME_OK);

    memcpy((uint8_t *)FIRMWARE_BOOT_PTR, (uint8_t *)FIRMWARE_STORAGE_PTR,
           size_fw);

    uart_writeb(HOST_UART, 'M');

    // Last verification before takeoff!
    crypto_blake2b_general(hash, MAC_SIZE, mac_key, KEY_SIZE,
                           (uint8_t *)FIRMWARE_BOOT_PTR, size_fw);

    if (crypto_verify16(hash, (uint8_t *)FIRMWARE_MAC_PTR)) {
        uart_writeb(HOST_UART, BAD_ENC);
        crypto_wipe(mac_key, KEY_SIZE);
        return;
    }

    uart_writeb(HOST_UART, 'V');
    crypto_wipe(mac_key, KEY_SIZE);

    // Print the release message
    uint16_t msg_size = 0;
    rel_msg = (uint8_t *)FIRMWARE_RELEASE_MSG_PTR;
    while (*rel_msg != 0 && msg_size++ < 0x400) {
        uart_writeb(HOST_UART, *rel_msg);
        rel_msg++;
    }
    uart_writeb(HOST_UART, '\0');

    // Execute the firmware
    void (*firmware)(void) = (void (*)(void))(FIRMWARE_BOOT_PTR + 1);
    firmware();
}

/* Reset the EEPROM challenge for the next READBACK
 * This is done by repeated hashing to generate the new challenge
 * Anyone without the key cannot generate it beforehand
 */
void generate_new_challenge(uint8_t *old_chal, uint8_t *mac_key) {
    uint8_t new_chal[KEY_SIZE];
    crypto_blake2b_general(new_chal, KEY_SIZE, mac_key, KEY_SIZE, old_chal,
                           KEY_SIZE);
    EEPROMProgram((uint32_t *)new_chal, KEY_SIZE * 2, KEY_SIZE);
}

/**
 * @brief Send the firmware data over the host interface.
 */
void handle_readback(void) {
    uint8_t region;
    uint8_t *address;
    uint32_t size = 0;

    // Acknowledge the host
    uart_writeb(HOST_UART, 'R');

    // Perform the challenge-response verification
    // Retrieve the most secret challenge and perform keyed hashing
    uint8_t challenge[KEY_SIZE];
    uint8_t response[KEY_SIZE];
    uint8_t hash[KEY_SIZE];
    uint8_t mac_key[KEY_SIZE];

    EEPROMRead((uint32_t *)mac_key, KEY_SIZE, KEY_SIZE);
    EEPROMRead((uint32_t *)challenge, KEY_SIZE * 2, KEY_SIZE);

    uart_write(HOST_UART, challenge, KEY_SIZE);

    crypto_blake2b_general(hash, KEY_SIZE, mac_key, KEY_SIZE, challenge,
                           KEY_SIZE);

    uart_read(HOST_UART, response, KEY_SIZE);

    // Send ACK for received
    uart_writeb(HOST_UART, 'R');

    if (crypto_verify32(hash, response)) {
        generate_new_challenge(hash, mac_key);
        crypto_wipe(mac_key, KEY_SIZE);
        uart_writeb(HOST_UART, BAD_ENC);
        return;
    }

    uart_writeb(HOST_UART, 'K');

    crypto_wipe(hash, MAC_SIZE);
    uart_writeb(HOST_UART, FRAME_OK);

    // Receive region identifier
    region = (uint32_t)uart_readb(HOST_UART);

    if (region == 'F') {
        // Set the base address for the readback
        address = (uint8_t *)FIRMWARE_STORAGE_PTR;
        // Acknowledge the host
        uart_writeb(HOST_UART, 'F');
    } else if (region == 'C') {
        // Set the base address for the readback
        address = (uint8_t *)CONFIGURATION_STORAGE_PTR;
        // Acknowledge the hose
        uart_writeb(HOST_UART, 'C');
    } else {
        return;
    }

    // Receive the size to send back to the host
    size = ((uint32_t)uart_readb(HOST_UART)) << 24;
    size |= ((uint32_t)uart_readb(HOST_UART)) << 16;
    size |= ((uint32_t)uart_readb(HOST_UART)) << 8;
    size |= (uint32_t)uart_readb(HOST_UART);

    // Generate new challenge
    generate_new_challenge(response, mac_key);

    // Read out the memory
    uart_write(HOST_UART, address, size);
}

/**
 * @brief Read data from a UART interface and program to flash memory.
 *
 * @param interface is the base address of the UART interface to read from.
 * @param dst is the starting page address to store the data.
 * @param size is the number of bytes to load.
 * @param AD is the pointer to the AD buffer. Can be NULL
 * @param AD_size is the size of the AD. Set to 0 for NULL AD.
 */
void load_data(uint32_t interface, uint32_t dst, uint32_t size, uint8_t *AD,
               uint32_t AD_size) {
    int i;
    uint32_t frame_size;
    uint8_t page_buffer[FLASH_PAGE_SIZE];

    uint8_t counter = 1;
    uint8_t enc_key[KEY_SIZE];
    uint8_t nonce[NONCE_SIZE];
    uint8_t mac[MAC_SIZE];

    // Read in the nonce first and ACK
    uart_read(HOST_UART, nonce, NONCE_SIZE);
    uart_writeb(HOST_UART, FRAME_OK);

    // Retrieve the SECRETS from EEPROM
    EEPROMRead((uint32_t *)enc_key, 0x0, KEY_SIZE);

    while (size > 0) {
        // calculate frame size
        frame_size = size > FLASH_PAGE_SIZE ? FLASH_PAGE_SIZE : size;
        // read mac and frame into buffer
        uart_read(HOST_UART, mac, MAC_SIZE);
        uart_read(HOST_UART, page_buffer, frame_size);

        // Decrypt and check for integrity for every page. Will return 0 only
        // upon success
        if (crypto_unlock_aead(page_buffer, enc_key, nonce, mac, AD, AD_size,
                               page_buffer, frame_size)) {
            crypto_wipe(enc_key, KEY_SIZE);
            uart_writeb(HOST_UART, BAD_ENC);
            return;
        }

        // Increment the nonce counter and XOR with nonce.
        nonce[10] ^= counter++;

        // pad buffer if frame is smaller than the page
        for (i = frame_size; i < FLASH_PAGE_SIZE; i++) {
            page_buffer[i] = 0xFF;
        }
        // clear flash page
        flash_erase_page(dst);
        // write flash page
        flash_write((uint32_t *)page_buffer, dst, FLASH_PAGE_SIZE >> 2);
        // next page and decrease size
        dst += FLASH_PAGE_SIZE;
        size -= frame_size;
        // send frame ok
        uart_writeb(HOST_UART, FRAME_OK);
    }

    crypto_wipe(enc_key, KEY_SIZE);
}

/**
 * @brief Update the firmware.
 */
void handle_update(void) {
    // metadata
    uint32_t current_version;
    uint32_t version = 0;
    uint32_t size = 0;
    uint32_t rel_msg_size = 0;
    uint8_t AD[1047];  // 16 (mac) + 6 (metadata) + 1024 (rel_msg) + terminator

    // Acknowledge the HOST and start the process!
    uart_writeb(HOST_UART, 'U');

    // Receive the first part of the AD data, consisting of MAC and metadata
    uart_read(HOST_UART, AD, MAC_SIZE + 6);

    // Convert the raw bytes to comparable datatypes
    version = ((uint32_t)AD[16]) << 8;
    version |= (uint32_t)AD[17];
    for (int i = 18; i < 22; i++) {
        size <<= 8;
        size |= (uint32_t)AD[i];
    }

    // Receive release message
    rel_msg_size = uart_readline(HOST_UART, &AD[22]) + 1;

    uart_writeb(HOST_UART, FRAME_OK);

    // Check the version
    current_version = *((uint32_t *)FIRMWARE_VERSION_PTR);
    if (current_version == 0xFFFFFFFF) {
        current_version = (uint32_t)OLDEST_VERSION;
    }

    if ((version != 0) && (version < current_version)) {
        // Lower version not acceptable unless version is 0
        uart_writeb(HOST_UART, FRAME_BAD);
        return;
    }

    // Max size checks for firmware (16KB)
    if (size > FLASH_PAGE_SIZE * 16) {
        uart_writeb(HOST_UART, FRAME_BAD);
        return;
    }

    // Clear firmware metadata
    flash_erase_page(FIRMWARE_METADATA_PTR);

    // Save size and MAC
    flash_write((uint32_t *)AD, FIRMWARE_MAC_PTR, MAC_SIZE >> 2);
    flash_write_word(size, FIRMWARE_SIZE_PTR);

    // Only save new version if it is not 0
    if (version != 0) {
        flash_write_word(version, FIRMWARE_VERSION_PTR);
    } else {
        flash_write_word(current_version, FIRMWARE_VERSION_PTR);
    }

    // Write release message
    uint8_t *rel_msg = &AD[22];
    uint8_t *rel_msg_read_ptr = rel_msg;
    uint32_t rel_msg_write_ptr = FIRMWARE_RELEASE_MSG_PTR;
    uint32_t rem_bytes = rel_msg_size;

    // If release message goes outside of the first page, write the first
    // full page then next.
    if (rel_msg_size > (FLASH_PAGE_SIZE - 24)) {
        // Write first page
        flash_write(
            (uint32_t *)rel_msg, FIRMWARE_RELEASE_MSG_PTR,
            (FLASH_PAGE_SIZE - 24) >> 2);  // This is always a multiple of 4

        // Set up second page
        rem_bytes = rel_msg_size - (FLASH_PAGE_SIZE - 24);
        rel_msg_read_ptr = rel_msg + (FLASH_PAGE_SIZE - 24);
        rel_msg_write_ptr = FIRMWARE_RELEASE_MSG_PTR2;
        flash_erase_page(rel_msg_write_ptr);
    }

    // Program last or only page of release message
    if (rem_bytes % 4 != 0) {
        rem_bytes += 4 - (rem_bytes % 4);  // Account for partial word
    }
    flash_write((uint32_t *)rel_msg_read_ptr, rel_msg_write_ptr,
                rem_bytes >> 2);

    // Acknowledge
    uart_writeb(HOST_UART, FRAME_OK);

    // Retrieve firmware
    load_data(HOST_UART, FIRMWARE_STORAGE_PTR, size, &AD[MAC_SIZE],
              rel_msg_size + 6);

    // Retrieve the MAC SECRETS and perform MAC verification
    uint8_t mac_key[KEY_SIZE];
    uint8_t hash[MAC_SIZE];
    EEPROMRead((uint32_t *)mac_key, KEY_SIZE, KEY_SIZE);
    crypto_blake2b_general(hash, MAC_SIZE, mac_key, KEY_SIZE,
                           (uint8_t *)FIRMWARE_STORAGE_PTR, size);

    crypto_wipe(mac_key, KEY_SIZE);

    // Verify and will return false if the buffers match
    if (crypto_verify16(hash, (uint8_t *)FIRMWARE_MAC_PTR)) {
        uart_writeb(HOST_UART, BAD_ENC);
        return;
    }
    uart_writeb(HOST_UART, FRAME_OK);
}

/**
 * @brief Load configuration data.
 */
void handle_configure(void) {
    uint32_t size = 0;
    uint8_t mac[16];

    // Acknowledge the host
    uart_writeb(HOST_UART, 'C');

    // Receive MAC
    uart_read(HOST_UART, mac, MAC_SIZE);
    uart_writeb(HOST_UART, FRAME_OK);

    // Receive size
    size = (((uint32_t)uart_readb(HOST_UART)) << 24);
    size |= (((uint32_t)uart_readb(HOST_UART)) << 16);
    size |= (((uint32_t)uart_readb(HOST_UART)) << 8);
    size |= ((uint32_t)uart_readb(HOST_UART));

    // Sanity checks
    if (size > 0x10000) {
        uart_writeb(HOST_UART, FRAME_BAD);
        return;
    }

    // Clear page, write MAC and size first
    flash_erase_page(CONFIGURATION_METADATA_PTR);
    flash_write((uint32_t *)mac, CONFIGURATION_MAC_PTR, (MAC_SIZE >> 2));
    flash_write_word(size, CONFIGURATION_SIZE_PTR);

    uart_writeb(HOST_UART, FRAME_OK);

    // Save the config data with no AD data verification
    load_data(HOST_UART, CONFIGURATION_STORAGE_PTR, size, NULL, 0);

    // Retrieve the key used for MAC and perform MAC verification
    uint8_t mac_key[KEY_SIZE];
    uint8_t hash[MAC_SIZE];
    EEPROMRead((uint32_t *)mac_key, KEY_SIZE, KEY_SIZE);
    crypto_blake2b_general(hash, MAC_SIZE, mac_key, KEY_SIZE,
                           (uint8_t *)CONFIGURATION_STORAGE_PTR, size);

    crypto_wipe(mac_key, KEY_SIZE);

    if (crypto_verify16(hash, (uint8_t *)CONFIGURATION_MAC_PTR)) {
        uart_writeb(HOST_UART, BAD_ENC);
        return;
    }
    uart_writeb(HOST_UART, FRAME_OK);
}

/**
 * @brief Host interface polling loop to receive configure, update, readback,
 * and boot commands.
 *
 * @return int
 */
int main(void) {
    uint8_t cmd = 0;

    // Initialize IO components
    uart_init();

    // Init the EEPROM
    uint32_t ui32EEPROMInit;
    SysCtlPeripheralEnable(SYSCTL_PERIPH_EEPROM0);
    while (!SysCtlPeripheralReady(SYSCTL_PERIPH_EEPROM0)) {
    }

    // Handle host commands
    while (1) {
        cmd = uart_readb(HOST_UART);

        // Verify it is ready to use
        ui32EEPROMInit = EEPROMInit();
        if (ui32EEPROMInit != EEPROM_INIT_OK) {
            return 1;
        }

        switch (cmd) {
            case 'C':
                handle_configure();
                break;
            case 'U':
                handle_update();
                break;
            case 'R':
                handle_readback();
                break;
            case 'B':
                handle_boot();
                break;
            default:
                break;
        }
    }
}
