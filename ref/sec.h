#pragma once

#include <stdint.h>
#include <unistd.h>

// Initialize security layer
void init_sec(int initial_state);

// Get input from security layer
ssize_t input_sec(uint8_t* buf, size_t max_length);

// Output to security layer
void output_sec(uint8_t* buf, size_t length);

// helper functions
uint32_t TLV_maker(uint8_t* buf, uint8_t type, uint16_t length, uint8_t* value);
int find_location(uint8_t* data, int state_sec, uint8_t type);
uint16_t get_size(uint8_t* data, int bufloc);
uint16_t plaintxt_length(uint16_t payload_length);
typedef struct // maybe useful to cast pointer into this
{
    uint8_t type;
    uint16_t len; // big endian when received from networks
    uint8_t input_load[0];
} tlv_pkt;