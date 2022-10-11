#ifndef _TRANSPORT_LAYER_H_
#define _TRANSPORT_LAYER_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <vector>

#include "base_type.h"
#include "network_layer.h"

using std::vector;
using std::string;

// Range of the TCP header length in 32-bit (4-byte) words.
#define TCP_HEADER_LEN_MIN 5
#define TCP_HEADER_LEN_MAX 15

typedef struct PcapTCPHeader {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint16_t hl_flags;      // The higher 4-bit specifies the size of the TCP header in 32-bit (4-byte) words.
                            // The next 3-bit is reserved as 0.
                            // The last 9-bit are 9 1-bit flags.
    uint16_t win_size;
    uint16_t checksum;
    uint16_t urg_ptr;
    uchar8_t options[];     // The length of Options field is determined by the data offset field (the higher 4-bit of header_len_reserved_flags).
                            // Note that the size of Options field must be an integer multiple of 32-bit (4-byte).
} PcapTCPHeader;

typedef struct PcapUDPHeader {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t len;                           // The length in bytes of the UDP header and data.
    uint16_t checksum;
} PcapUDPHeader;

void parse_tcp_pkt(char8_t *tcp_pkt);

void parse_udp_pkt(char8_t *udp_pkt);

#endif
