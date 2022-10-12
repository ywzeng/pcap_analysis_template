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

// TCP flags. Ignore the higher 4-bit in the hl_flags here.
#define TCP_FLAG_FIN 0x0001
#define TCP_FLAG_SYN 0x0002
#define TCP_FLAG_RST 0x0004
#define TCP_FLAG_PSH 0x0008
#define TCP_FLAG_ACK 0x0010
#define TCP_FLAG_URG 0x0020
#define TCP_FLAG_ECE 0x0040
#define TCP_FLAG_CWR 0x0080
#define TCP_FLAG_NOC 0x0100

typedef struct PcapTCPHeader {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint16_t hl_flags;      // The higher 4-bit specifies the size of the TCP header in 32-bit (4-byte) words.
                            // The next 3-bit is temporarily reserved as 0.
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

string parse_tcp_pkt(char8_t *tcp_pkt);

string parse_udp_pkt(char8_t *udp_pkt);

#endif
