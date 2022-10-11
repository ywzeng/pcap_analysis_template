#ifndef _NETWORK_LAYER_H_
#define _NETWORK_LAYER_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <vector>

#include "base_type.h"
#include "transport_layer.h"

using std::vector;
using std::string;

// Range of the IPv4 header length in 32-bit (4-byte) words.
#define IPV4_IHL_MIN 5
#define IPV4_IHL_MAX 15

// IP protocol numbers.
#define IP_PROTOCOL_ICMP 0x01
#define IP_PROTOCOL_TCP  0x06
#define IP_PROTOCOL_UDP  0x11

// IPv4 packet header. Mostly 20 bytes with no Options field. 
typedef struct PcapIPv4Header {
    uchar8_t version_ihl;           // The higher 4-bit is the Version field, and the lower 4-bit is the Internet Header Length field.
                                    // IHL specifies the number of 32-bit (4-byte) words in the header, ranging from 5 to 15. Mostly 5.
    uchar8_t diff_services;         // Differentiated services field. 
                                    // The higher 6-bit is the DSCP field, and the lower 2-bit is the ECN field.
    uint16_t total_len;             // The entire packet size in bytes, including header and data.
    uint16_t identification;        // Uniquely identifying the group of fragments of a single IP datagram.
    uint16_t flags_frag_offset;     // The higher 3-bit is the Flags field, including DF and MF.
                                    // The lower 13-bit is the Fragment-offset field, specifying the offset of a fragment relative the beginning of the original unfragmented IP datagram.
    uchar8_t ttl;
    uchar8_t protocol_type;         // Type of the encapsulated protocol.
    uint16_t header_checksum;
    uchar8_t src_ip_addr[4];
    uchar8_t dst_ip_addr[4];
    uchar8_t options[];             // The Options field is not often used, and its size is depending on the IHL field
} PcapIPv4Header;

// ICMP type-code pair numbers
#define ICMP_TC_ECHO_REPLY       0x0000
#define ICMP_TC_DES_NET_UNREACH  0x0300
#define ICMP_TC_DES_HOST_UNREACH 0x0301
#define ICMP_TC_DES_PROC_UNREACH 0x0302
#define ICMP_TC_DES_PORT_UNREACH 0x0303
#define ICMP_TC_DES_NET_UNKNOWN  0x0306
#define ICMP_TC_DES_HOST_UNKNOWN 0x0307
#define ICMP_TC_ECHO_REQUEST     0x0800
#define ICMP_TC_TIME_EXCEED_TTL  0x0b00
#define ICMP_TC_TIME_EXCEED_FRAG 0x0b01

// ICMP packet header. 8 bytes. The first 4 bytes have fixed format, while the last 4 bytes depend on the Type/Code field.
typedef struct PcapICMPHeader {
    uchar8_t type;
    uchar8_t code;
    uint16_t checksum;
    uchar8_t rst_header[4];         // Contents vary based on the Type and Code values.
} PcapICMPHeader;

void parse_ipv4_pkt(char8_t *ipv4_pkt);

void parse_icmp_pkt(char8_t *icmp_pkt);

#endif
