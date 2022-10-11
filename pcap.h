#ifndef _PCAP_ANALYSIS_H_
#define _PCAP_ANALYSIS_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <iostream>
#include <string>
#include <vector>

#include "base_type.h"
#include "data_link_layer.h"

using std::vector;
using std::string;
using std::cout;
using std::endl;

// Pcap file magic numbers. 0xa1b2c3d4 denotes the big endian, 0xd4c3b2a1 denotes the little endian.
#define PCAP_HDR_MAGIC_BIG    0xa1b2c3d4
#define PCAP_HDR_MAGIC_LITTLE 0xd4c3b2a1

// Link-layer header types. To be supplemented...
#define LINKTYPE_ETHERNET 1

// Pcap file header. 24 bytes.
typedef struct PcapFileHeader {
    uint32_t magic_num;
    uint16_t major_version;
    uint16_t minor_version;
    int32_t  thiszone;      // GMT to local timezone correction. Always 0.
    uint32_t sig_figs;      // Accuracy of the timestamps. Always 0.
    uint32_t snap_len;      // Max length of the captured packet.
    uint32_t link_type;     // Data link type. 1 for Ethernet.
} PcapFileHeader;

// Timestamp, including second and microsecond. 8 bytes.
typedef struct Timestamp {
    uint32_t timestamp_s;       // Timestamp high. Accurate to seconds.
    uint32_t timestamp_us;      // Timestamp low. Accurate to microseconds.
} Timestamp;

// Packet header. 16 bytes.
typedef struct PcapPktHeader {
    Timestamp timestamp;        // Timestamp. 8 bytes.
    uint32_t cap_len;           // Length of the current packet.
    uint32_t len;               // Length of the actual off wire data, mostly equals to cap_len.
                                // If the transfered data is longer than sanp_len specified in PcapFileHeader,
                                // then the cap_len equals to (len - snap_len).
} PcapPktHeader;

size_t parse_pcap(const char8_t *file_path, vector<vector<string>>& pkt_info_vec);

#endif
