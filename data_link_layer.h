#ifndef _DATA_LINK_LAYER_H_
#define _DATA_LINK_LAYER_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <vector>

#include "base_type.h"
#include "general_funcs.h"
#include "network_layer.h"

using std::vector;
using std::string;

#define ETHERTYPE_IPV4 0x0800
#define ETHERTYPE_ARP  0x0806
#define ETHERTYPE_VLAN 0x8100
#define ETHERTYPE_IPV6 0x86dd
#define ETHERTYPE_LLDP 0x88cc

// Ethernet packet header. 14 bytes.
typedef struct PcapEthernetHeader {
    uchar8_t dst_mac_addr[6];           // Destination MAC address.
    uchar8_t src_mac_addr[6];           // Source MAC address.
    uint16_t ether_type;                // Type of the encapsulated protocol.
} PcapEthernetHeader;

#define ARP_OP_REQUEST 0x0001
#define ARP_OP_REPLY   0x0002

// ARP packet. 28 bytes.
typedef struct PcapARPPacket {
    uint16_t hardware_type;             // Type of the hardware used for the local network transmitting the ARP message.
    uint16_t protocol_type;             // Type of the layer-3 addresses used in the message. For IPv4, this value is 0x0800.
    uchar8_t hardware_addr_len;         // Length of the hardware address. For MAC, this value is 6.
    uchar8_t protocol_addr_len;         // Length of the layer-3 address. For IPv4, this value is 4.
    uint16_t opcode;                    // The operation type of the ARP packet.
    uchar8_t src_hd_addr[6];            // Hardware address of the device sending this message.
    uchar8_t src_ip_addr[4];            // IP address of the device sending this message.
    uchar8_t tar_hd_addr[6];            // Hardware address of the device this message is being sent to.
    uchar8_t tar_ip_addr[4];            // IP address of the device this message is being sent to.
} PcapARPPacket;

// IEEE 802.1Q VLAN Tag. 4 bytes.
typedef struct PcapVlanHeader {
    uint16_t tag_control_info;          // Contain 3 sub-fields.
                                        // The higher 3-bit is the Priority Code Point (PCP) field.
                                        // The next 1-bit is the Drop Eligible Indicator (DEI) field.
                                        // The last 12-bit is the VLAN ID (VID) field.
    uint16_t protocol_type;             // Type of the encapsulated protocol. The identifier is the same as the identifier used in Ethernet header.
} PcapVlanHeader;

vector<string> parse_ethernet_pkt(char8_t *ethernet_pkt);

vector<string> parse_arp_pkt(char8_t *arp_pkt);

void parse_vlan_pkt(char8_t *vlan_pkt);

#endif
