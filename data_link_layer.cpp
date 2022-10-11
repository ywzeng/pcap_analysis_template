#include "data_link_layer.h"

vector<string> parse_ethernet_pkt(char8_t *ethernet_pkt)
{
    PcapEthernetHeader eth_header;
    memcpy(&eth_header, ethernet_pkt, sizeof(PcapEthernetHeader));
    // Modify the byte order.
    eth_header.ether_type = (eth_header.ether_type << 8) | (eth_header.ether_type >> 8);

    vector<string> ether_pkt_info;
    switch (eth_header.ether_type)
    {
        case ETHERTYPE_IPV4:
            parse_ipv4_pkt(ethernet_pkt + sizeof(PcapEthernetHeader));
            break;
        case ETHERTYPE_ARP:
            ether_pkt_info = parse_arp_pkt(ethernet_pkt + sizeof(PcapEthernetHeader));
            break;
        case ETHERTYPE_VLAN:
            parse_vlan_pkt(ethernet_pkt + sizeof(PcapEthernetHeader));
            break;
        case ETHERTYPE_IPV6:
            break;
        case ETHERTYPE_LLDP:
            break;
        default:
            break;
    }
    
    return ether_pkt_info;
}

vector<string> parse_arp_pkt(char8_t *arp_pkt)
{
    PcapARPPacket arp_msg;
    memcpy(&arp_msg, arp_pkt, sizeof(PcapARPPacket));
    // Modify the byte order.
    arp_msg.hardware_type = (arp_msg.hardware_type << 8) | (arp_msg.hardware_type >> 8);
    arp_msg.protocol_type = (arp_msg.protocol_type << 8) | (arp_msg.protocol_type >> 8);
    arp_msg.opcode = (arp_msg.opcode << 8) | (arp_msg.opcode >> 8);
    
    // Extract ARP packet data
    vector<string> temp_vec;
    string temp_src_mac, temp_tar_mac;
    string temp_src_ip, temp_tar_ip;
    // src mac
    hex2str(arp_msg.src_hd_addr, sizeof(arp_msg.src_hd_addr), temp_vec);
    join(temp_vec, temp_src_mac, ":");
    // src ip
    hex2str(arp_msg.src_ip_addr, sizeof(arp_msg.src_ip_addr), temp_vec);
    join(temp_vec, temp_src_ip, ".");
    // tar mac
    hex2str(arp_msg.tar_hd_addr, sizeof(arp_msg.tar_hd_addr), temp_vec);
    join(temp_vec, temp_tar_mac, ":");
    // tar ip
    hex2str(arp_msg.tar_ip_addr, sizeof(arp_msg.tar_ip_addr), temp_vec);
    join(temp_vec, temp_tar_ip, ".");
    // Specific description info
    char8_t des_info_buffer[50];
    memset(des_info_buffer, 0, sizeof(des_info_buffer));
    switch (arp_msg.opcode)
    {
        case ARP_OP_REQUEST:
            snprintf(des_info_buffer, sizeof(des_info_buffer), "Request: Who has %s? Tell %s", temp_tar_ip.c_str(), temp_src_ip.c_str());
            break;
        case ARP_OP_REPLY:
            snprintf(des_info_buffer, sizeof(des_info_buffer), "Reply: %s is at %s", temp_src_ip.c_str(), temp_src_mac.c_str());
            break;
        default:
            snprintf(des_info_buffer, sizeof(des_info_buffer), "Unknown Opcode: 0x%04x", arp_msg.opcode);
            break;
    }

    // Aggregate the ARP packet info.
    vector<string> arp_info_vec;
    arp_info_vec.emplace_back(temp_src_mac);
    arp_info_vec.emplace_back(temp_tar_mac);;
    arp_info_vec.emplace_back("ARP");
    arp_info_vec.emplace_back(std::to_string(sizeof(PcapARPPacket)));
    arp_info_vec.emplace_back(string(des_info_buffer));

    return arp_info_vec;
}

void parse_vlan_pkt(char8_t *vlan_pkt)
{
    PcapVlanHeader vlan_header;
    memcpy(&vlan_header, vlan_pkt, sizeof(PcapVlanHeader));
    // Modify the byte order.
    vlan_header.tag_control_info = (vlan_header.tag_control_info << 8) | (vlan_header.tag_control_info >> 8);
    vlan_header.protocol_type = (vlan_header.protocol_type << 8) | (vlan_header.protocol_type >> 8);

    switch (vlan_header.protocol_type)
    {
        case ETHERTYPE_IPV4:
            parse_ipv4_pkt(vlan_pkt + sizeof(PcapVlanHeader));
            break;
        case ETHERTYPE_IPV6:
            break;
        default:
            break;
    }
    return;
}
