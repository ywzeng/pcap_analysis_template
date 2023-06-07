#include "transport_layer.h"

string parse_tcp_pkt(char8_t *tcp_pkt)
{
    // Get the Header Len field. If its value is greater than TCP_HEADER_LEN_MIN (5), the Options field is not NULL.
    uchar8_t hl;
    size_t hl_offset = 12;        // The byte offset of the Header Len field from the beginning of the TCP header.
    memcpy(&hl, tcp_pkt + hl_offset, sizeof(uchar8_t));
    hl = (hl & 0xf0) >> 4;
    size_t hl_byte = hl * 4;

    PcapTCPHeader *p_tcp_header = nullptr;
    p_tcp_header = (PcapTCPHeader*)malloc(hl_byte);
    memcpy(p_tcp_header, tcp_pkt, hl_byte);

    // Modify the byte order.
    p_tcp_header->src_port = SWAP16(p_tcp_header->src_port);
    p_tcp_header->dst_port = SWAP16(p_tcp_header->dst_port);
    p_tcp_header->seq_num = SWAP32(p_tcp_header->seq_num);
    p_tcp_header->ack_num = SWAP32(p_tcp_header->ack_num);
    p_tcp_header->hl_flags = SWAP16(p_tcp_header->hl_flags);
    p_tcp_header->win_size = SWAP16(p_tcp_header->win_size);
    p_tcp_header->checksum = SWAP16(p_tcp_header->checksum);
    p_tcp_header->urg_ptr = SWAP16(p_tcp_header->urg_ptr);

    // 暂时不知道怎么处理基于TCP的DNS报文，搁置这里
    string upper_layer_des;
    // // For uplink packet, assign the upper layer protocol based on the dst port.
    // switch (p_tcp_header->dst_port)
    // {
    //     case PORT_DNS:
    //         upper_layer_des = get_dns_info(tcp_pkt + hl_byte);
    //         break;
    //     default:
    //         break;
    // }
    // // For downlink packet, assign the upper layer protocol based on the src port.
    // switch (p_tcp_header->src_port)
    // {
    //     case PORT_DNS:
    //         upper_layer_des = get_dns_info(tcp_pkt + hl_byte);
    //         break;
    //     default:
    //         break;
    // }

    // Form the TCP description info, including src_port, dst_port, flags, and upper-layer protocol info.
    // Get the flags.
    vector<string> flag_vec;
    vector<uint16_t> candidate_flags = {TCP_FLAG_FIN, TCP_FLAG_SYN, TCP_FLAG_RST, TCP_FLAG_PSH, TCP_FLAG_ACK, 
                                        TCP_FLAG_URG, TCP_FLAG_ECE, TCP_FLAG_CWR, TCP_FLAG_NOC};
    vector<string> flag_names = {"FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR", "NOC"};
    uint16_t flag_mask = 0x0fff;
    uint16_t cur_flags = p_tcp_header->hl_flags & flag_mask;
    for (size_t i = 0; i < candidate_flags.size(); i++) {
        if ((cur_flags & candidate_flags[i]) == candidate_flags[i]) {
            flag_vec.emplace_back(flag_names[i]);
        }
    }
    string flags_str;
    join(flag_vec, flags_str, ",");

    // Format the basic description info.
    char8_t buffer[500];
    memset(buffer, 0, sizeof(buffer));
    snprintf(buffer, sizeof(buffer), "%hu -> %hu [%s]", p_tcp_header->src_port, p_tcp_header->dst_port, flags_str.c_str());
    string des_info(buffer);
    
    if (upper_layer_des.length() > 0) {
        des_info += " " + upper_layer_des;
    }

    free(p_tcp_header);
    p_tcp_header = nullptr;

    return des_info;
}

string parse_udp_pkt(char8_t *udp_pkt)
{
    PcapUDPHeader udp_header;
    memcpy(&udp_header, udp_pkt, sizeof(PcapUDPHeader));
    // Modify the byte order.
    udp_header.src_port = SWAP16(udp_header.src_port);
    udp_header.dst_port = SWAP16(udp_header.dst_port);
    udp_header.len = SWAP16(udp_header.len);
    udp_header.checksum = SWAP16(udp_header.checksum);

    string upper_layer_des;
    // For uplink packet, assign the upper layer protocol based on the dst port.
    switch (udp_header.dst_port)
    {
        case PORT_DNS:
            upper_layer_des = get_dns_info(udp_pkt + sizeof(PcapUDPHeader));
            break;
        default:
            break;
    }
    // For downlink packet, assign the upper layer protocol based on the src port.
    switch (udp_header.src_port)
    {
        case PORT_DNS:
            upper_layer_des = get_dns_info(udp_pkt + sizeof(PcapUDPHeader));
            break;
        default:
            break;
    }

    // Format the description info.
    char8_t buffer[500];
    memset(buffer, 0, sizeof(buffer));
    snprintf(buffer, sizeof(buffer), "%hu -> %hu", udp_header.src_port, udp_header.dst_port);
    string des_info(buffer);

    if (upper_layer_des.length() > 0) {
        des_info += " " + upper_layer_des;
    }

    return des_info;
}
