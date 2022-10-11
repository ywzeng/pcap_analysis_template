#include "transport_layer.h"

void parse_tcp_pkt(char8_t *tcp_pkt)
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
    p_tcp_header->src_port = (p_tcp_header->src_port << 8) | (p_tcp_header->src_port >> 8);
    p_tcp_header->dst_port = (p_tcp_header->dst_port << 8) | (p_tcp_header->dst_port >> 8);
    p_tcp_header->seq_num = (p_tcp_header->seq_num << 24) | ((p_tcp_header->seq_num & 0x0000ff00) << 8) | 
                            ((p_tcp_header->seq_num & 0x00ff0000) >> 8) | (p_tcp_header->seq_num >> 24);
    p_tcp_header->ack_num = (p_tcp_header->ack_num << 24) | ((p_tcp_header->ack_num & 0x0000ff00) << 8) | 
                            ((p_tcp_header->ack_num & 0x00ff0000) >> 8) | (p_tcp_header->ack_num >> 24);
    p_tcp_header->hl_flags = (p_tcp_header->hl_flags << 8) | (p_tcp_header->hl_flags >> 8);
    p_tcp_header->win_size = (p_tcp_header->win_size << 8) | (p_tcp_header->win_size >> 8);
    p_tcp_header->checksum = (p_tcp_header->checksum << 8) | (p_tcp_header->checksum >> 8);
    p_tcp_header->urg_ptr = (p_tcp_header->urg_ptr << 8) | (p_tcp_header->urg_ptr >> 8);

    free(p_tcp_header);

    return;
}

void parse_udp_pkt(char8_t *udp_pkt)
{
    PcapUDPHeader udp_header;
    memcpy(&udp_header, udp_pkt, sizeof(PcapUDPHeader));
    // Modify the byte order.
    udp_header.src_port = (udp_header.src_port << 8) | (udp_header.src_port >> 8);
    udp_header.dst_port = (udp_header.dst_port << 8) | (udp_header.dst_port >> 8);
    udp_header.len = (udp_header.len << 8) | (udp_header.len >> 8);
    udp_header.checksum = (udp_header.checksum << 8) | (udp_header.checksum >> 8);

    return;
}