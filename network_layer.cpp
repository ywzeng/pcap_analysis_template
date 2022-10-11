#include "network_layer.h"

void parse_ipv4_pkt(char8_t *ipv4_pkt)
{
    // Get the IHL field. If its value is greater than IPV4_IHL_MIN (5), the Options field is not NULL.
    uchar8_t ihl_val;
    memcpy(&ihl_val, ipv4_pkt, sizeof(ihl_val));
    ihl_val = ihl_val & 0x0f;
    size_t ihl_byte = ihl_val * 4;

    PcapIPv4Header *p_ipv4_header = nullptr;
    p_ipv4_header = (PcapIPv4Header*)malloc(ihl_byte);
    memset(p_ipv4_header, 0, ihl_byte);
    memcpy(p_ipv4_header, ipv4_pkt, ihl_byte);

    // Modify the byte order.
    p_ipv4_header->total_len = (p_ipv4_header->total_len << 8) | (p_ipv4_header->total_len >> 8);
    p_ipv4_header->identification = (p_ipv4_header->identification << 8) | (p_ipv4_header->identification >> 8);
    p_ipv4_header->flags_frag_offset = (p_ipv4_header->flags_frag_offset << 8) | (p_ipv4_header->flags_frag_offset >> 8);
    p_ipv4_header->header_checksum = (p_ipv4_header->header_checksum << 8) | (p_ipv4_header->header_checksum >> 8);

    switch (p_ipv4_header->protocol_type)
    {
        case IP_PROTOCOL_ICMP:
            parse_icmp_pkt(ipv4_pkt + ihl_byte);
            break;
        case IP_PROTOCOL_TCP:
            parse_tcp_pkt(ipv4_pkt + ihl_byte);
            break;
        case IP_PROTOCOL_UDP:
            parse_udp_pkt(ipv4_pkt + ihl_byte);
            break;
        default:
            break;
    }



    free(p_ipv4_header);

    return;
}

void parse_icmp_pkt(char8_t *icmp_pkt)
{
    PcapICMPHeader icmp_header;
    memcpy(&icmp_header, icmp_pkt, sizeof(PcapICMPHeader));
    // Modify the byte order.
    icmp_header.checksum = (icmp_header.checksum << 8) | (icmp_header.checksum >> 8);

    uint16_t type_code = ((uint16_t)icmp_header.type << 8) | icmp_header.code;
    
    // Different Type/Code pairs (namely temp_tc) correspond to different last 4-byte formats.
    // The further ICMP analysis needs more details on Type/Code tuple.

    // Extract ICMP packet data
    switch (type_code)
    {
        case ICMP_TC_ECHO_REPLY:
            break;
        case ICMP_TC_ECHO_REQUEST:
            break;
        case ICMP_TC_DES_NET_UNREACH:
            break;
        case ICMP_TC_DES_HOST_UNREACH:
            break;
        case ICMP_TC_DES_PROC_UNREACH:
            break;
        case ICMP_TC_DES_PORT_UNREACH:
            break;
        case ICMP_TC_DES_NET_UNKNOWN:
            break;
        case ICMP_TC_DES_HOST_UNKNOWN:
            break;
        case ICMP_TC_TIME_EXCEED_TTL:
            break;
        case ICMP_TC_TIME_EXCEED_FRAG:
            break;
        default:
            break;
    }

    return;
}