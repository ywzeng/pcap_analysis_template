#include "network_layer.h"

vector<string> parse_ipv4_pkt(char8_t *ipv4_pkt)
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

    // Used to aggregate the IPv4 info, including src_ip, dst_ip, encap_protocol, encap_pkt_size, encap_des_info.
    vector<string> ipv4_info_vec;

    vector<string> temp_vec;
    string temp_src_ip, temp_dst_ip;
    // src IP
    hex2str(p_ipv4_header->src_ip_addr, sizeof(p_ipv4_header->src_ip_addr), temp_vec, true);
    join(temp_vec, temp_src_ip, ".");
    // Dst IP
    hex2str(p_ipv4_header->dst_ip_addr, sizeof(p_ipv4_header->dst_ip_addr), temp_vec, true);
    join(temp_vec, temp_dst_ip, ".");
    // Encapsulated Protocol
    string encap_protc;
    // Encapsulated packet size
    size_t encap_pkt_size = p_ipv4_header->total_len - ihl_byte;
    // Encapsulated protocol description
    string encap_des_info;

    switch (p_ipv4_header->protocol_type)
    {
        case IP_PROTOCOL_ICMP:
            encap_protc = "ICMP";
            encap_des_info = parse_icmp_pkt(ipv4_pkt + ihl_byte);
            break;
        case IP_PROTOCOL_TCP:
            encap_protc = "TCP";
            encap_des_info = parse_tcp_pkt(ipv4_pkt + ihl_byte);
            break;
        case IP_PROTOCOL_UDP:
            encap_protc = "UDP";
            encap_des_info = parse_udp_pkt(ipv4_pkt + ihl_byte);
            break;
        case IP_PROTOCOL_GRE:
            ipv4_info_vec = parse_gre_pkt(ipv4_pkt + ihl_byte);
            break;
        default:
            break;
    }

    // The ipv4_info has been aggregated 
    if (ipv4_info_vec.empty())  {
        ipv4_info_vec.emplace_back(temp_src_ip);
        ipv4_info_vec.emplace_back(temp_dst_ip);
        ipv4_info_vec.emplace_back(encap_protc);
        ipv4_info_vec.emplace_back(std::to_string(encap_pkt_size));
        ipv4_info_vec.emplace_back(encap_des_info);
    }

    free(p_ipv4_header);

    return ipv4_info_vec;
}

string parse_icmp_pkt(char8_t *icmp_pkt)
{
    PcapICMPHeader icmp_header;
    memcpy(&icmp_header, icmp_pkt, sizeof(PcapICMPHeader));
    // Modify the byte order.
    icmp_header.checksum = (icmp_header.checksum << 8) | (icmp_header.checksum >> 8);

    uint16_t type_code = ((uint16_t)icmp_header.type << 8) | icmp_header.code;
    
    // Different Type/Code pairs (namely temp_tc) correspond to different last 4-byte formats.
    // The further ICMP analysis needs more details on Type/Code tuple.

    // Form the ICMP description info.
    string des_info;
    switch (type_code)
    {
        case ICMP_TC_ECHO_REPLY:
            des_info = "Echo (ping) reply";
            break;
        case ICMP_TC_ECHO_REQUEST:
            des_info = "Echo (ping) request";
            break;
        case ICMP_TC_DES_NET_UNREACH:
            des_info = "Destination unreachable (Network unreachable)";
            break;
        case ICMP_TC_DES_HOST_UNREACH:
            des_info = "Destination unreachable (Host unreachable)";
            break;
        case ICMP_TC_DES_PROC_UNREACH:
            des_info = "Destination unreachable (Protocol unreachable)";
            break;
        case ICMP_TC_DES_PORT_UNREACH:
            des_info = "Destination unreachable (Port unreachable)";
            break;
        case ICMP_TC_DES_NET_UNKNOWN:
            des_info = "Destination unreachable (Destination network unknown)";
            break;
        case ICMP_TC_DES_HOST_UNKNOWN:
            des_info = "Destination unreachable (Destination host unknown)";
            break;
        case ICMP_TC_TIME_EXCEED_TTL:
            des_info = "Time exceeded (TTL expired in transit)";
            break;
        case ICMP_TC_TIME_EXCEED_FRAG:
            des_info = "Time exceeded (Fragment reassembly time exceeded)";
            break;
        default:
            break;
    }

    return des_info;
}

vector<string> parse_gre_pkt(char8_t *gre_pkt)
{
    uint16_t flag_mask = 0xf800;
    uint16_t cur_flags;
    memcpy(&cur_flags, gre_pkt, sizeof(uint16_t));
    cur_flags = (cur_flags << 8) | (cur_flags >> 8);        // Modify the byte order.
    cur_flags = cur_flags & flag_mask;
    
    size_t cur_op_size = 0;
    bool has_checksum = false, has_offset = false, has_key = false, has_seqnum = false, has_routing = false;
    if ((cur_flags & GRE_FLAG_CHECKSUM) == GRE_FLAG_CHECKSUM) {
        has_checksum = true;
        cur_op_size += GRE_OP_CHECKSUM_SIZE;
    }
    if ((cur_flags & GRE_FLAG_ROUTING) == GRE_FLAG_ROUTING) {
        has_offset = true;
        has_routing = true;
        cur_op_size += GRE_OP_ROUTING_SIZE;
    }
    if ((cur_flags & GRE_FLAG_KEY) == GRE_FLAG_KEY) {
        has_key = true;
        cur_op_size += GRE_OP_KEY_SIZE;
    }
    if ((cur_flags & GRE_FLAG_SEQNUM) == GRE_FLAG_SEQNUM) {
        has_seqnum = true;
        cur_op_size += GRE_OP_SEQNUM_SIZE;
    }

    size_t gre_header_size = sizeof(PcapGREHeader) + cur_op_size;
    PcapGREHeader *p_gre_header = nullptr;
    p_gre_header = (PcapGREHeader*)malloc(gre_header_size);
    memcpy(p_gre_header, gre_pkt, gre_header_size);
    // Modify the byte order.
    p_gre_header->flags_version = (p_gre_header->flags_version << 8) | (p_gre_header->flags_version >> 8);
    p_gre_header->protocol_type = (p_gre_header->protocol_type << 8) | (p_gre_header->protocol_type >> 8);

    // Different flag combination correspond to different options.
    // The further GRE analysis is left as TODO.

    vector<string> gre_pkt_info;
    switch (p_gre_header->protocol_type)
    {
        case GRE_PROTOCOL_IPV4:
            gre_pkt_info = parse_ipv4_pkt(gre_pkt + gre_header_size);
            break;
        case GRE_PROTOCOL_IPV6:
            break;
        default:
            break;
    }

    free(p_gre_header);

    return gre_pkt_info;
}
