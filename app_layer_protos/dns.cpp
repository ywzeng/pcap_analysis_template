#include "dns.h"

/**
 * Extract domain name from the DNS packet RR section. 
 * Notice the zip mode. Apart from the entire domain name, certain suffix of the domain can also be represented in zip mode.
 * 
 * Note that the domain field is represented as 'len-string' pair.
 * For example, 'baidu.com' is represented as '05 62 61 69 64 75 03 63 6f 6d 00' in HEX format, 
 *      where '05' and '03' indicate the length of the following bytes, and '00' is the ending symbol.
 * In this case, the length of 'baidu.com' is 9, but the byte it occupies is 11 in DNS packet.
 * 
 * Return the actual occupied bytes of the domain field.
*/
uint16_t get_domain(char8_t* dns_pkt, uint16_t offset, string& domain)
{
    uint16_t occupied_bytes = 0;
    bool is_zip = false;

    // Get the occupied bytes of the first label, and check whether it involves zip mode.
    uchar8_t label_bytes = (dns_pkt + offset)[0];
    while (label_bytes) {
        // Check the zip mode flag.
        if (label_bytes >= DNS_ZIP_FLAG) {
            memcpy(&offset, dns_pkt + offset, sizeof(uint16_t));
            // Modify the byte order.
            offset = SWAP16(offset);
            // Extract the embedded offset.
            offset = offset & DNS_ZIP_MASK;

            label_bytes = (dns_pkt + offset)[0];

            if (!is_zip) {
                is_zip = true;
                occupied_bytes += sizeof(uint16_t);
            }
        } else {
            // Copy the domain label.
            char8_t* label = (char8_t*)malloc(label_bytes + 1);     // Consider the '\0' ending symbol.
            memset(label, '\0', label_bytes + 1);
            memcpy(label, dns_pkt + offset + 1, label_bytes);       // Skip the 'label_bytes' byte.
            domain += string(label);

            free(label);
            label = nullptr;

            if (!is_zip) {
                // Consider the 'label_bytes' byte at the beginning of the label field.
                occupied_bytes += 1+ label_bytes;
            }

            offset += 1 + label_bytes;
            label_bytes = (dns_pkt + offset)[0];

            if (label_bytes) {
                domain += ".";
            }
        }
    }
    
    // Consider the '\0' ending symbel at the end of the domain field.
    if (!is_zip) {
        occupied_bytes++;
    }

    return occupied_bytes;
}

void free_question_section(vector<PcapDNSQuestion>& dns_question_list)
{
    for (auto iter = dns_question_list.begin(); iter != dns_question_list.end(); iter++) {
        if (iter->name != nullptr) {
            free(iter->name);
            iter->name = nullptr;
        }
    }
}

void free_rr_section(vector<PcapDNSRR>& dns_rr_list)
{
    for (auto iter = dns_rr_list.begin(); iter != dns_rr_list.end(); iter++) {
        if (iter->name != nullptr) {
            free(iter->name);
            iter->name = nullptr;
        }
        if (iter->rdata != nullptr) {
            free(iter->rdata);
            iter->rdata = nullptr;
        }
    }
}

void get_question_section_info(char8_t* dns_pkt, uint16_t& offset, PcapDNSQuestion& cur_ques_sec)
{
    // Get domain.
    string temp_domain;
    uint16_t dm_occupied_len = get_domain(dns_pkt, offset, temp_domain);
    cur_ques_sec.name = (char8_t*)malloc(temp_domain.length() + 1);
    memset(cur_ques_sec.name, '\0', temp_domain.length() + 1);
    temp_domain.copy(cur_ques_sec.name, temp_domain.length(), 0);

    // Get domain length.
    cur_ques_sec.name_len = strlen(cur_ques_sec.name);

    // Get query type.
    offset += dm_occupied_len;
    memcpy(&cur_ques_sec.qtype, dns_pkt + offset, sizeof(uint16_t));
    cur_ques_sec.qtype = SWAP16(cur_ques_sec.qtype);

    // Get query class.
    offset += sizeof(uint16_t);
    memcpy(&cur_ques_sec.qclass, dns_pkt + offset, sizeof(uint16_t));
    cur_ques_sec.qclass = SWAP16(cur_ques_sec.qclass);

    offset += sizeof(uint16_t);
}

void get_rr_section_info(char8_t* dns_pkt, uint16_t& offset, PcapDNSRR& cur_rr_sec)
{
    // Get domain.
    string temp_domain;
    uint16_t dm_occupied_len = get_domain(dns_pkt, offset, temp_domain);
    cur_rr_sec.name = (char8_t*)malloc(temp_domain.length() + 1);
    memset(cur_rr_sec.name, '\0', temp_domain.length() + 1);
    temp_domain.copy(cur_rr_sec.name, temp_domain.length(), 0);

    // Get domain length.
    cur_rr_sec.name_len = strlen(cur_rr_sec.name);

    // Get RR type.
    offset += dm_occupied_len;
    memcpy(&cur_rr_sec.rr_type, dns_pkt + offset, sizeof(uint16_t));
    cur_rr_sec.rr_type = SWAP16(cur_rr_sec.rr_type);

    // Get RR class.
    offset += sizeof(uint16_t);
    memcpy(&cur_rr_sec.rr_class, dns_pkt + offset, sizeof(uint16_t));
    cur_rr_sec.rr_class = SWAP16(cur_rr_sec.rr_class);

    // Get TTL.
    offset += sizeof(uint16_t);
    memcpy(&cur_rr_sec.ttl, dns_pkt + offset, sizeof(uint32_t));
    cur_rr_sec.ttl = SWAP32(cur_rr_sec.ttl);
        
    // Get RDATA length.
    offset += sizeof(uint32_t);
    memcpy(&cur_rr_sec.rd_len, dns_pkt + offset, sizeof(uint16_t));
    cur_rr_sec.rd_len = SWAP16(cur_rr_sec.rd_len);

    // Get RDATA.
    offset += sizeof(uint16_t);
    cur_rr_sec.rdata = (char8_t*)malloc(sizeof(char8_t) * cur_rr_sec.rd_len);
    memcpy(cur_rr_sec.rdata, dns_pkt + offset, cur_rr_sec.rd_len);

    offset += cur_rr_sec.rd_len;
}

string parse_dns_pkt(char8_t* dns_pkt)
{
    PcapDNSHeader dns_header;
    memcpy(&dns_header, dns_pkt, sizeof(PcapDNSHeader));

    // Modify the byte order.
    dns_header.trans_id = SWAP16(dns_header.trans_id);
    dns_header.flags = SWAP16(dns_header.flags);
    dns_header.qd_cnt = SWAP16(dns_header.qd_cnt);
    dns_header.an_cnt = SWAP16(dns_header.an_cnt);
    dns_header.ns_cnt = SWAP16(dns_header.ns_cnt);
    dns_header.ar_cnt = SWAP16(dns_header.ar_cnt);

    // Identify the flags.
    // test, 暂时只识别方向和是否是nxdomain
    bool is_query = false;
    bool is_nxdomain = false;
    if ((dns_header.flags & DNS_FLAG_QR_Q) == DNS_FLAG_QR_Q) {
        is_query = true;
    }
    if (!is_query && (dns_header.flags & DNS_RCODE_NXDOMAIN) == DNS_RCODE_NXDOMAIN) {
        is_nxdomain = true;
    }

    // printf("---- ID: 0x%04x ---- Query: %d ---- Answer: %d ---- Authority: %d ---- Additional: %d ----\n", 
    //         dns_header.trans_id, dns_header.qd_cnt, dns_header.an_cnt, dns_header.ns_cnt, dns_header.ar_cnt);

    // Assign the Question, Answer RR, Authority RR, and Additional RR sections based on the DNS header info, respectively.
    // Find the corresponding sections based on a cumulative offset.
    uint16_t offset = sizeof(PcapDNSHeader);
    // Assign the Question sections.
    vector<PcapDNSQuestion> dns_question_list(dns_header.qd_cnt);
    for (uint16_t i = 0; i < dns_header.qd_cnt; i++) {
        PcapDNSQuestion cur_ques_sec;
        get_question_section_info(dns_pkt, offset, cur_ques_sec);
        dns_question_list[i] = cur_ques_sec;

        // printf("Query - %d: %s, %d, 0x%04x\n", i, cur_ques_sec.name, cur_ques_sec.qtype, cur_ques_sec.qclass);
    }

    // Assign the Answer RR sections.
    vector<PcapDNSRR> dns_answer_list(dns_header.an_cnt);
    for (uint16_t i = 0; i < dns_header.an_cnt; i++) {
        PcapDNSRR cur_ans_sec;
        get_rr_section_info(dns_pkt, offset, cur_ans_sec);
        dns_answer_list[i] = cur_ans_sec;

        // printf("Answer - %d: %s, %d, 0x%04x, %d, %d\n", i, cur_ans_sec.name, cur_ans_sec.rr_type, cur_ans_sec.rr_class, cur_ans_sec.ttl, cur_ans_sec.rd_len);
    }

    // Assign the Authority RR sections.
    vector<PcapDNSRR> dns_authority_list(dns_header.ns_cnt);
    for (uint16_t i = 0; i < dns_header.ns_cnt; i++) {
        PcapDNSRR cur_auth_sec;
        get_rr_section_info(dns_pkt, offset, cur_auth_sec);
        dns_authority_list[i] = cur_auth_sec;

        // printf("Authority - %d: %s\n", i, cur_auth_sec.name);
    }

    // Assign the Additional RR sections.
    vector<PcapDNSRR> dns_additional_list(dns_header.ar_cnt);
    for (uint16_t i = 0; i < dns_header.ar_cnt; i++) {
        PcapDNSRR cur_add_sec;
        get_rr_section_info(dns_pkt, offset, cur_add_sec);
        dns_additional_list[i] = cur_add_sec;

        // printf("Additional - %d: %s\n", i, cur_add_sec.name);
    }

    char8_t buffer[300];
    memset(buffer, '\0', sizeof(buffer));
    string query_flag;
    if (is_query) {
        query_flag = "DNS Query";
        snprintf(buffer, sizeof(buffer), "%s \t QueryNum: %hu", query_flag.c_str(), dns_header.qd_cnt);
    } else {
        query_flag = "DNS Reponse";
        if (is_nxdomain) {
            string nxd_info = "NXDomain";
            snprintf(buffer, sizeof(buffer), "%s %s", query_flag.c_str(), nxd_info.c_str());
        } else {
            snprintf(buffer, sizeof(buffer), "%s QueryNum: %hu, AnswerNum: %hu, NSNum: %hu, AdditionalNum: %hu", query_flag.c_str(), dns_header.qd_cnt, dns_header.an_cnt, dns_header.ns_cnt, dns_header.ar_cnt);
        }
    }
    string des_info(buffer);

    // Free the allocated domain momery.
    free_question_section(dns_question_list);
    free_rr_section(dns_answer_list);
    free_rr_section(dns_authority_list);
    free_rr_section(dns_additional_list);

    return des_info;
}
