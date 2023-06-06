/**
 * The details of DNS protocol format can refer to RFC1035.
 * https://www.rfc-editor.org/rfc/rfc1035.html
 * Also can refer to IANA document.
 * https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml
*/

#ifndef _DNS_H_
#define _DNS_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <iostream>
#include <string>
#include <vector>

#include "../base_type.h"

using std::vector;
using std::string;

// DNS flags. More RCODEs need to be complemented.
#define DNS_FLAG_QR_Q      0x8000
#define DNS_FLAG_QR_R      0x0000
#define DNS_FLAG_OP_SQUERY 0x0000
#define DNS_FLAG_OP_IQUERY 0x0800
#define DNS_FLAG_OP_STATUS 0x1000
#define DNS_FLAG_OP_NOTIFY 0x2000
#define DNS_FLAG_OP_UPDATE 0x2800
#define DNS_FLAG_OP_DSO    0x3000
#define DNS_FLAG_AA_N      0x0000
#define DNS_FLAG_AA_Y      0x0400
#define DNS_FLAG_TC_N      0x0000
#define DNS_FLAG_TC_Y      0x0200
#define DNS_FLAG_RD_N      0x0000
#define DNS_FLAG_RD_Y      0x0100
#define DNS_FLAG_RA_N      0x0000
#define DNS_FLAG_RA_Y      0x0080
#define DNS_FLAG_AD_N      0x0000
#define DNS_FLAG_AD_Y      0x0020
#define DNS_FLAG_CD_N      0x0000
#define DNS_FLAG_CD_Y      0x0010
#define DNS_RCODE_NOERR    0x0000
#define DNS_RCODE_FMERR    0x0001
#define DNS_RCODE_SERVFAIL 0x0002
#define DNS_RCODE_NXDOMAIN 0x0003

// DNS types. More types need to be complemented.
#define DNS_TYPE_A         0x0001
#define DNS_TYPE_NS        0x0002
#define DNS_TYPE_MD        0x0003
#define DNS_TYPE_MF        0x0004
#define DNS_TYPE_CNAME     0x0005
#define DNS_TYPE_SOA       0x0006
#define DNS_TYPE_MB        0x0007
#define DNS_TYPE_MG        0x0008
#define DNS_TYPE_MR        0x0009
#define DNS_TYPE_NULL      0x000a
#define DNS_TYPE_WKS       0x000b
#define DNS_TYPE_PTR       0x000c
#define DNS_TYPE_HINFO     0x000d
#define DNS_TYPE_MINFO     0x000e
#define DNS_TYPE_MX        0x000f
#define DNS_TYPE_TXT       0x0010
#define DNS_TYPE_AAAA      0x001c
#define DNS_TYPE_SRV       0x0021
#define DNS_TYPE_DNAME     0x0027
#define DNS_TYPE_NINFO     0x0038
#define DNS_TYPE_HTTPS     0x0041
#define DNS_TYPE_IXFR      0x00fb
#define DNS_TYPE_AXFR      0x00fc
#define DNS_TYPE_MAILB     0x00fd
#define DNS_TYPE_MAILA     0X00fe
#define DNS_TYPE_ANY       0x00ff

// DNS classes. More classes need to be complemented.
#define DNS_CLASS_IN       0x0001
#define DNS_CLASS_CS       0x0002
#define DNS_CLASS_CH       0x0003
#define DNS_CLASS_HS       0x0004
#define DNS_CLASS_NONE     0x00fe
#define DNS_CLASS_ANY      0x00ff

/**
 * Message compression (zip mode) flag.
 * In the zip mode 2-byte, the first 2 bits are specified as '11', 
 *      and the remaining 14 bits are organized as the offset from the ID field.
 *     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *     | 1  1|                OFFSET                   |
 *     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*/
#define DNS_ZIP_FLAG       0xc0
#define DNS_ZIP_MASK       0x3fff

// DNS packet header. 12 bytes.
typedef struct PcapDNSHeader {
    uint16_t trans_id;
    uint16_t flags;         // The highest 1-bit (QR) indicates whether the message is a query (0) or a reply (1).
                            // The next 4-bit (OPCODE) represents the opcode.
                            // The next 1-bit (AA) indicates whether the responding DNS server is authoritative.
                            // The next 1-bit (TC) indicates whether the message is truncated.
                            // The next 1-bit (RD) indicates whether the client desired a recursive query.
                            // The next 1-bit (RA) indicates whether the responding DNS server supports recursive query.
                            // The next 1-bit (Z) is reserved.
                            // The next 1-bit (AD) indicates in a response packet that whether the response data has been verified by the responding DNS server.
                            // The next 1-bit (CD) indicates in a query packet that whether the non-verified data is acceptable by the client.
                            // The last 4-bit (RCODE) represents the respond code.
    uint16_t qd_cnt;
    uint16_t an_cnt;
    uint16_t ns_cnt;
    uint16_t ar_cnt;
} PcapDNSHeader;

/**
 * DNS packet Question section. 
 * A DNS packet may contain more than one Question section.
*/
typedef struct PcapDNSQuestion {
    char8_t* name;
    uint16_t name_len;
    uint16_t qtype;
    uint16_t qclass;
} PcapDNSQuestion;

/**
 * The Answer, Authority, and Additional sections all share the same format:
 * a variable number of RRs, where the number of records is specified in the
 * corresponding count field in the DNS header.
 * 
 * Different RR types have different RDATA format.
*/
typedef struct PcapDNSRR {
    char8_t* name;          // Notice, e.g., the '0xc00c', in the domain field, which is the 'message compression' scheme in DNS.
                            // In message compression scheme, an entire domain is replaced with a pointer to a prior occurance of the same domain.
                            // The message compression bytes occupies two bytes, and the first 2 bits are ones.
                            // More details about the message compression scheme can refer to https://www.rfc-editor.org/rfc/rfc1035.html#section-4.1.4.
    uint16_t name_len;
    uint16_t rr_type;
    uint16_t rr_class;
    uint32_t ttl;
    uint16_t rd_len;
    char8_t* rdata;
} PcapDNSRR;

uint16_t get_domain(char8_t* dns_pkt, uint16_t offset, string& domain);
void free_question_section(vector<PcapDNSQuestion>& dns_question_list);
void free_rr_section(vector<PcapDNSRR>& dns_rr_list);
void get_question_section_info(char8_t* dns_pkt, uint16_t& offset, PcapDNSQuestion& cur_ques_sec);
void get_rr_section_info(char8_t* dns_pkt, uint16_t& offset, PcapDNSRR& cur_rr_sec);
void parse_dns_pkt(char8_t* dns_pkt);

#endif
