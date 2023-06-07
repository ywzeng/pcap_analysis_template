#include "application_layer.h"

string get_dns_info(char8_t* dns_pkt)
{
    return parse_dns_pkt(dns_pkt);
}
