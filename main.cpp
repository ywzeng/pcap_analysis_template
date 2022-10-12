#include "base_type.h"
#include "pcap.h"

int main()
{
    const char8_t *filepath = "./data/test_data_2.pcap";
    vector<vector<string>> pkt_info_vec;
    parse_pcap(filepath, pkt_info_vec);
    
    return 0;
}

