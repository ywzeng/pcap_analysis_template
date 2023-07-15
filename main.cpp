#include <stdio.h>
#include <vector>
#include <string>

#include "base_type.h"
#include "arg_parse.h"
#include "pcap.h"

int main(int argc, char** argv)
{
    // if (argc <= 1) {
    //     printf("Need a pcap file.\n");
    //     return 0;
    // }

    // // const char8_t *filepath = "../data/test_ddos_data.pcap";
    // for (int i = 1; i < argc; i++) {
    //     const char8_t *filepath = argv[i];
    //     vector<vector<string>> pkt_info_vec;
    //     parse_pcap(filepath, pkt_info_vec);
    // }

    vector<string> input_files;
    vector<string> opt_list;
    arg_parse(argc, argv, input_files, opt_list);

    
    return 0;
}

