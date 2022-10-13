#include "pcap.h"

size_t parse_pcap(const char8_t* file_path, vector<vector<string>>& pkt_info_vec)
{
    FILE *fp = fopen(file_path, "rb");
    if (!fp) {
        printf("%s open failed!\n", file_path);
        return 0;
    }

    // Read the Pcap file header.
    PcapFileHeader pcap_header;
    fread(&pcap_header, sizeof(PcapFileHeader), 1, fp);

    if (pcap_header.magic_num == PCAP_HDR_MAGIC_BIG) {
        printf("%s is a big endian Pcap file.\n", file_path);
    } else if (pcap_header.magic_num == PCAP_HDR_MAGIC_LITTLE) {
        printf("%s is a little endian Pcap file.\n", file_path);
    } else {
        printf("%s is not a Pcap file.\n", file_path);
        fclose(fp);
        return 0;
    }

    // Read packets.
    PcapPktHeader *pkt_header = nullptr;
    pkt_header = (PcapPktHeader*)malloc(sizeof(PcapPktHeader));
    while (fread(pkt_header, sizeof(PcapPktHeader), 1, fp)) {
        // Read the data link layer packet.
        char8_t *buffer = nullptr;
        buffer = (char8_t*)malloc(pkt_header->cap_len);
        if (!buffer) {
            break;
        }

        fread(buffer, pkt_header->cap_len, 1, fp);
        vector<string> cur_pkt_info;
        // Parse different link types, respectively.
        switch (pcap_header.link_type) {
            case LINKTYPE_ETHERNET:
                cur_pkt_info = parse_ethernet_pkt(buffer);
                break;
            default:
                break;
        }

        /* 暂时用，测试完了删除一下代码 */
        if (!cur_pkt_info.empty()) {
            for (auto iter: cur_pkt_info) {
                cout << iter << '\t';
            }
            cout << endl;
        }
        /* ========================= */

        free(buffer);
    }

    free(pkt_header);
    fclose(fp);

    return pkt_info_vec.size();
}
