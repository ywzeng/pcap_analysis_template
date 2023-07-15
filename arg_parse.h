#ifndef _ARG_PARSE_H_
#define _ARG_PARSE_H_

#include <stdio.h>
#include <string.h>
#include <vector>
#include <string>
#include <unordered_set>
#include <unordered_map>

using std::vector;
using std::string;
using std::pair;
using std::unordered_map;
using std::unordered_set;

/**
 * Two kinds of options, namely with argument (arged) and without argument (unarged).
 * Use a single hyphen '-' and double hyphens '--' to indicate arged and unarged options, respectively.
 *   For example, '-o abc.txt' indicates that saved the parsing results into the file 'abc.txt'.
 *                '-srcip 192.168.1.5' indicates that only packets whose srcip is 192.168.1.5 should be kept.
 *                '--tcp' indicates that keeping the TCP packets.
 *                '--icmp' indicates that keeping the ICMP packets.
 * 
 * Priority needs to be set between options (both arged and unarged).
 * High-priority options should override low-priority options.
*/

#define TOTAL_OPT_NUM                         17     // The total number of defined macros.

// The macro value is used to indicate the index of corresponding option in the option list.
// Command options declared with arguments required.
#define ARGED_OPT_OUTPUT_FILE                 0
#define ARGED_OPT_PARSE_COUNT                 1      // '-c val'. Specify the number of parsing entry.
#define ARGED_OPT_FILTER_IP                   2
#define ARGED_OPT_FILTER_SRCIP                3
#define ARGED_OPT_FILTER_DSTIP                4
#define ARGED_OPT_FILTER_PORT                 5
#define ARGED_OPT_FILTER_SRCPORT              6
#define ARGED_OPT_FILTER_DSTPORT              7

// Command options declared with no argument.
#define UNARGED_OPT_OUTPUT_COUNT              8      // '--count'. Output the total number of entry number.
#define UNARGED_OPT_PARSE_LAYER_DATALINK      9
#define UNARGED_OPT_PARSE_LAYER_NETWORK       10
#define UNARGED_OPT_PARSE_LAYER_TRANSPORT     11
#define UNARGED_OPT_FILTER_PROTOCOL_ARP       12
#define UNARGED_OPT_FILTER_PROTOCOL_TCP       13
#define UNARGED_OPT_FILTER_PROTOCOL_UDP       14
#define UNARGED_OPT_FILTER_PROTOCOL_ICMP      15
#define UNARGED_OPT_FILTER_PROTOCOL_DNS       16

// Identifier for unarged-options.
#define UNARGED_OPT_SET_FLAG                  "ON"

unordered_map<string, int> ARGED_OPTIONS_MAP = {
    {"-o",       ARGED_OPT_OUTPUT_FILE},
    {"-c",       ARGED_OPT_PARSE_COUNT},
    {"-ip",      ARGED_OPT_FILTER_IP},
    {"-srcip",   ARGED_OPT_FILTER_SRCIP},
    {"-dstip",   ARGED_OPT_FILTER_DSTIP},
    {"-port",    ARGED_OPT_FILTER_PORT},
    {"-srcport", ARGED_OPT_FILTER_SRCPORT},
    {"-dstport", ARGED_OPT_FILTER_DSTPORT}
};

unordered_map<string, int> UNARGED_OPTIONS_MAP = {
    {"--count", UNARGED_OPT_OUTPUT_COUNT},
    {"--datalink", UNARGED_OPT_PARSE_LAYER_DATALINK},
    {"--network", UNARGED_OPT_PARSE_LAYER_NETWORK},
    {"--transport", UNARGED_OPT_PARSE_LAYER_TRANSPORT},
    {"--arp", UNARGED_OPT_FILTER_PROTOCOL_ARP},
    {"--tcp", UNARGED_OPT_FILTER_PROTOCOL_TCP},
    {"--udp", UNARGED_OPT_FILTER_PROTOCOL_UDP},
    {"--icmp", UNARGED_OPT_FILTER_PROTOCOL_ICMP},
    {"--dns", UNARGED_OPT_FILTER_PROTOCOL_DNS}
};


/**
 * Consider the single-hyphen (e.g., '-o', '-x', '-srcip') and the double-hyphen options (e.g., --tcp) here.
 * A single-hyphen option must be used with a matching argument.
 * Double-hyphen options should be used individually, indicating certain parsing modes.
*/
bool arg_extract(int argc, char** argv, 
                 vector<pair<string, string>>& opt_arg_pairs, 
                 vector<string>& unarg_opts, 
                 vector<string>& operands)
{
    // Used to check the repeadtedly input arguments.
    unordered_map<string, int> arg_opt_idx_map;
    unordered_set<string> unarg_opt_set;
    unordered_set<string> operand_set;

    bool opt_error = false;

    for (int i = 1; i < argc; i++) {
        // Process the options (both the arged and the unarged).
        if (argv[i][0] == '-') {
            // Process the exceptional cases when option length no more than 2.
            // Only a '-' or '--' symbol. No more suffixed options.
            if (strlen(argv[i]) == 1 || (strlen(argv[i]) == 2 && argv[i][1] == '-')) {
                printf("Invalid option '%s'. Missing specific option.\n", argv[i]);
                opt_error = true;
                break;
            } else if (argv[i][1] == '-') {     // Extract the '--' prefixed options.
                string temp_unarg_opt(argv[i]);
                // Ignore the repeated input unarged options.
                if (unarg_opt_set.find(temp_unarg_opt) == unarg_opt_set.end()) {
                    unarg_opt_set.insert(temp_unarg_opt);
                    unarg_opts.emplace_back(temp_unarg_opt);
                }
            } else if (strlen(argv[i]) >= 2) {      // Extract the '-' prefixed options and the corresponding arguments.
                // Process the exceptional case when facing a single-hyphen option without valid argument followed.
                //   1. Directly a single-hyphen option at the command tail.
                //   2. No argument after an option.
                if (i == argc - 1 || argv[i + 1][0] == '-') {
                    printf("No matching argument for option '%s'.\n", argv[i]);
                    opt_error = true;
                    break;
                } else {
                    string temp_opt(argv[i]);
                    string temp_arg(argv[i + 1]);
                    unordered_map<string, int>::iterator map_iter = arg_opt_idx_map.find(temp_opt);
                    // Update the repeatedly declared arged options.
                    if (map_iter == arg_opt_idx_map.end()) {
                        pair<string, string> opt_arg = std::make_pair(temp_opt, temp_arg);
                        opt_arg_pairs.emplace_back(opt_arg);
                        arg_opt_idx_map.insert(std::make_pair(temp_opt, opt_arg_pairs.size() - 1));
                    } else {
                        opt_arg_pairs[map_iter->second].second = temp_arg;
                    }

                    i++;
                }
            } else {
                printf("An unexpected error occurred when parsing the option '%s'.\n", argv[i]);
                opt_error = true;
                break;
            }
        } else {        // Process the operands, namely the files need to be parsed.
            string temp_operand(argv[i]);
            // Ignore the repeated input operands.
            if (operand_set.find(temp_operand) == operand_set.end()) {
                operands.emplace_back(string(argv[i]));
                operand_set.insert(temp_operand);
            }
        }
    }

    // Process the option errors.
    if (opt_error) {
        // Clear the referenced vectors.
        vector<pair<string, string>>().swap(opt_arg_pairs);
        vector<string>().swap(unarg_opts);
        vector<string>().swap(operands);

        return false;
    }

    return true;
}

/**
 * Handle the priority between options.
 * Ignore the options with lower priority when two options conflict.
 * 
 * Leave it for future work.
*/
bool priority_manage(vector<string>& opt_list)
{
    return true;
}

/**
 * Get the input pcap files and the saved output file from the command arguments.
 * Returns true if the options and arguments are valid, otherwise, false.
 * 
 * The parameter opt_list reserves the declaration of corresponding options.
 * For arged options (e.g., '-o'), the value represents the corresponding argument.
 * As for unarged options (e.g., '--tcp'), use the defined macro "ON" to flag the corresponding declaration.
 * 
 * There should be certain options to identify the packet extrction rules.
 * For example, "--tcp" represents extracting the TCP packets.
 * Leave it for future work.
*/
bool arg_parse(int argc, char** argv, vector<string>& input_files, vector<string>& opt_list) {
    vector<pair<string, string>> opt_arg_pairs;
    vector<string> unarg_opts;
    vector<string> operands;
    if (!arg_extract(argc, argv, opt_arg_pairs, unarg_opts, operands)) {
        return false;
    }

    bool parsing_error = false;

    // First, parse the operands, namely the input files.
    if (operands.empty()) {
        printf("Need an input file.\n");
        parsing_error = true;
    } else {
        for (string oper: operands) {
            input_files.emplace_back(oper);
        }
    }

    // Verify the validity options, including both arged and unarged options.
    // Re-initialize the option list with empty strings.
    vector<string>(TOTAL_OPT_NUM).swap(opt_list);

    // Parse the arged options. Process the undefined options.
    if (!parsing_error) {
        for (pair<string, string> cur_pair: opt_arg_pairs) {
            auto arged_opt_iter = ARGED_OPTIONS_MAP.find(cur_pair.first);
            if (arged_opt_iter == ARGED_OPTIONS_MAP.end()) {
                printf("Undefined option '%s'.\n", cur_pair.first.c_str());
                parsing_error = true;
                break;
            }

            opt_list[arged_opt_iter->second] = cur_pair.second;
        }
    }

    // Parse the unarged options. Process the undefined options.
    if (!parsing_error) {
        for (string opt: unarg_opts) {
            auto unarged_opt_iter = UNARGED_OPTIONS_MAP.find(opt);
            if (unarged_opt_iter == UNARGED_OPTIONS_MAP.end()) {
                printf("Undefined option '%s'.\n", opt.c_str());
                parsing_error = true;
                break;
            }

            opt_list[unarged_opt_iter->second] = UNARGED_OPT_SET_FLAG;
        }
    }

    // Process the parsing errors.
    if (parsing_error) {
        // Clear the referenced vectors.
        vector<string>().swap(input_files);
        vector<string>(TOTAL_OPT_NUM).swap(opt_list);
        return false;
    }

    return true;
}

#endif
