#include "general_funcs.h"

size_t hex2str(uchar8_t *hex_array, size_t len, vector<string>& res_vec, bool decimal)
{
    if (!res_vec.empty()) {
        vector<string>().swap(res_vec);     // Clear the given vector.
    }

    if (decimal) {
        for (size_t i = 0; i < len; i++) {
            res_vec.emplace_back(std::to_string(hex_array[i]));
        }
    } else {
        string hex_char = "0123456789abcdef";
        for (size_t i = 0; i < len; i++) {
            char8_t str_h = hex_char[hex_array[i] >> 4];
            char8_t str_l = hex_char[hex_array[i] & 0x0f];
            string cur_str;
            cur_str = cur_str + str_h + str_l;
            res_vec.emplace_back(cur_str);
        }
    }

    return res_vec.size();
}

size_t join(vector<string>& str_vec, string& res_str, string symbol)
{
    if (!res_str.empty()) {
        string().swap(res_str);
    }

    for (auto iter = str_vec.begin(); iter != str_vec.end();) {
        res_str += *iter;
        if (++iter != str_vec.end()) {
            res_str += symbol;
        }
    }

    return res_str.length();
}
