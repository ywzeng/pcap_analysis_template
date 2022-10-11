#ifndef _GENERAL_FUNCS_H_
#define _GENERAL_FUNCS_H_

#include <vector>
#include <string>

#include "base_type.h"

using std::vector;
using std::string;

// Convert the hex numbers into hex-strings, namely 0x3a -> "3a".
size_t hex2str(uchar8_t *hex_array, size_t len, vector<string>& res);

// Join all sub-strings into a string using a specific symbol.
size_t join(vector<string>& str_vec, string& res_str, string symbol = " ");

#endif
