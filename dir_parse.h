#ifndef _DIR_PARSE_
#define _DIR_PARSE_

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <vector>
#include <string>

using std::vector;
using std::string;

/**
 * Check whether the file is a Pcap file.
 * Leave it for future work.
*/

/**
 * Get and check the basic info of the file within the given list, namely checking whether it is a file or a directory.
 * Recursively parse all the inner files when encountering a directory.
 * Ignore the invalid files and directories.
*/
vector<string> parse_input(vector<string>& input_list)
{
    vector<string> file_list;

    // Check the type of each file.
    for (string& input: input_list) {
        const char* input_file = input.c_str();
        struct stat file_stat;
        stat(input_file, &file_stat);
        if (S_ISDIR(file_stat.st_mode)) {
            vector<string> subdir_file_list = parse_dir(input_file);
            file_list.insert(file_list.end(), subdir_file_list.begin(), subdir_file_list.end());
        } else if (S_ISREG(file_stat.st_mode)) {
            file_list.emplace_back(input);
        } else {
            printf("'%s' is not a valid file/dir.\n", input_file);
        }
    }

    return file_list;
}

/**
 * Get and check the basic info of the given file, namely check whether the input is a file or a directory.
 * Return an empty string when encountering an invalid input.
*/
vector<string> parse_input(const char* input)
{
    vector<string> file_list;

    // Check the file type.
    struct stat file_stat;
    stat(input, &file_stat);
    if (S_ISDIR(file_stat.st_mode)) {
        file_list = parse_dir(input);
    } else if (S_ISREG(file_stat.st_mode)) {
        file_list.emplace_back(string(input));
    } else {
        printf("'%s' is not a valid file/dir.\n", input);
    }

    return file_list;
}

/**
 * Recursively parse the files within the given directory.
*/
vector<string> parse_dir(const char* input_dir)
{
    
}

#endif
