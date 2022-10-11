#ifndef _BASE_TYPE_H_
#define _BASE_TYPE_H_

typedef char char8_t;
typedef unsigned char uchar8_t;
typedef short int16_t;
typedef unsigned short uint16_t;
typedef int int32_t;
typedef unsigned int uint32_t;
#ifdef _WIN32
    typedef long long int64_t;
    typedef unsigned long long uint64_t;
#elif __linux__
    typedef long int64_t;
    typedef unsigned long int64_t;
#endif

#endif
