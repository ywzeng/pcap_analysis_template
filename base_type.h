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
    typedef unsigned long uint64_t;
#endif

#define BIT32_BYTE1_MASK 0x000000ff
#define BIT32_BYTE2_MASK 0x0000ff00
#define BIT32_BYTE3_MASK 0x00ff0000
#define BIT32_BYTE4_MASK 0xff000000

#define SWAP16(A)        (((uint16_t)(A) << 8) | ((uint16_t)(A) >> 8))

#define SWAP32(A)        ((((uint32_t)(A) & BIT32_BYTE1_MASK) << 24) | \
                          (((uint32_t)(A) & BIT32_BYTE2_MASK) <<  8) | \
                          (((uint32_t)(A) & BIT32_BYTE3_MASK) >>  8) | \
                          (((uint32_t)(A) & BIT32_BYTE4_MASK) >> 24))

#endif
