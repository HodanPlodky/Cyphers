#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// used wiki alot 
// https://en.wikipedia.org/wiki/MD5

typedef unsigned char   uint8_t;
typedef unsigned int    uint32_t;

// specifies per round amount
const uint32_t s[64] = {
    7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
    5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
    4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
    6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21
};
/*
 * for i from 0 to 63 do
 *      K[i] := floor(232 × abs (sin(i + 1)))
 * end for
 *
 * This is how this is generated
 */
const uint32_t k[64] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};

uint32_t 
leftrotate(uint32_t x, uint32_t c) {
    return (x << c) | (x >> (32 - c));
}

void
handleBlock(uint32_t block[16], uint32_t * a0, uint32_t * b0, uint32_t * c0, uint32_t * d0) {
    uint32_t a = *a0;
    uint32_t b = *b0;
    uint32_t c = *c0;
    uint32_t d = *d0;
    for (uint32_t i = 0; i < 64; i++) {
        uint32_t f, g;
        if (i <= 15) {
            f = (b & c) | ((~b) & c);
            g = i;
        }
        else if (i <= 31) {
            f = (d & b) | ((~d) & c);
            g = (5*i + 1) % 16;
        }
        else if (i <= 47) {
            f = b ^ c ^ d;
            g = (3 * i + 5) % 16;
        }
        else {
            f = c ^ (b | (~d));
            g = (7 * i) % 16;
        }
        f = f + a + k[i] + block[g];
        a = d;
        d = c;
        c = b;
        b = b + leftrotate(f, s[i]);
    }
    *a0 += a;
    *b0 += b;
    *c0 += c;
    *d0 += d;
}

void
md5hash(uint8_t buffer[16]) {
    uint32_t block[16];
    FILE * inputstream = freopen(NULL, "rb", stdin);
    uint32_t a0 = 0x67452301;
    uint32_t b0 = 0xefcdab89;
    uint32_t c0 = 0x98badcfe;
    uint32_t d0 = 0x10325476;
    size_t sum = 0;
    while(1) {
        size_t read = fread(block, 1, sizeof(uint32_t) * 16, inputstream);
        sum += read;
        if (read < sizeof(uint32_t) * 16) {
            // padding
            size_t sizeneeded = (56 - ((sum + 1) % 64));// + read + 8;
            if (sizeneeded < 0)
                sizeneeded += 64;
            sizeneeded += read + 8 + 1;
            uint8_t * blockBytes = (uint8_t*) malloc(sizeneeded);
            memcpy(blockBytes, block, read);
            blockBytes[read] = 1 << 7;
            for(size_t i = read + 1; i < sizeneeded - 8; i++) {
                blockBytes[i] = 0;
            }
            for (size_t i = 0; i < 8; i++) {
                blockBytes[sizeneeded - 8 + i] = sum >> ((8 - i - 1) * 8);
            }
            for (size_t i = 0; i < sizeneeded; i += 64) {
                handleBlock((uint32_t*)(blockBytes + i), &a0, &b0, &c0, &d0);
            }
            free(blockBytes);
            break;
        }
        else {
            // normal
            handleBlock(block, &a0, &b0, &c0, &d0);
        }
    }
    fclose(inputstream);
    // concat output
    buffer[0]   = (uint8_t)(a0 >> 24);
    buffer[1]   = (uint8_t)(a0 >> 16);
    buffer[2]   = (uint8_t)(a0 >> 8);
    buffer[3]   = (uint8_t) a0;
    buffer[4]   = (uint8_t)(b0 >> 24);
    buffer[5]   = (uint8_t)(b0 >> 16);
    buffer[6]   = (uint8_t)(b0 >> 8);
    buffer[7]   = (uint8_t) b0;
    buffer[8]   = (uint8_t)(c0 >> 24);
    buffer[9]   = (uint8_t)(c0 >> 16);
    buffer[10]  = (uint8_t)(c0 >> 8);
    buffer[11]  = (uint8_t) c0;
    buffer[12]  = (uint8_t)(d0 >> 24);
    buffer[13]  = (uint8_t)(d0 >> 16);
    buffer[14]  = (uint8_t)(d0 >> 8);
    buffer[15]  = (uint8_t) d0;
}

int
main(int argc, char ** argv) {
    uint8_t buffer[16];
    md5hash(buffer);
    for (size_t i = 0; i < 16; i++) {
        printf("%02x", buffer[i]);
    }
    return 0;
}
