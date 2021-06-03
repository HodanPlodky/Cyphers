#include <stdio.h>
#include <string.h>

typedef unsigned char   uint8_t;
typedef unsigned int    uint32_t;

void
genPerm(uint8_t * key, size_t keylen, uint8_t * perm) {
    for (uint32_t i = 0; i < 256; i++)
        perm[i] = i;
    
    uint8_t j = 0;
    for (size_t i = 0; i < 256; i++) {
        j = j + perm[i] + key[i % keylen];
        // swap perm[i] and perm[j]
        uint8_t tmp = perm[i];
        perm[i] = perm[j];
        perm[j] = tmp;
    }
}

uint8_t
getNextPass(uint8_t * perm, uint8_t * i, uint8_t * j) {
    *i += 1;
    *j += perm[*i];
    // swap perm[i] and perm[j]
    uint8_t tmp = perm[*i];
    perm[*i] = perm[*j];
    perm[*j] = tmp;
    return perm[(perm[*i] + perm[*j]) % 256];
}

void
cypherstream(uint8_t * key, size_t keylen) {
    uint8_t perm[256];
    genPerm(key, keylen, perm);
    uint8_t i, j;
    i = j = 0;
    FILE * inputstream = freopen(NULL, "rb", stdin);
    while(1) {
        uint8_t xorbyte = getNextPass(perm, &i, &j);
        uint8_t input;
        if (fread(&input, sizeof(input), 1, inputstream) == 0)
            break;
        printf("%c", input ^ xorbyte);
    }
    fclose(inputstream);
}

int
main(int argc, char ** argv) {
    if (argc != 2) {
        fprintf(stderr, "must contain password as argument\n");
        return 1;
    }
    size_t keylen = strlen(argv[1]);

    cypherstream(argv[1], keylen);
    return 0;
}
