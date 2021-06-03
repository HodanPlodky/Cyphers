#include <stdio.h>
#include <string.h>

// helper types because i cannot be bothered
typedef unsigned char uint8_t;
typedef unsigned int uint32_t;
typedef unsigned long uint64_t;

typedef struct TSRegisters {
    uint32_t r1; // 19 bit (takt 8)
    uint32_t r2; // 22 bit (takt 10)
    uint32_t r3; // 23 bit (takt 10)
} Registers;


// https://stackoverflow.com/questions/15185324/how-to-get-amount-of-1s-from-64-bit-number
uint32_t
setbitCount(uint32_t val) {
    uint32_t c; // store the total here
    static const int S[] = {1, 2, 4, 8, 16}; // Magic Binary Numbers
    static const int B[] = {0x55555555, 0x33333333, 0x0F0F0F0F, 0x00FF00FF, 0x0000FFFF};

    c = val - ((val >> 1) & B[0]);
    c = ((c >> S[1]) & B[1]) + (c & B[1]);
    c = ((c >> S[2]) + c) & B[2];
    c = ((c >> S[3]) + c) & B[3];
    c = ((c >> S[4]) + c) & B[4];
    return c;
}

void
rotate(uint32_t * reg, uint32_t feedbackMask) {
    uint32_t feedbits = *reg & feedbackMask;
    uint32_t setcount = setbitCount(feedbits);
    uint32_t feedback = setcount % 2 == 0 ? 0 : 1;
    *reg <<= 1;
    *reg ^= feedback;
}

void
rotateR1(Registers * reg) {
    const uint32_t feedback = (1 << 18) + (1 << 17) + (1 << 16) + (1 << 13);
    rotate(&reg->r1, feedback);
}

void
rotateR2(Registers * reg) {
    const uint32_t feedback = (1 << 21) + (1 << 20);
    rotate(&reg->r2, feedback);
}

void
rotateR3(Registers * reg) {
    const uint32_t feedback = (1 << 22) + (1 << 21) + (1 << 20) + (1 << 7);
    rotate(&reg->r3, feedback);
}

void
rotateAll(Registers * reg) {
    rotateR1(reg);
    rotateR2(reg);
    rotateR3(reg);
}

void
majorityruleClock(Registers * reg) {
    uint32_t setcount = 0;
    // R1 tack bit = 8
    if (reg->r1 & (1<<8))
        setcount++;
    // R2 tack bit = 10
    if (reg->r2 & (1<<10))
        setcount++;
    // R3 tack bit = 10
    if (reg->r3 & (1<<10))
        setcount++;
    if (setcount > 1) {
        if (reg->r1 & (1<<8)) rotateR1(reg);
        if (reg->r2 & (1<<10)) rotateR2(reg);
        if (reg->r3 & (1<<10)) rotateR3(reg);
    }
    else {
        if (!(reg->r1 & (1<<8))) rotateR1(reg);
        if (!(reg->r2 & (1<<10))) rotateR2(reg);
        if (!(reg->r3 & (1<<10))) rotateR3(reg);
    }
}

void
init(Registers * reg, uint64_t key, uint32_t iv) {
    // null all regs
    reg->r1 = 0;
    reg->r2 = 0;
    reg->r3 = 0;
    // insert key
    for (uint32_t i = 0; i < 64; i++) {
        uint64_t index = 1 << i;
        uint32_t keyval = key & index ? 1 : 0;
        reg->r1 ^= keyval;
        reg->r2 ^= keyval;
        reg->r3 ^= keyval;
        rotateAll(reg);
    }
    //insert vector
    for (uint32_t i = 0; i < 22; i++) {
        uint32_t index = 1 << i;
        uint32_t ivval = iv & index ? 1 : 0;
        reg->r1 ^= ivval;
        reg->r2 ^= ivval;
        reg->r3 ^= ivval;
        rotateAll(reg);
    }
    // hundred rotations
    for (uint32_t i = 0; i < 100; i++) {
        majorityruleClock(reg);
    }
}

uint32_t
getaccKeybit(Registers * reg) {
    uint32_t r1 = (reg->r1 & (1 << 18)) >> 18;
    uint32_t r2 = (reg->r2 & (1 << 21)) >> 21;
    uint32_t r3 = (reg->r3 & (1 << 22)) >> 22;
    return r1 ^ r2 ^ r3;
}

uint8_t
getNextPass(Registers * reg) {
    uint8_t result = 0;
    for (uint32_t i = 0; i < 8; i++) {
        result ^= getaccKeybit(reg) << i;
        majorityruleClock(reg);
    }
    return result; 
}

void
cryptstream(uint64_t key, uint32_t iv) {
    Registers regs;
    init(&regs, key, iv);
    FILE * inputstream = freopen(NULL, "rb", stdin);
    while (1) {
        uint8_t xorbyte = getNextPass(&regs);
        uint8_t input;
        if (fread(&input, sizeof(input), 1, inputstream) == 0)
            break;
        printf("%c", input ^ xorbyte);
    }
    fclose(inputstream);
}

uint64_t
generateKey(char * argv) {
    uint64_t result = 0;
    for(uint32_t i = 0; i < 8; i++) {
        result <<= 8;
        result ^= argv[i];
    }
    return result;
}

uint32_t 
generateIv(char * argv) {
    uint32_t result = 0;
    for (uint32_t i = 0; i < 4; i++) {
        result <<= 8;
        result ^= argv[i];
    }
    return result;
}

int
main(int argc, char ** argv) {
    if (argc != 2) {
        fprintf(stderr, "most contain password(64bit) and vector(22bit)\n");
        fprintf(stderr, "it is inputed as string of length 12\n");
        return 1;
    }
    if (strlen(argv[1]) != 12) {
        fprintf(stderr, "password must be 12 characters long\n");
        return 1;
    }
    uint64_t key = generateKey(argv[1]);
    uint32_t iv = generateIv(argv[1]);
    cryptstream(key, iv);
    return 0;
}
