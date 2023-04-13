#include "sha3.h"
#include "util.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#define OPTIONS "hw"

void print_usage(char **argv) {
    fprintf(stderr,
        "SYNOPSIS\n"
        "   Hashes inputs using the SHA-3 256 algorithm.\n"
        "\n"
        "USAGE\n"
        "   %s [-h] -w word \n"
        "\n"
        "OPTIONS\n"
        "   -h          Display program help and usage\n"
        "   -w word     Input word\n",
        argv[0]);
}

void hash_file(char *msg, int64_t length) {
    uint8_t md[SHA3_256_MD_LEN] = { 0 };
    sha3_256_digest((uint8_t *)msg, length, md);
    hexprint(SHA3_256_MD_LEN, md);
}

int main(int argc, char **argv) {
    char *word;
    int64_t length = -1;

    verbose = true;

    if (strcmp(argv[1], "-h") == 0) {
        print_usage(argv);
        return 0;
    }
    if ((strcmp(argv[1], "-w") == 0) && (argc > 2)) {
        word = argv[2];
    }
    if ((strcmp(argv[1], "-h") != 0) && strcmp(argv[1],"-w") != 0) {
        print_usage(argv);
        return 0;
    }

    length = strlen(word);
    check(length >= 0, "Valid message length must be supplied.\n");

    hash_file(word, length);

    return 0;
}
