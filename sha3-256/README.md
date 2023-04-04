# SHA3-256 in C

This project is comprised of the singular program `sha3-test`, which is capable
of performing the sponge-based, SHA-3 256 secure hash algorithm on arbitrary
amounts of input data.

### Building

To build the program:

	$ make

Or:

	$ make all

### Usage

Note that the length of the input to hash must be specified using a `getopt()`
command-line option as demonstrated below:

	$ ./sha3-test -w <word to hash> 

### Additional Program Options

The following `getopt()` command-line options below are available as well:
  - `-h`: Display program help and usage
