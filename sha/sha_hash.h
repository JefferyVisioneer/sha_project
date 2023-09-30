#ifndef SHA_HASH_H_INCLUDED
#define SHA_HASH_H_INCLUDED

#include <cstdint>
#include <string>
#include <vector>

/*
All needed constants for the algorithm:
It's the 256-bit algorithm, thus the length of one block is 512 bit.
We have 64 bytes in block at maximum, but we can put only 55 in the last block at maximum.
If we put 56 byte, then we won't have a place to put the 8-byte message length, thus we'd need another one block.
*/

const uint32_t block_length {512};
const uint32_t min_bytes_in_block {55};
const uint32_t max_bytes_in_block {64};

/*
Hash class, that incapsulates all related to algorithm info in it.
The class has default constructor and reloaded func-call operator, which gets string to hash it. 
*/

class sha_hash{
public:
    sha_hash();

    std::string operator()(const std::string&);

private:

    std::vector<uint32_t> create_hash();

    uint32_t rightrotate(uint32_t, uint32_t);
    uint32_t rightshift(uint32_t, uint32_t);

    std::vector<uint8_t> read_from_string(const std::string& s);
    std::vector<std::vector<uint8_t>> divide_into_blocks(std::vector<uint8_t>&);
    std::vector<std::vector<uint32_t>> from_bytes_to_word(std::vector<std::vector<uint8_t>>&);
    std::vector<uint32_t> create_message_schedule(std::vector<uint32_t>&);
    void update_hash_values(std::vector<uint32_t>&, std::vector<uint32_t>&);

    std::vector<uint8_t> message;
};

#endif // SHA_HASH_H_INCLUDED
