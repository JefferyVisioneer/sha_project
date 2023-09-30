#include "sha_hash.h"
#include <iostream>
#include <vector>
#include <iterator>
#include <algorithm>
#include <unordered_map>

using namespace std;

sha_hash::sha_hash() = default;


uint32_t sha_hash::rightrotate(uint32_t what_to, uint32_t how_much)
{
/*
a cyclic shift to riht from what_to index to +how_much position.
*/
    return ((what_to >> how_much) | (what_to << (32 - how_much)));
}

uint32_t sha_hash::rightshift(uint32_t what_to, uint32_t how_much)
{
/*
an ordinary shift to right from what_to to how_much positions.
*/
    return what_to >> how_much;
}

vector<uint8_t> sha_hash::read_from_string(const string& s)
{
/*
This func gets string, changes it to vector<uint8_t> and returns it.
*/

    vector<uint8_t> v{};

    transform(begin(s), end(s), back_inserter(v), [](char c) { return static_cast<uint8_t>(c); });

    return v;
}

vector<vector<uint8_t>> sha_hash::divide_into_blocks(vector<uint8_t>& v)
{
/*
Thif func gets vector of all string bytes, divides this vector to blocks by 512 bits. After the main bits, it adds the bite (10000000)2;
and then zeros follow to the end except the last 8 bytes, in which the length of hash message is written.
*/
    vector<vector<uint8_t>> ans {};

    if (v.size() == 0){

        vector<uint8_t> temp {};
        temp.reserve(64);

        temp.push_back(128);

        for (size_t i {1}; i < 64; i++){
            temp.push_back(0);
        }

        ans.push_back(move(temp));

        return ans;
    }

    auto v_begin_it {v.cbegin()};

    size_t blocks_count {v.size() / max_bytes_in_block};

    if (v.size() - blocks_count * max_bytes_in_block > 55){
        ++blocks_count;
    }

    for (size_t i {0}; i < blocks_count; i++){

        vector<uint8_t> temp {};

        for (size_t j {0}; j < max_bytes_in_block && i * max_bytes_in_block + j < v.size(); j++){
            temp.push_back(move(v[i * max_bytes_in_block + j]));
        }

        if (temp.size() < 64){
            temp.push_back(128);

            while (temp.size() < 64){
                temp.push_back(0);
            }
        }

        ans.push_back(move(temp));
    }

    {
        vector<uint8_t> temp {};

        for (size_t j {0}; j < min_bytes_in_block && blocks_count * max_bytes_in_block + j < v.size(); j++){
            temp.push_back(move(v[blocks_count * max_bytes_in_block + j]));
        }

        if (temp.size() > 0)
            temp.push_back(128);

        while (temp.size() < 56){
            temp.push_back(0);
        }

        const uint64_t length {v.size() * 8};

        for (size_t j {0}; j < 8; j++){
            temp.push_back((length << j * 8) >> 56);
        }

        ans.push_back(move(temp));
    }

    return ans;
}

vector<vector<uint32_t>> sha_hash::from_bytes_to_word(vector<vector<uint8_t>>& v)
{
/*
This func transform bytes-vector to 32-bit-word-vector to work with it on sha-256 algorithm.
*/
    vector<vector<uint32_t>> ans(v.size());

    for (size_t i {0}; i < ans.size(); i++){
        ans[i].resize(max_bytes_in_block / 4);
    }

    for (size_t i {0}; i < ans.size(); i++){

        for (size_t j {0}; j < ans[i].size(); j++){

            uint32_t first {}, second {}, third {}, forth {};

            first  = v[i][j * 4] << 24;
            second = v[i][j * 4 + 1] << 16;
            third  = v[i][j * 4 + 2] << 8;
            forth  = v[i][j * 4 + 3];

            ans[i][j] = first | second | third | forth;
        }

    }

    return ans;
}

vector<uint32_t> sha_hash::create_message_schedule(vector<uint32_t>& v)
{
/*
This func forms an 64-length 32-bit-word-array. The array will be hashed by sha-256.
*/
    vector<uint32_t> message_schedule(64);

    for (size_t i {0}; i < v.size(); i++){
        message_schedule[i] = v[i];
    }

    for (size_t i {16}; i < message_schedule.size(); i++){

        uint32_t first {rightrotate(message_schedule[i - 15], 7) ^ rightrotate(message_schedule[i - 15], 18) ^ rightshift(message_schedule[i - 15], 3)};
        uint32_t second {rightrotate(message_schedule[i - 2], 17) ^ rightrotate(message_schedule[i - 2], 19) ^ rightshift(message_schedule[i - 2], 10)};

        message_schedule[i] = message_schedule[i - 16] + first + message_schedule[i - 7] + second;
    }

    return message_schedule;
}

void sha_hash::update_hash_values(vector<uint32_t>& v, vector<uint32_t>& hash_values)
{
/*
The main work is here. 8 hash-values get 64-round cycle of changes; afther that they update or return as the hash-result of sha-256, 
if the bytes-block (v) is the last one in a row.
*/
    uint32_t k[64] {0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
                    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
                    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
                    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
                    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
                    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
                    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
                    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2};

    uint32_t a {hash_values[0]}, b {hash_values[1]}, c {hash_values[2]}, d {hash_values[3]}, e {hash_values[4]}, f {hash_values[5]}, g {hash_values[6]}, h {hash_values[7]};

    uint32_t Temp1, Temp2, Sigma1, Choice, Sigma0, Majority;

    for (size_t i {0}; i < 64; i++){

        Sigma1 = rightrotate(e, 6) ^ rightrotate(e, 11) ^ rightrotate(e, 25);
        Sigma0 = rightrotate(a, 2) ^ rightrotate(a, 13) ^ rightrotate(a, 22);
        Choice = (e & f) ^ ((~e) & g);
        Majority = (a & b) ^ (a & c) ^ (b & c);

        Temp1 = h + Sigma1 + Choice + k[i] + v[i];
        Temp2 = Sigma0 + Majority;

        h = g;
        g = f;
        f = e;
        e = d + Temp1;
        d = c;
        c = b;
        b = a;
        a = Temp1 + Temp2;

    }

    hash_values[0] += a;
    hash_values[1] += b;
    hash_values[2] += c;
    hash_values[3] += d;
    hash_values[4] += e;
    hash_values[5] += f;
    hash_values[6] += g;
    hash_values[7] += h;
}


vector<uint32_t> sha_hash::create_hash()
{
/*
An interface function for customers to create a hash. Returns the resulted hash-values.
*/
    vector<uint32_t> hash_values {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

    auto v {divide_into_blocks(message)};

    auto v_32 {from_bytes_to_word(v)};


    for (auto &vec : v_32){

        auto schedule {create_message_schedule(vec)};

        update_hash_values(schedule, hash_values);

    }

    return hash_values;
}

static char bit_4_to_char(uint8_t symbol){
/*
This func gets 4 bits of (symbol) to this symbol in hexadecimal.
Функция преобразует 4 бита (symbol) в символ в шестнадцатеричном представлении.
*/

    static unordered_map<uint8_t, char> mp{
    { 0x0, '0' }, { 0x01, '1'}, {0x2, '2'}, {0x3, '3'},
    { 0x4, '4' }, { 0x5, '5'}, {0x6, '6'}, {0x7, '7'},
    { 0x8, '8'}, { 0x9, '9' }, {0xA, 'a'}, {0xB, 'b'},
    { 0xC, 'c'}, { 0xD, 'd' }, {0xE, 'e'}, {0xF, 'f'}
    };

    return mp[symbol];
}


static string uint32_t_to_string(const uint32_t& num)
{
/*
This func gets 32-bit num, divides it to a 8 pairs of 4-bit words and gets these pairs to bit_4_to_char func (see above).
Returns an hexadecimal format of num.
*/

    string ans {};

    uint8_t words[8] {};

    words[0] =  num >> 28;
    words[1] = (num << 4) >> 28;
    words[2] = (num << 8) >> 28;
    words[3] = (num << 12) >> 28;
    words[4] = (num << 16) >> 28;
    words[5] = (num << 20) >> 28;
    words[6] = (num << 24) >> 28;
    words[7] = (num << 28) >> 28;

    for (size_t i {0}; i < 8; i++){
        ans += bit_4_to_char(words[i]);
    }

    return ans;
}

string sha_hash::operator()(const string& s)
{
/*
Reloaded func-call operator of sha_hash class to provide an organic interface for customers to get a string straight from the func-call of this object.
*/
    message = read_from_string(s);

    auto hashes {create_hash()};
    vector<string> v {};

    transform(begin(hashes), end(hashes), back_inserter(v), [](const uint32_t& num) { return uint32_t_to_string(num); });

    string ans {};

    for (auto &s : v){
        ans += s;
    }

    return ans;
}

