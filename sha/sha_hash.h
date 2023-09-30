#ifndef SHA_HASH_H_INCLUDED
#define SHA_HASH_H_INCLUDED

#include <cstdint>
#include <string>
#include <vector>

/*
Необходимые константы для работы:
Т.к. алгоритм 256-битовый, то длина одного блока данных 512 бит.
Максимально байтов в блоке 64 штуки, а максимально минимально вместить можно 55 байтов.
Если вместить 56 байт, то не хватит места для 8 байтов с длиной сообщения, поэтому
для sha256 потребуется второй блок информации.
*/

const uint32_t block_length {512};
const uint32_t min_bytes_in_block {55};
const uint32_t max_bytes_in_block {64};

/*
Класс хэша, который инкапсулирует информацию об алгоритме.
Имеет стандартный конструктор по умолчанию и оператор вызова функции, принимающий исходную строку в качестве аргумента.
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
