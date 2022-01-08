#include "PacketCrypt.h"
#include <cassert>

mt64 PacketCrypt::mt;
bool PacketCrypt::inited = false;

uint64_t PacketCrypt::Init(uint64_t seed) {
	mt64_init(&mt, seed);
	
    uint64_t ret = 0;
	for (int i = 0; i < 7; i++)
		ret = mt64_update(&mt);

    inited = true;

    return ret;
}

std::vector<uint8_t> PacketCrypt::Decrypt(void* data, size_t size) {
    return Crypt((char*)data + 8, size - 8, *(uint64_t*)data);
}

std::vector<uint8_t> PacketCrypt::Encrypt(void* data, size_t size) {
    uint64_t key = 0xDEADBEEFDEADBEEF; // TODO: should be random
    auto temp = std::vector<uint8_t>(size + 8);
    *(uint64_t*)temp.data() = key;
    auto ret = Crypt(data, size, key);
    memcpy(temp.data() + 8, ret.data(), size);
    return temp;
}

std::vector<uint8_t> PacketCrypt::Crypt(void* data, size_t size, uint64_t key) {
    assert(inited);
    mt.mti = 0;
    auto remainder = size % 8;
    auto ret = std::vector<uint8_t>(size);
    size_t idx = 0;
    auto* data_uint64 = (uint64_t*)data;
    size_t handled = 0;
    for (size_t i = 0; i < size / 8; i++) {
        uint64_t offset_key = key + i * 16;
        ((uint64_t*)ret.data())[i] = offset_key ^ mt64_update(&mt) ^ data_uint64[i];
        mt.mti %= 312;
        handled += 8;
    }
    // the remainder is just copied as-is to the end
    if (remainder > 0)
        memcpy(&ret[handled], &((char*)data)[handled], remainder);
    return ret;
}