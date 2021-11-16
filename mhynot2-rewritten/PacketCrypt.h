#pragma once

#include <stdint.h>
#include <vector>

#include "mt64.h"

// handles encryption/decryption of mhyprot2 communication
// sadly has to be static
class PacketCrypt {
public:
	static uint64_t Init(uint64_t seed);
	static std::vector<uint8_t> Decrypt(void* data, size_t size);
	static std::vector<uint8_t> Encrypt(void* data, size_t size);

private:
	static std::vector<uint8_t> Crypt(void* data, size_t size, uint64_t key);

	static mt64 mt;
	static bool inited;
}; 