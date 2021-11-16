#pragma once

// mihoyo's MT19937-64 implementation
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "Common.h"

struct mt64 {
	uint64_t* mt;
	int mti;
	int initialized;
};

void mt64_init(mt64* mt64, uint64_t seed);
uint64_t mt64_update(mt64* a1);