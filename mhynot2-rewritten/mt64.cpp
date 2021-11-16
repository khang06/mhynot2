#include "mt64.h"

void mt64_init(mt64* mt64, uint64_t seed) {
    if (mt64)
    {
        *(uint64_t*)&mt64->mti = 0;
        mt64->mt = (uint64_t*)malloc(0x9C0);;
        if (mt64->mt == nullptr)
            Common::Panic("wtf, couldn't alloc mt64 data!");

        memset(mt64->mt, 0, 0x9C0);
        *mt64->mt = seed;
        mt64->initialized = 1;
        mt64->mti = 1;
        do
        {
            mt64->mt[mt64->mti] = mt64->mti
                + 0x5851F42D4C957F2D * (mt64->mt[mt64->mti - 1] ^ (mt64->mt[mt64->mti - 1] >> 62));
            ++mt64->mti;
        } while (mt64->mti < 312);
    }
}

uint64_t mt64_update(mt64* a1)
{
    int mti; // er8
    __int64 v2; // rbx
    __int64 v3; // r11
    unsigned __int64 v4; // rdx
    __int64 v5; // rdx

    static unsigned long long mag01[2] = { 0ULL, 0xB5026F5AA96619E9ULL };

    if (!a1 || !a1->initialized)
        return 0;
    mti = a1->mti;
    if (mti >= 312)
    {
        v2 = 0;
        v3 = 156;
        do
        {
            a1->mt[v2] = ((a1->mt[v2] ^ (unsigned __int64)((LODWORD(a1->mt[v2]) ^ LODWORD(a1->mt[v2 + 1])) & 0x7FFFFFFF)) >> 1) ^ a1->mt[v2 + 156] ^ mag01[a1->mt[v2 + 1] & 1];
            ++v2;
        } while (v2 < 156);
        do
        {
            a1->mt[v3] = ((a1->mt[v3] ^ (unsigned __int64)((LODWORD(a1->mt[v3]) ^ LODWORD(a1->mt[v3 + 1])) & 0x7FFFFFFF)) >> 1) ^ a1->mt[v3 - 156] ^ mag01[a1->mt[v3 + 1] & 1];
            ++v3;
        } while (v3 < 311);
        a1->mt[311] = ((a1->mt[311] ^ (unsigned __int64)((*(uint32_t*)a1->mt ^ *((uint32_t*)a1->mt + 622)) & 0x7FFFFFFF)) >> 1) ^ a1->mt[155] ^ mag01[*(uint8_t*)a1->mt & 1];
        a1->mti = 0;
        mti = 0;
    }
    v4 = a1->mt[mti];
    a1->mti = mti + 1;
    v5 = ((((v4 >> 29) & 0x555555555 ^ v4) & 0x38EB3FFFF6D3) << 17) ^ (v4 >> 29) & 0x555555555 ^ v4;
    return ((v5 & 0xFFFFFFFFFFFFBF77u) << 37) ^ v5 ^ ((((v5 & 0xFFFFFFFFFFFFBF77u) << 37) ^ v5) >> 43);
}