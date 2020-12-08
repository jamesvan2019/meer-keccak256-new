
#include <string.h>
#include <stdint.h>

#include "sph_keccak.h"

 void keccakhash(void *state, const void *input)
{
    sph_keccak256_context ctx_keccak;
    uint32_t hash[32];

    sph_keccak256_init(&ctx_keccak);
    sph_keccak256 (&ctx_keccak,input, 113);//80
    sph_keccak256_close(&ctx_keccak, hash);

	memcpy(state, hash, 32);
}


 void pmeer_v2_keccakhash(void *state, const void *input)
{
    sph_keccak256_context ctx_keccak;
    uint32_t hash1[8];
    uint32_t hash2[8];

    sph_keccak256_init(&ctx_keccak);
    sph_keccak256 (&ctx_keccak,input, 117);//117
    sph_keccak256_close(&ctx_keccak, hash1);

    sph_keccak256_init(&ctx_keccak);
    sph_keccak256 (&ctx_keccak,hash1, 32);//32
    sph_keccak256_close(&ctx_keccak, hash2);

    sph_keccak256_init(&ctx_keccak);
    sph_keccak256 (&ctx_keccak,hash2, 32);//32
    sph_keccak256_close(&ctx_keccak, hash1);	

    memcpy(state, hash1, 32);
}
