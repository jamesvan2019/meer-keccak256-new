
#ifndef KECCAK_H__
#define KECCAK_H__

#ifdef __cplusplus
extern "C"{
#endif

void keccakhash(void* state, const void* input);
void pmeer_v2_keccakhash(void *state, const void *input);

#ifdef __cplusplus
}
#endif

#endif
