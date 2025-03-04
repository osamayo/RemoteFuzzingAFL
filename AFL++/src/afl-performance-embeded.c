#include <stdint.h>
#include "types.h"

#define XXH_INLINE_ALL
#include "xxhash.h"
#undef XXH_INLINE_ALL


/* we switch from afl's murmur implementation to xxh3 as it is 30% faster -
   and get 64 bit hashes instead of just 32 bit. Less collisions! :-) */

#ifdef _DEBUG
u32 hash32(u8 *key, u32 len, u32 seed) {

#else
inline u32 hash32(u8 *key, u32 len, u32 seed) {

#endif

  (void)seed;
  return (u32)XXH3_64bits(key, len);

}

#ifdef _DEBUG
u64 hash64(u8 *key, u32 len, u64 seed) {

#else
inline u64 hash64(u8 *key, u32 len, u64 seed) {

#endif

  (void)seed;
  return XXH3_64bits(key, len);

}

