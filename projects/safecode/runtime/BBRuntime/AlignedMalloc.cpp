#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "safecode/Runtime/BBMetaData.h"

/* On a dlmalloc/ptmalloc malloc implementation, memalign is performed by allocating
 * a block of size (alignment+size), and then finding the correctly aligned location
 * within that block, and try to give back the memory before the correctly aligned
 * location. This means that a memalign-based baggy bounds allocator can use up to
 * roughly 2x the amount the memory you'd expect.
 */

int next_pow_of_2(size_t size) {
  unsigned int i ;
  for (i = 1; i < size; i = i << 1) ;
  return (i < 16 ? 16 : i);
}

extern "C" void* __sc_bb_malloc(size_t size) {
  size_t adjusted_size = size + sizeof(BBMetaData);
  size_t aligned_size = next_pow_of_2(adjusted_size);
  void *vp;
  posix_memalign(&vp, aligned_size, aligned_size);

  BBMetaData *data = (BBMetaData*)((uintptr_t)vp + aligned_size - sizeof(BBMetaData));
  data->size = size;
  data->pool = NULL;
  return vp;
}

extern "C" void* __sc_bb_calloc(size_t nmemb, size_t size) {
  size_t adjusted_size = nmemb*size+sizeof(BBMetaData);
  size_t aligned_size = next_pow_of_2(adjusted_size);
  void *vp;
  posix_memalign(&vp, aligned_size, aligned_size);
  memset(vp, 0, aligned_size);
  BBMetaData *data = (BBMetaData*)((uintptr_t)vp + aligned_size - sizeof(BBMetaData));
  data->size = nmemb*size;
  data->pool = NULL;
  return vp;
}

extern "C" void* __sc_bb_realloc(void *ptr, size_t size) {
  if (ptr == NULL) {
    return __sc_bb_malloc(size);
  }

  size_t adjusted_size = size + sizeof(BBMetaData);
  size_t aligned_size = next_pow_of_2(adjusted_size);
  void *vp;
  posix_memalign(&vp, aligned_size, aligned_size);
  memcpy(vp, ptr, size);
  free(ptr);
  BBMetaData *data = (BBMetaData*)((uintptr_t)vp + aligned_size - sizeof(BBMetaData));
  data->size = size;
  data->pool = NULL;
  return vp;
}

extern "C" char* __sc_bb_getenv(const char *ptr) {
  char * env = getenv(ptr);
  if (NULL == env) {
    return NULL;
  }
  size_t env_str_size = strlen(env) + 1;
  size_t adjusted_size = env_str_size + sizeof(BBMetaData);
  size_t aligned_size = next_pow_of_2(adjusted_size);
  void *vp;
  posix_memalign(&vp, aligned_size, aligned_size);
  memcpy(vp, env, env_str_size);
  BBMetaData *data = (BBMetaData*)((uintptr_t)vp + aligned_size - sizeof(BBMetaData));
  data->size = env_str_size;
  data->pool = NULL;
  return (char *)vp;
}

extern "C" char* __sc_bb_strdup(const char *ptr) {
  if (NULL == ptr)
    return NULL;
  size_t str_size = strlen(ptr) + 1;
  size_t adjusted_size = str_size + sizeof(BBMetaData);
  size_t aligned_size = next_pow_of_2(adjusted_size);
  void *vp;
  posix_memalign(&vp, aligned_size, aligned_size);
  memcpy(vp, ptr, str_size);
  BBMetaData *data = (BBMetaData*)((uintptr_t)vp + aligned_size - sizeof(BBMetaData));
  data->size = str_size;
  data->pool = NULL;
  return (char *)vp;
}
