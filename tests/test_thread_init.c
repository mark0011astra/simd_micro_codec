#include "smc_hex.h"

#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define THREAD_COUNT 8U
#define ITERATIONS 20000U
#define DATA_LEN 64U

typedef struct thread_ctx {
  uint32_t seed;
  int failed;
} thread_ctx;

static uint32_t next_u32(uint32_t *state) {
  uint32_t x = *state;
  x ^= x << 13;
  x ^= x >> 17;
  x ^= x << 5;
  *state = x;
  return x;
}

static void *worker(void *arg) {
  thread_ctx *ctx = (thread_ctx *)arg;
  uint8_t src[DATA_LEN];
  uint8_t out[DATA_LEN];
  char hex[DATA_LEN * 2U];
  uint32_t state = ctx->seed;
  unsigned int iter;

  for (iter = 0U; iter < ITERATIONS; ++iter) {
    size_t i;
    size_t written_encode = 0U;
    size_t written_decode = 0U;

    for (i = 0U; i < DATA_LEN; ++i) {
      src[i] = (uint8_t)(next_u32(&state) & 0xFFU);
    }

    if (smc_hex_encode(src, DATA_LEN, hex, sizeof(hex), &written_encode) != SMC_OK) {
      ctx->failed = 1;
      return NULL;
    }

    if (written_encode != (DATA_LEN * 2U)) {
      ctx->failed = 1;
      return NULL;
    }

    if (smc_hex_decode(hex, written_encode, out, sizeof(out), &written_decode) != SMC_OK) {
      ctx->failed = 1;
      return NULL;
    }

    if (written_decode != DATA_LEN) {
      ctx->failed = 1;
      return NULL;
    }

    if (memcmp(src, out, DATA_LEN) != 0) {
      ctx->failed = 1;
      return NULL;
    }
  }

  return NULL;
}

int main(void) {
  pthread_t threads[THREAD_COUNT];
  thread_ctx ctx[THREAD_COUNT];
  unsigned int i;

  for (i = 0U; i < THREAD_COUNT; ++i) {
    ctx[i].seed = (uint32_t)(0x12345678U + (i * 7919U));
    ctx[i].failed = 0;
    if (pthread_create(&threads[i], NULL, worker, &ctx[i]) != 0) {
      fprintf(stderr, "pthread_create failed\n");
      return 1;
    }
  }

  for (i = 0U; i < THREAD_COUNT; ++i) {
    if (pthread_join(threads[i], NULL) != 0) {
      fprintf(stderr, "pthread_join failed\n");
      return 1;
    }
    if (ctx[i].failed != 0) {
      fprintf(stderr, "thread %u failed\n", i);
      return 1;
    }
  }

  puts("test_thread_init: OK");
  return 0;
}
