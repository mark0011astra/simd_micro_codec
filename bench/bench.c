#include "smc_hex.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define DEFAULT_SIZE_MB 64U
#define RUNS 10U
#define WARMUP 3U

static uint64_t now_ns(void) {
  struct timespec ts;
  if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
    return 0U;
  }
  return ((uint64_t)ts.tv_sec * 1000000000ULL) + (uint64_t)ts.tv_nsec;
}

static int cmp_u64(const void *lhs, const void *rhs) {
  const uint64_t a = *(const uint64_t *)lhs;
  const uint64_t b = *(const uint64_t *)rhs;
  if (a < b) {
    return -1;
  }
  if (a > b) {
    return 1;
  }
  return 0;
}

static uint64_t median_ns(uint64_t *samples, size_t count) {
  qsort(samples, count, sizeof(samples[0]), cmp_u64);
  return samples[count / 2U];
}

static void ref_hex_encode(const uint8_t *src, size_t src_len, char *dst) {
  static const char hex[] = "0123456789abcdef";
  size_t i;
  for (i = 0U; i < src_len; ++i) {
    const uint8_t v = src[i];
    dst[2U * i] = hex[(size_t)(v >> 4U)];
    dst[(2U * i) + 1U] = hex[(size_t)(v & 0x0FU)];
  }
}

static int ref_hex_nibble(unsigned char c) {
  if ((c >= (unsigned char)'0') && (c <= (unsigned char)'9')) {
    return (int)(c - (unsigned char)'0');
  }
  if ((c >= (unsigned char)'a') && (c <= (unsigned char)'f')) {
    return (int)(c - (unsigned char)'a' + 10U);
  }
  if ((c >= (unsigned char)'A') && (c <= (unsigned char)'F')) {
    return (int)(c - (unsigned char)'A' + 10U);
  }
  return -1;
}

static int ref_hex_decode(const char *src, size_t src_len, uint8_t *dst) {
  size_t i;
  if ((src_len & 1U) != 0U) {
    return 0;
  }
  for (i = 0U; i < src_len; i += 2U) {
    int hi = ref_hex_nibble((unsigned char)src[i]);
    int lo = ref_hex_nibble((unsigned char)src[i + 1U]);
    if ((hi < 0) || (lo < 0)) {
      return 0;
    }
    dst[i / 2U] = (uint8_t)(((uint8_t)hi << 4U) | (uint8_t)lo);
  }
  return 1;
}

static double gbps(size_t bytes, uint64_t ns) {
  if (ns == 0U) {
    return 0.0;
  }
  return ((double)bytes / (double)ns);
}

static void fill_input(uint8_t *buf, size_t len) {
  size_t i;
  uint32_t x = 0x12345678U;
  for (i = 0U; i < len; ++i) {
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    buf[i] = (uint8_t)(x & 0xFFU);
  }
}

int main(int argc, char **argv) {
  const size_t size_mb = (argc >= 2) ? (size_t)strtoull(argv[1], NULL, 10) : DEFAULT_SIZE_MB;
  const size_t input_size = size_mb * 1024U * 1024U;
  const size_t encoded_size = input_size * 2U;
  uint8_t *input = NULL;
  char *encoded = NULL;
  char *ref_encoded = NULL;
  uint8_t *decoded = NULL;
  uint8_t *ref_decoded = NULL;
  uint64_t enc_lib_samples[RUNS];
  uint64_t enc_ref_samples[RUNS];
  uint64_t dec_lib_samples[RUNS];
  uint64_t dec_ref_samples[RUNS];
  size_t run;
  int rc = 1;

  input = (uint8_t *)malloc(input_size);
  encoded = (char *)malloc(encoded_size);
  ref_encoded = (char *)malloc(encoded_size);
  decoded = (uint8_t *)malloc(input_size);
  ref_decoded = (uint8_t *)malloc(input_size);

  if ((input == NULL) || (encoded == NULL) || (ref_encoded == NULL) || (decoded == NULL) ||
      (ref_decoded == NULL)) {
    fprintf(stderr, "allocation failed\n");
    goto cleanup;
  }

  fill_input(input, input_size);
  ref_hex_encode(input, input_size, ref_encoded);

  for (run = 0U; run < WARMUP; ++run) {
    size_t written = 0U;
    if (smc_hex_encode(input, input_size, encoded, encoded_size, &written) != SMC_OK) {
      fprintf(stderr, "warmup encode failed\n");
      goto cleanup;
    }
    if (smc_hex_decode(ref_encoded, encoded_size, decoded, input_size, &written) != SMC_OK) {
      fprintf(stderr, "warmup decode failed\n");
      goto cleanup;
    }
  }

  for (run = 0U; run < RUNS; ++run) {
    uint64_t begin;
    uint64_t end;
    size_t written = 0U;

    begin = now_ns();
    if (smc_hex_encode(input, input_size, encoded, encoded_size, &written) != SMC_OK) {
      fprintf(stderr, "encode failed\n");
      goto cleanup;
    }
    end = now_ns();
    enc_lib_samples[run] = end - begin;

    begin = now_ns();
    ref_hex_encode(input, input_size, ref_encoded);
    end = now_ns();
    enc_ref_samples[run] = end - begin;

    begin = now_ns();
    if (smc_hex_decode(ref_encoded, encoded_size, decoded, input_size, &written) != SMC_OK) {
      fprintf(stderr, "decode failed\n");
      goto cleanup;
    }
    end = now_ns();
    dec_lib_samples[run] = end - begin;

    begin = now_ns();
    if (ref_hex_decode(ref_encoded, encoded_size, ref_decoded) == 0) {
      fprintf(stderr, "reference decode failed\n");
      goto cleanup;
    }
    end = now_ns();
    dec_ref_samples[run] = end - begin;
  }

  {
    uint64_t enc_lib = median_ns(enc_lib_samples, RUNS);
    uint64_t enc_ref = median_ns(enc_ref_samples, RUNS);
    uint64_t dec_lib = median_ns(dec_lib_samples, RUNS);
    uint64_t dec_ref = median_ns(dec_ref_samples, RUNS);

    printf("Input: %zu MB\n", size_mb);
    printf("Encode lib : %.3f GB/s (%.3f ns/byte)\n", gbps(input_size, enc_lib),
           (double)enc_lib / (double)input_size);
    printf("Encode ref : %.3f GB/s (%.3f ns/byte)\n", gbps(input_size, enc_ref),
           (double)enc_ref / (double)input_size);
    printf("Encode speedup: %.2fx\n", (double)enc_ref / (double)enc_lib);

    printf("Decode lib : %.3f GB/s (%.3f ns/byte)\n", gbps(input_size, dec_lib),
           (double)dec_lib / (double)input_size);
    printf("Decode ref : %.3f GB/s (%.3f ns/byte)\n", gbps(input_size, dec_ref),
           (double)dec_ref / (double)input_size);
    printf("Decode speedup: %.2fx\n", (double)dec_ref / (double)dec_lib);
  }

  rc = 0;

cleanup:
  free(input);
  free(encoded);
  free(ref_encoded);
  free(decoded);
  free(ref_decoded);
  return rc;
}
