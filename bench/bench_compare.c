#include "smc_hex.h"

#include <openssl/crypto.h>

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

static void naive_hex_encode(const uint8_t *src, size_t src_len, char *dst) {
  static const char hex[] = "0123456789abcdef";
  size_t i;
  for (i = 0U; i < src_len; ++i) {
    const uint8_t v = src[i];
    dst[2U * i] = hex[(size_t)(v >> 4U)];
    dst[(2U * i) + 1U] = hex[(size_t)(v & 0x0FU)];
  }
}

static int naive_hex_nibble(unsigned char c) {
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

static int naive_hex_decode(const char *src, size_t src_len, uint8_t *dst) {
  size_t i;
  if ((src_len & 1U) != 0U) {
    return 0;
  }
  for (i = 0U; i < src_len; i += 2U) {
    int hi = naive_hex_nibble((unsigned char)src[i]);
    int lo = naive_hex_nibble((unsigned char)src[i + 1U]);
    if ((hi < 0) || (lo < 0)) {
      return 0;
    }
    dst[i / 2U] = (uint8_t)(((uint8_t)hi << 4U) | (uint8_t)lo);
  }
  return 1;
}

static int openssl_hex_encode(const uint8_t *src, size_t src_len, char *dst, size_t dst_len) {
  size_t written = 0U;
  if (OPENSSL_buf2hexstr_ex(dst, dst_len, &written, src, (long)src_len, '\0') != 1) {
    return 0;
  }
  return (written == ((src_len * 2U) + 1U)) ? 1 : 0;
}

static int openssl_hex_decode(const char *src, size_t src_len, uint8_t *dst, size_t dst_len) {
  size_t written = 0U;
  if (src_len > 0U) {
    if (src[src_len] != '\0') {
      return 0;
    }
  }
  if (OPENSSL_hexstr2buf_ex(dst, dst_len, &written, src, '\0') != 1) {
    return 0;
  }
  return (written == (src_len / 2U)) ? 1 : 0;
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

static void print_line(const char *label, size_t bytes, uint64_t ns) {
  printf("%-16s %.3f GB/s (%.3f ns/byte)\n", label, gbps(bytes, ns), (double)ns / (double)bytes);
}

int main(int argc, char **argv) {
  const size_t size_mb = (argc >= 2) ? (size_t)strtoull(argv[1], NULL, 10) : DEFAULT_SIZE_MB;
  const size_t input_size = size_mb * 1024U * 1024U;
  const size_t encoded_size = input_size * 2U;
  uint8_t *input = (uint8_t *)malloc(input_size);
  uint8_t *decoded = (uint8_t *)malloc(input_size);
  char *encoded = (char *)malloc(encoded_size + 1U);
  char *naive_encoded = (char *)malloc(encoded_size + 1U);
  char *openssl_encoded = (char *)malloc(encoded_size + 1U);
  uint64_t smc_enc[RUNS], smc_dec[RUNS];
  uint64_t naive_enc[RUNS], naive_dec[RUNS];
  uint64_t ossl_enc[RUNS], ossl_dec[RUNS];
  size_t run;

  if ((input == NULL) || (decoded == NULL) || (encoded == NULL) || (naive_encoded == NULL) ||
      (openssl_encoded == NULL)) {
    fprintf(stderr, "allocation failed\n");
    free(input);
    free(decoded);
    free(encoded);
    free(naive_encoded);
    free(openssl_encoded);
    return 1;
  }

  fill_input(input, input_size);

  for (run = 0U; run < WARMUP; ++run) {
    size_t written = 0U;
    if (smc_hex_encode(input, input_size, encoded, encoded_size, &written) != SMC_OK) {
      fprintf(stderr, "smc warmup encode failed\n");
      return 1;
    }
    encoded[encoded_size] = '\0';
    if (smc_hex_decode(encoded, encoded_size, decoded, input_size, &written) != SMC_OK) {
      fprintf(stderr, "smc warmup decode failed\n");
      return 1;
    }
  }

  for (run = 0U; run < RUNS; ++run) {
    uint64_t begin;
    uint64_t end;
    size_t written = 0U;

    begin = now_ns();
    if (smc_hex_encode(input, input_size, encoded, encoded_size, &written) != SMC_OK) {
      fprintf(stderr, "smc encode failed\n");
      return 1;
    }
    end = now_ns();
    smc_enc[run] = end - begin;
    encoded[encoded_size] = '\0';

    begin = now_ns();
    if (smc_hex_decode(encoded, encoded_size, decoded, input_size, &written) != SMC_OK) {
      fprintf(stderr, "smc decode failed\n");
      return 1;
    }
    end = now_ns();
    smc_dec[run] = end - begin;

    begin = now_ns();
    naive_hex_encode(input, input_size, naive_encoded);
    end = now_ns();
    naive_enc[run] = end - begin;
    naive_encoded[encoded_size] = '\0';

    begin = now_ns();
    if (naive_hex_decode(naive_encoded, encoded_size, decoded) == 0) {
      fprintf(stderr, "naive decode failed\n");
      return 1;
    }
    end = now_ns();
    naive_dec[run] = end - begin;

    begin = now_ns();
    if (openssl_hex_encode(input, input_size, openssl_encoded, encoded_size + 1U) == 0) {
      fprintf(stderr, "openssl encode failed\n");
      return 1;
    }
    end = now_ns();
    ossl_enc[run] = end - begin;

    openssl_encoded[encoded_size] = '\0';
    begin = now_ns();
    if (openssl_hex_decode(openssl_encoded, encoded_size, decoded, input_size) == 0) {
      fprintf(stderr, "openssl decode failed\n");
      return 1;
    }
    end = now_ns();
    ossl_dec[run] = end - begin;
  }

  {
    uint64_t smc_enc_m = median_ns(smc_enc, RUNS);
    uint64_t smc_dec_m = median_ns(smc_dec, RUNS);
    uint64_t naive_enc_m = median_ns(naive_enc, RUNS);
    uint64_t naive_dec_m = median_ns(naive_dec, RUNS);
    uint64_t ossl_enc_m = median_ns(ossl_enc, RUNS);
    uint64_t ossl_dec_m = median_ns(ossl_dec, RUNS);

    printf("Input: %zu MB\n", size_mb);
    puts("-- Encode --");
    print_line("smc", input_size, smc_enc_m);
    print_line("openssl", input_size, ossl_enc_m);
    print_line("naive", input_size, naive_enc_m);
    puts("-- Decode --");
    print_line("smc", input_size, smc_dec_m);
    print_line("openssl", input_size, ossl_dec_m);
    print_line("naive", input_size, naive_dec_m);

    printf("Encode speedup vs OpenSSL: %.2fx\n", (double)ossl_enc_m / (double)smc_enc_m);
    printf("Decode speedup vs OpenSSL: %.2fx\n", (double)ossl_dec_m / (double)smc_dec_m);
    printf("Encode speedup vs naive: %.2fx\n", (double)naive_enc_m / (double)smc_enc_m);
    printf("Decode speedup vs naive: %.2fx\n", (double)naive_dec_m / (double)smc_dec_m);
  }

  free(input);
  free(decoded);
  free(encoded);
  free(naive_encoded);
  free(openssl_encoded);
  return 0;
}
