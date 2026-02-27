#include "smc_hex.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define FUZZ_CASES 100000U
#define MAX_LEN 1024U

static uint64_t g_seed = 0x9e3779b97f4a7c15ULL;

static uint32_t rand_u32(void) {
  uint64_t x = g_seed;
  x ^= x << 13;
  x ^= x >> 7;
  x ^= x << 17;
  g_seed = x;
  return (uint32_t)(x & 0xffffffffU);
}

static void ref_hex_encode(const uint8_t *src, size_t src_len, char *dst) {
  static const char hex[] = "0123456789abcdef";
  size_t i;
  for (i = 0U; i < src_len; ++i) {
    uint8_t v = src[i];
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

int main(void) {
  uint8_t input[MAX_LEN];
  uint8_t decoded[MAX_LEN];
  uint8_t ref_decoded[MAX_LEN];
  char encoded[MAX_LEN * 2U];
  char ref_encoded[MAX_LEN * 2U];
  unsigned int case_id;

  for (case_id = 0U; case_id < FUZZ_CASES; ++case_id) {
    size_t len = (size_t)(rand_u32() % (MAX_LEN + 1U));
    size_t i;
    size_t written_enc = 0U;
    size_t written_dec = 0U;
    smc_status status;

    for (i = 0U; i < len; ++i) {
      input[i] = (uint8_t)(rand_u32() & 0xffU);
    }

    status = smc_hex_encode(input, len, encoded, sizeof(encoded), &written_enc);
    if (status != SMC_OK) {
      fprintf(stderr, "encode failed at case %u\n", case_id);
      return 1;
    }
    if (written_enc != (len * 2U)) {
      fprintf(stderr, "encode length mismatch at case %u\n", case_id);
      return 1;
    }

    ref_hex_encode(input, len, ref_encoded);
    if (memcmp(encoded, ref_encoded, written_enc) != 0) {
      fprintf(stderr, "encode output mismatch at case %u\n", case_id);
      return 1;
    }

    status = smc_hex_decode(encoded, written_enc, decoded, sizeof(decoded), &written_dec);
    if (status != SMC_OK) {
      fprintf(stderr, "decode failed at case %u\n", case_id);
      return 1;
    }
    if (written_dec != len) {
      fprintf(stderr, "decode length mismatch at case %u\n", case_id);
      return 1;
    }

    if (ref_hex_decode(encoded, written_enc, ref_decoded) == 0) {
      fprintf(stderr, "reference decode failed at case %u\n", case_id);
      return 1;
    }
    if (memcmp(decoded, ref_decoded, len) != 0) {
      fprintf(stderr, "decode output mismatch at case %u\n", case_id);
      return 1;
    }

    if (written_enc >= 2U) {
      char bad[(MAX_LEN * 2U) + 1U];
      size_t bad_pos = (size_t)(rand_u32() % written_enc);
      size_t bad_written = 999U;
      memcpy(bad, encoded, written_enc);
      bad[bad_pos] = 'g';

      status = smc_hex_decode(bad, written_enc, decoded, sizeof(decoded), &bad_written);
      if (status != SMC_ERR_INVALID_CHAR) {
        fprintf(stderr, "invalid-char check failed at case %u\n", case_id);
        return 1;
      }
      if (bad_written != 0U) {
        fprintf(stderr, "written not reset on error at case %u\n", case_id);
        return 1;
      }
    }
  }

  puts("test_fuzz: OK");
  return 0;
}
