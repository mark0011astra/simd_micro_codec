#include "smc_hex.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define EXPECT_TRUE(cond)                                                       \
  do {                                                                          \
    if (!(cond)) {                                                              \
      fprintf(stderr, "ASSERT FAILED: %s (%s:%d)\n", #cond, __FILE__, __LINE__); \
      return 1;                                                                 \
    }                                                                           \
  } while (0)

#define EXPECT_STATUS(actual, expected) EXPECT_TRUE((actual) == (expected))

static int ref_nibble(unsigned int c) {
  if ((c >= (unsigned int)'0') && (c <= (unsigned int)'9')) {
    return (int)(c - (unsigned int)'0');
  }
  if ((c >= (unsigned int)'a') && (c <= (unsigned int)'f')) {
    return (int)(c - (unsigned int)'a' + 10U);
  }
  if ((c >= (unsigned int)'A') && (c <= (unsigned int)'F')) {
    return (int)(c - (unsigned int)'A' + 10U);
  }
  return -1;
}

static int test_required_size(void) {
  EXPECT_TRUE(smc_hex_encode_required_size(0U) == 0U);
  EXPECT_TRUE(smc_hex_encode_required_size(1U) == 2U);
  EXPECT_TRUE(smc_hex_encode_required_size(16U) == 32U);
  EXPECT_TRUE(smc_hex_encode_required_size((size_t)-1) == 0U);
  return 0;
}

static int test_encode_basic(void) {
  const uint8_t src[] = {0x00U, 0x0fU, 0xa5U, 0xffU};
  char dst[8];
  size_t written = 123U;
  smc_status status = smc_hex_encode(src, sizeof(src), dst, sizeof(dst), &written);

  EXPECT_STATUS(status, SMC_OK);
  EXPECT_TRUE(written == sizeof(dst));
  EXPECT_TRUE(memcmp(dst, "000fa5ff", sizeof(dst)) == 0);
  return 0;
}

static int test_decode_basic(void) {
  const char src[] = "000Fa5fF";
  uint8_t dst[4];
  size_t written = 0U;
  smc_status status = smc_hex_decode(src, 8U, dst, sizeof(dst), &written);

  EXPECT_STATUS(status, SMC_OK);
  EXPECT_TRUE(written == sizeof(dst));
  EXPECT_TRUE(dst[0] == 0x00U);
  EXPECT_TRUE(dst[1] == 0x0fU);
  EXPECT_TRUE(dst[2] == 0xa5U);
  EXPECT_TRUE(dst[3] == 0xffU);
  return 0;
}

static int test_encode_errors(void) {
  const uint8_t src[] = {0x01U, 0x02U};
  char dst[3];
  size_t written = 99U;
  smc_status status = smc_hex_encode(src, sizeof(src), dst, sizeof(dst), &written);

  EXPECT_STATUS(status, SMC_ERR_DST_TOO_SMALL);
  EXPECT_TRUE(written == 0U);

  status = smc_hex_encode(src, sizeof(src), dst, sizeof(dst), NULL);
  EXPECT_STATUS(status, SMC_ERR_NULL_POINTER);

  return 0;
}

static int test_decode_errors(void) {
  uint8_t dst[8];
  size_t written = 777U;
  smc_status status = smc_hex_decode("abc", 3U, dst, sizeof(dst), &written);

  EXPECT_STATUS(status, SMC_ERR_INVALID_LENGTH);
  EXPECT_TRUE(written == 0U);

  status = smc_hex_decode("zz", 2U, dst, sizeof(dst), &written);
  EXPECT_STATUS(status, SMC_ERR_INVALID_CHAR);
  EXPECT_TRUE(written == 0U);

  status = smc_hex_decode("aa", 2U, dst, 0U, &written);
  EXPECT_STATUS(status, SMC_ERR_DST_TOO_SMALL);
  EXPECT_TRUE(written == 0U);

  status = smc_hex_decode("aa", 2U, NULL, 1U, &written);
  EXPECT_STATUS(status, SMC_ERR_NULL_POINTER);

  status = smc_hex_decode("", 0U, NULL, 0U, &written);
  EXPECT_STATUS(status, SMC_OK);
  EXPECT_TRUE(written == 0U);

  return 0;
}

static int test_overlap_detection(void) {
  uint8_t bytes[16];
  char chars[16] = "0011223344556677";
  size_t written = 0U;
  smc_status status;

  memset(bytes, 0, sizeof(bytes));
  status = smc_hex_encode(bytes, 4U, (char *)(void *)(bytes + 1U), 8U, &written);
  EXPECT_STATUS(status, SMC_ERR_OVERLAP);
  EXPECT_TRUE(written == 0U);

  status = smc_hex_decode(chars, 8U, (uint8_t *)(void *)(chars + 1U), 4U, &written);
  EXPECT_STATUS(status, SMC_ERR_OVERLAP);
  EXPECT_TRUE(written == 0U);

  return 0;
}

static int test_round_trip(void) {
  uint8_t src[257];
  char encoded[514];
  uint8_t decoded[257];
  size_t len;

  for (len = 0U; len < sizeof(src); ++len) {
    size_t i;
    size_t written_encode = 0U;
    size_t written_decode = 0U;
    smc_status status;

    for (i = 0U; i < len; ++i) {
      src[i] = (uint8_t)((i * 131U) & 0xFFU);
    }

    status = smc_hex_encode(src, len, encoded, sizeof(encoded), &written_encode);
    EXPECT_STATUS(status, SMC_OK);
    EXPECT_TRUE(written_encode == (len * 2U));

    status = smc_hex_decode(encoded, written_encode, decoded, sizeof(decoded), &written_decode);
    EXPECT_STATUS(status, SMC_OK);
    EXPECT_TRUE(written_decode == len);
    EXPECT_TRUE(memcmp(src, decoded, len) == 0);
  }

  return 0;
}

static int test_decode_exhaustive_pairs(void) {
  unsigned int c0;
  unsigned int c1;

  for (c0 = 0U; c0 <= 255U; ++c0) {
    for (c1 = 0U; c1 <= 255U; ++c1) {
      const char in[2] = {(char)(unsigned char)c0, (char)(unsigned char)c1};
      uint8_t out = 0U;
      size_t written = 99U;
      smc_status status = smc_hex_decode(in, 2U, &out, 1U, &written);
      int hi = ref_nibble(c0);
      int lo = ref_nibble(c1);

      if ((hi < 0) || (lo < 0)) {
        EXPECT_STATUS(status, SMC_ERR_INVALID_CHAR);
        EXPECT_TRUE(written == 0U);
      } else {
        uint8_t expected = (uint8_t)(((uint8_t)hi << 4U) | (uint8_t)lo);
        EXPECT_STATUS(status, SMC_OK);
        EXPECT_TRUE(written == 1U);
        EXPECT_TRUE(out == expected);
      }
    }
  }

  return 0;
}

int main(void) {
  if (test_required_size() != 0) {
    return 1;
  }
  if (test_encode_basic() != 0) {
    return 1;
  }
  if (test_decode_basic() != 0) {
    return 1;
  }
  if (test_encode_errors() != 0) {
    return 1;
  }
  if (test_decode_errors() != 0) {
    return 1;
  }
  if (test_overlap_detection() != 0) {
    return 1;
  }
  if (test_round_trip() != 0) {
    return 1;
  }
  if (test_decode_exhaustive_pairs() != 0) {
    return 1;
  }

  puts("test_smc_hex: OK");
  return 0;
}
