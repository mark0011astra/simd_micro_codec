#include "smc_hex.h"

#include <limits.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#if defined(__aarch64__) && defined(__ARM_NEON) && !defined(SMC_DISABLE_SIMD)
#include <arm_neon.h>
#endif

#if defined(__x86_64__) && (defined(__clang__) || defined(__GNUC__)) && !defined(SMC_DISABLE_SIMD)
#include <immintrin.h>
#endif

typedef smc_status (*smc_encode_impl_fn)(const uint8_t *src, size_t src_len, char *dst);
typedef smc_status (*smc_decode_impl_fn)(const char *src, size_t src_len, uint8_t *dst);

#if defined(__clang__) || defined(__GNUC__)
#define SMC_ALWAYS_INLINE __attribute__((always_inline)) inline
#else
#define SMC_ALWAYS_INLINE inline
#endif

static smc_status smc_hex_encode_scalar(const uint8_t *src, size_t src_len, char *dst);
static smc_status smc_hex_decode_scalar(const char *src, size_t src_len, uint8_t *dst);

#if defined(__aarch64__) && defined(__ARM_NEON) && !defined(SMC_DISABLE_SIMD)
static smc_status smc_hex_encode_neon(const uint8_t *src, size_t src_len, char *dst);
static smc_status smc_hex_decode_neon(const char *src, size_t src_len, uint8_t *dst);
#endif

#if defined(__x86_64__) && (defined(__clang__) || defined(__GNUC__)) && !defined(SMC_DISABLE_SIMD)
#define SMC_AVX2_TARGET __attribute__((target("avx2")))
static smc_status smc_hex_encode_avx2(const uint8_t *src, size_t src_len, char *dst);
static smc_status smc_hex_decode_avx2(const char *src, size_t src_len, uint8_t *dst);
#endif

static smc_encode_impl_fn g_encode_impl = smc_hex_encode_scalar;
static smc_decode_impl_fn g_decode_impl = smc_hex_decode_scalar;
static atomic_int g_dispatch_state = ATOMIC_VAR_INIT(0);

static int smc_ranges_overlap(const void *lhs,
                              size_t lhs_len,
                              const void *rhs,
                              size_t rhs_len) {
  uintptr_t lhs_start;
  uintptr_t rhs_start;
  uintptr_t lhs_end;
  uintptr_t rhs_end;

  if ((lhs_len == 0U) || (rhs_len == 0U)) {
    return 0;
  }
  if ((lhs == NULL) || (rhs == NULL)) {
    return 0;
  }

  lhs_start = (uintptr_t)lhs;
  rhs_start = (uintptr_t)rhs;

  if ((lhs_start > (UINTPTR_MAX - lhs_len)) || (rhs_start > (UINTPTR_MAX - rhs_len))) {
    return 1;
  }

  lhs_end = lhs_start + lhs_len;
  rhs_end = rhs_start + rhs_len;

  return ((lhs_start < rhs_end) && (rhs_start < lhs_end)) ? 1 : 0;
}

#if !defined(SMC_DISABLE_SIMD)
static int smc_force_scalar_enabled(void) {
  const char *value = getenv("SMC_FORCE_SCALAR");
  if (value == NULL) {
    return 0;
  }
  return ((value[0] == '1') && (value[1] == '\0')) ? 1 : 0;
}
#endif

static void smc_init_dispatch_impl(void) {
#if !defined(SMC_DISABLE_SIMD)
  if (smc_force_scalar_enabled() != 0) {
    return;
  }

#if defined(__aarch64__) && defined(__ARM_NEON)
  g_encode_impl = smc_hex_encode_neon;
  g_decode_impl = smc_hex_decode_neon;
#elif defined(__x86_64__) && (defined(__clang__) || defined(__GNUC__))
  __builtin_cpu_init();
  if (__builtin_cpu_supports("avx2") != 0) {
    g_encode_impl = smc_hex_encode_avx2;
    g_decode_impl = smc_hex_decode_avx2;
  }
#endif
#endif
}

static void smc_ensure_dispatch_initialized(void) {
  int state = atomic_load_explicit(&g_dispatch_state, memory_order_acquire);
  int expected = 0;

  if (state == 2) {
    return;
  }

  if (atomic_compare_exchange_strong_explicit(&g_dispatch_state,
                                              &expected,
                                              1,
                                              memory_order_acq_rel,
                                              memory_order_acquire)) {
    smc_init_dispatch_impl();
    atomic_store_explicit(&g_dispatch_state, 2, memory_order_release);
    return;
  }

  while (atomic_load_explicit(&g_dispatch_state, memory_order_acquire) != 2) {
  }
}

size_t smc_hex_encode_required_size(size_t src_len) {
  if (src_len > (SIZE_MAX / 2U)) {
    return 0U;
  }
  return src_len * 2U;
}

static smc_status smc_validate_encode_args(const uint8_t *src,
                                           size_t src_len,
                                           char *dst,
                                           size_t dst_len,
                                           size_t *written,
                                           size_t *required_out) {
  size_t required;

  if ((written == NULL) || (required_out == NULL)) {
    return SMC_ERR_NULL_POINTER;
  }
  *written = 0U;

  required = smc_hex_encode_required_size(src_len);
  if ((required == 0U) && (src_len != 0U)) {
    return SMC_ERR_INVALID_LENGTH;
  }

  if (required > dst_len) {
    return SMC_ERR_DST_TOO_SMALL;
  }

  if ((src_len != 0U) && ((src == NULL) || (dst == NULL))) {
    return SMC_ERR_NULL_POINTER;
  }

  if (smc_ranges_overlap(src, src_len, dst, required) != 0) {
    return SMC_ERR_OVERLAP;
  }

  *required_out = required;
  return SMC_OK;
}

static smc_status smc_validate_decode_args(const char *src,
                                           size_t src_len,
                                           uint8_t *dst,
                                           size_t dst_len,
                                           size_t *written,
                                           size_t *required_out) {
  size_t required;

  if ((written == NULL) || (required_out == NULL)) {
    return SMC_ERR_NULL_POINTER;
  }
  *written = 0U;

  if ((src_len & 1U) != 0U) {
    return SMC_ERR_INVALID_LENGTH;
  }

  required = src_len / 2U;
  if (required > dst_len) {
    return SMC_ERR_DST_TOO_SMALL;
  }

  if ((src_len != 0U) && ((src == NULL) || (dst == NULL))) {
    return SMC_ERR_NULL_POINTER;
  }

  if (smc_ranges_overlap(src, src_len, dst, required) != 0) {
    return SMC_ERR_OVERLAP;
  }

  *required_out = required;
  return SMC_OK;
}

smc_status smc_hex_encode(const uint8_t *src,
                          size_t src_len,
                          char *dst,
                          size_t dst_len,
                          size_t *written) {
  size_t required = 0U;
  smc_status status = smc_validate_encode_args(src, src_len, dst, dst_len, written, &required);

  if (status != SMC_OK) {
    return status;
  }
  if (required == 0U) {
    return SMC_OK;
  }

  smc_ensure_dispatch_initialized();
  status = g_encode_impl(src, src_len, dst);
  if (status != SMC_OK) {
    return status;
  }

  *written = required;
  return SMC_OK;
}

smc_status smc_hex_decode(const char *src,
                          size_t src_len,
                          uint8_t *dst,
                          size_t dst_len,
                          size_t *written) {
  size_t required = 0U;
  smc_status status = smc_validate_decode_args(src, src_len, dst, dst_len, written, &required);

  if (status != SMC_OK) {
    return status;
  }
  if (required == 0U) {
    return SMC_OK;
  }

  smc_ensure_dispatch_initialized();
  status = g_decode_impl(src, src_len, dst);
  if (status != SMC_OK) {
    return status;
  }

  *written = required;
  return SMC_OK;
}

static smc_status smc_hex_encode_scalar(const uint8_t *src, size_t src_len, char *dst) {
  static const char k_hex[] = "0123456789abcdef";
  size_t i;

  for (i = 0U; i < src_len; ++i) {
    uint8_t value = src[i];
    dst[2U * i] = k_hex[(size_t)(value >> 4U)];
    dst[(2U * i) + 1U] = k_hex[(size_t)(value & 0x0FU)];
  }

  return SMC_OK;
}

static int smc_decode_nibble(unsigned char c) {
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

static smc_status smc_hex_decode_scalar(const char *src, size_t src_len, uint8_t *dst) {
  size_t i;

  for (i = 0U; i < src_len; i += 2U) {
    int hi = smc_decode_nibble((unsigned char)src[i]);
    int lo = smc_decode_nibble((unsigned char)src[i + 1U]);

    if ((hi < 0) || (lo < 0)) {
      return SMC_ERR_INVALID_CHAR;
    }

    dst[i / 2U] = (uint8_t)(((uint8_t)hi << 4U) | (uint8_t)lo);
  }

  return SMC_OK;
}

#if defined(__aarch64__) && defined(__ARM_NEON) && !defined(SMC_DISABLE_SIMD)
static const uint8_t smc_hex_lut_data[16] = {
    (uint8_t)'0', (uint8_t)'1', (uint8_t)'2', (uint8_t)'3', (uint8_t)'4', (uint8_t)'5',
    (uint8_t)'6', (uint8_t)'7', (uint8_t)'8', (uint8_t)'9', (uint8_t)'a', (uint8_t)'b',
    (uint8_t)'c', (uint8_t)'d', (uint8_t)'e', (uint8_t)'f'};

static smc_status smc_hex_encode_neon(const uint8_t *src, size_t src_len, char *dst) {
  size_t i = 0U;
  const uint8x16_t hex_lut = vld1q_u8(smc_hex_lut_data);
  const uint8x16_t low_mask = vdupq_n_u8(0x0FU);

  for (; (i + 32U) <= src_len; i += 32U) {
    uint8x16_t input0 = vld1q_u8(src + i);
    uint8x16_t hi0 = vshrq_n_u8(input0, 4);
    uint8x16_t lo0 = vandq_u8(input0, low_mask);
    uint8x16_t hi_ascii0 = vqtbl1q_u8(hex_lut, hi0);
    uint8x16_t lo_ascii0 = vqtbl1q_u8(hex_lut, lo0);
    uint8x16x2_t interleaved0 = vzipq_u8(hi_ascii0, lo_ascii0);

    uint8x16_t input1 = vld1q_u8(src + i + 16U);
    uint8x16_t hi1 = vshrq_n_u8(input1, 4);
    uint8x16_t lo1 = vandq_u8(input1, low_mask);
    uint8x16_t hi_ascii1 = vqtbl1q_u8(hex_lut, hi1);
    uint8x16_t lo_ascii1 = vqtbl1q_u8(hex_lut, lo1);
    uint8x16x2_t interleaved1 = vzipq_u8(hi_ascii1, lo_ascii1);

    vst1q_u8((uint8_t *)(void *)(dst + (2U * i)), interleaved0.val[0]);
    vst1q_u8((uint8_t *)(void *)(dst + (2U * i) + 16U), interleaved0.val[1]);
    vst1q_u8((uint8_t *)(void *)(dst + (2U * i) + 32U), interleaved1.val[0]);
    vst1q_u8((uint8_t *)(void *)(dst + (2U * i) + 48U), interleaved1.val[1]);
  }

  for (; (i + 16U) <= src_len; i += 16U) {
    uint8x16_t input = vld1q_u8(src + i);
    uint8x16_t hi = vshrq_n_u8(input, 4);
    uint8x16_t lo = vandq_u8(input, low_mask);
    uint8x16_t hi_ascii = vqtbl1q_u8(hex_lut, hi);
    uint8x16_t lo_ascii = vqtbl1q_u8(hex_lut, lo);
    uint8x16x2_t interleaved = vzipq_u8(hi_ascii, lo_ascii);

    vst1q_u8((uint8_t *)(void *)(dst + (2U * i)), interleaved.val[0]);
    vst1q_u8((uint8_t *)(void *)(dst + (2U * i) + 16U), interleaved.val[1]);
  }

  if (i < src_len) {
    return smc_hex_encode_scalar(src + i, src_len - i, dst + (2U * i));
  }

  return SMC_OK;
}

static SMC_ALWAYS_INLINE uint8x16_t smc_decode_32_hex_chars_neon_unchecked(const char *src,
                                                                            uint8_t *dst_out_16bytes) {
  const uint8x16_t c0 = vdupq_n_u8((uint8_t)'0');
  const uint8x16_t ca = vdupq_n_u8((uint8_t)'a');
  const uint8x16_t c9 = vdupq_n_u8(9U);
  const uint8x16_t c5 = vdupq_n_u8(5U);
  const uint8x16_t c10 = vdupq_n_u8(10U);
  const uint8x16_t chars0 = vld1q_u8((const uint8_t *)(const void *)src);
  const uint8x16_t chars1 = vld1q_u8((const uint8_t *)(const void *)(src + 16U));
  const uint8x16_t lower0 = vorrq_u8(chars0, vdupq_n_u8((uint8_t)0x20U));
  const uint8x16_t lower1 = vorrq_u8(chars1, vdupq_n_u8((uint8_t)0x20U));
  const uint8x16_t digit_delta0 = vsubq_u8(chars0, c0);
  const uint8x16_t digit_delta1 = vsubq_u8(chars1, c0);
  const uint8x16_t alpha_delta0 = vsubq_u8(lower0, ca);
  const uint8x16_t alpha_delta1 = vsubq_u8(lower1, ca);
  const uint8x16_t is_digit0 = vcleq_u8(digit_delta0, c9);
  const uint8x16_t is_digit1 = vcleq_u8(digit_delta1, c9);
  const uint8x16_t is_alpha0 = vcleq_u8(alpha_delta0, c5);
  const uint8x16_t is_alpha1 = vcleq_u8(alpha_delta1, c5);
  const uint8x16_t valid0 = vorrq_u8(is_digit0, is_alpha0);
  const uint8x16_t valid1 = vorrq_u8(is_digit1, is_alpha1);
  const uint8x16_t valid_all = vandq_u8(valid0, valid1);
  const uint8x16_t alpha_val0 = vaddq_u8(alpha_delta0, c10);
  const uint8x16_t alpha_val1 = vaddq_u8(alpha_delta1, c10);
  const uint8x16_t nibble0 = vbslq_u8(is_digit0, digit_delta0, alpha_val0);
  const uint8x16_t nibble1 = vbslq_u8(is_digit1, digit_delta1, alpha_val1);
  const uint8x16x2_t deinterleaved = vuzpq_u8(nibble0, nibble1);
  const uint8x16_t packed = vorrq_u8(vshlq_n_u8(deinterleaved.val[0], 4), deinterleaved.val[1]);

  vst1q_u8(dst_out_16bytes, packed);
  return valid_all;
}

static smc_status smc_hex_decode_neon(const char *src, size_t src_len, uint8_t *dst) {
  size_t i = 0U;

  for (; (i + 128U) <= src_len; i += 128U) {
    uint8x16_t valid_acc = vdupq_n_u8(0xFFU);
    valid_acc = vandq_u8(valid_acc, smc_decode_32_hex_chars_neon_unchecked(src + i, dst + (i / 2U)));
    valid_acc = vandq_u8(valid_acc,
                         smc_decode_32_hex_chars_neon_unchecked(src + i + 32U, dst + (i / 2U) + 16U));
    valid_acc = vandq_u8(valid_acc,
                         smc_decode_32_hex_chars_neon_unchecked(src + i + 64U, dst + (i / 2U) + 32U));
    valid_acc = vandq_u8(valid_acc,
                         smc_decode_32_hex_chars_neon_unchecked(src + i + 96U, dst + (i / 2U) + 48U));
    if (vminvq_u8(valid_acc) != 0xFFU) {
      return SMC_ERR_INVALID_CHAR;
    }
  }

  for (; (i + 64U) <= src_len; i += 64U) {
    uint8x16_t valid_acc = vdupq_n_u8(0xFFU);
    valid_acc = vandq_u8(valid_acc, smc_decode_32_hex_chars_neon_unchecked(src + i, dst + (i / 2U)));
    valid_acc = vandq_u8(valid_acc,
                         smc_decode_32_hex_chars_neon_unchecked(src + i + 32U, dst + (i / 2U) + 16U));
    if (vminvq_u8(valid_acc) != 0xFFU) {
      return SMC_ERR_INVALID_CHAR;
    }
  }

  for (; (i + 32U) <= src_len; i += 32U) {
    uint8x16_t valid = smc_decode_32_hex_chars_neon_unchecked(src + i, dst + (i / 2U));
    if (vminvq_u8(valid) != 0xFFU) {
      return SMC_ERR_INVALID_CHAR;
    }
  }

  if (i < src_len) {
    return smc_hex_decode_scalar(src + i, src_len - i, dst + (i / 2U));
  }

  return SMC_OK;
}
#endif

#if defined(__x86_64__) && (defined(__clang__) || defined(__GNUC__)) && !defined(SMC_DISABLE_SIMD)
SMC_AVX2_TARGET static SMC_ALWAYS_INLINE __m256i smc_nibble_to_hex_avx2(__m256i nibble) {
  __m256i digit = _mm256_add_epi8(nibble, _mm256_set1_epi8('0'));
  __m256i alpha = _mm256_add_epi8(nibble, _mm256_set1_epi8((char)('a' - 10)));
  __m256i is_alpha = _mm256_cmpgt_epi8(nibble, _mm256_set1_epi8(9));
  return _mm256_blendv_epi8(digit, alpha, is_alpha);
}

SMC_AVX2_TARGET static smc_status smc_hex_encode_avx2(const uint8_t *src,
                                                       size_t src_len,
                                                       char *dst) {
  size_t i = 0U;
  const __m256i mask = _mm256_set1_epi8(0x0F);

  for (; (i + 64U) <= src_len; i += 64U) {
    __m256i input0 = _mm256_loadu_si256((const __m256i *)(const void *)(src + i));
    __m256i hi0 = _mm256_and_si256(_mm256_srli_epi16(input0, 4), mask);
    __m256i lo0 = _mm256_and_si256(input0, mask);
    __m256i hi_ascii0 = smc_nibble_to_hex_avx2(hi0);
    __m256i lo_ascii0 = smc_nibble_to_hex_avx2(lo0);
    __m256i interleaved_lo0 = _mm256_unpacklo_epi8(hi_ascii0, lo_ascii0);
    __m256i interleaved_hi0 = _mm256_unpackhi_epi8(hi_ascii0, lo_ascii0);

    __m256i input1 = _mm256_loadu_si256((const __m256i *)(const void *)(src + i + 32U));
    __m256i hi1 = _mm256_and_si256(_mm256_srli_epi16(input1, 4), mask);
    __m256i lo1 = _mm256_and_si256(input1, mask);
    __m256i hi_ascii1 = smc_nibble_to_hex_avx2(hi1);
    __m256i lo_ascii1 = smc_nibble_to_hex_avx2(lo1);
    __m256i interleaved_lo1 = _mm256_unpacklo_epi8(hi_ascii1, lo_ascii1);
    __m256i interleaved_hi1 = _mm256_unpackhi_epi8(hi_ascii1, lo_ascii1);

    _mm256_storeu_si256((__m256i *)(void *)(dst + (2U * i)), interleaved_lo0);
    _mm256_storeu_si256((__m256i *)(void *)(dst + (2U * i) + 32U), interleaved_hi0);
    _mm256_storeu_si256((__m256i *)(void *)(dst + (2U * i) + 64U), interleaved_lo1);
    _mm256_storeu_si256((__m256i *)(void *)(dst + (2U * i) + 96U), interleaved_hi1);
  }

  for (; (i + 32U) <= src_len; i += 32U) {
    __m256i input = _mm256_loadu_si256((const __m256i *)(const void *)(src + i));
    __m256i hi = _mm256_and_si256(_mm256_srli_epi16(input, 4), mask);
    __m256i lo = _mm256_and_si256(input, mask);
    __m256i hi_ascii = smc_nibble_to_hex_avx2(hi);
    __m256i lo_ascii = smc_nibble_to_hex_avx2(lo);
    __m256i interleaved_lo = _mm256_unpacklo_epi8(hi_ascii, lo_ascii);
    __m256i interleaved_hi = _mm256_unpackhi_epi8(hi_ascii, lo_ascii);

    _mm256_storeu_si256((__m256i *)(void *)(dst + (2U * i)), interleaved_lo);
    _mm256_storeu_si256((__m256i *)(void *)(dst + (2U * i) + 32U), interleaved_hi);
  }

  if (i < src_len) {
    return smc_hex_encode_scalar(src + i, src_len - i, dst + (2U * i));
  }

  return SMC_OK;
}

SMC_AVX2_TARGET static SMC_ALWAYS_INLINE smc_status smc_decode_32_hex_chars_avx2(
    const char *src, uint8_t *dst_out_16bytes) {
  const __m256i chars = _mm256_loadu_si256((const __m256i *)(const void *)src);
  const __m256i lower = _mm256_or_si256(chars, _mm256_set1_epi8(0x20));
  const __m256i is_digit =
      _mm256_and_si256(_mm256_cmpgt_epi8(chars, _mm256_set1_epi8('0' - 1)),
                       _mm256_cmpgt_epi8(_mm256_set1_epi8('9' + 1), chars));
  const __m256i is_alpha =
      _mm256_and_si256(_mm256_cmpgt_epi8(lower, _mm256_set1_epi8('a' - 1)),
                       _mm256_cmpgt_epi8(_mm256_set1_epi8('f' + 1), lower));
  const __m256i valid = _mm256_or_si256(is_digit, is_alpha);
  const __m256i digit_val = _mm256_sub_epi8(chars, _mm256_set1_epi8('0'));
  const __m256i alpha_val =
      _mm256_add_epi8(_mm256_sub_epi8(lower, _mm256_set1_epi8('a')), _mm256_set1_epi8(10));
  const __m256i nibble = _mm256_blendv_epi8(alpha_val, digit_val, is_digit);
  const __m256i mul = _mm256_set1_epi16(0x0110);
  const __m256i paired = _mm256_maddubs_epi16(nibble, mul);
  const __m128i low128 = _mm256_castsi256_si128(paired);
  const __m128i high128 = _mm256_extracti128_si256(paired, 1);
  const __m128i packed = _mm_packus_epi16(low128, high128);

  if (_mm256_movemask_epi8(valid) != -1) {
    return SMC_ERR_INVALID_CHAR;
  }

  _mm_storeu_si128((__m128i *)(void *)dst_out_16bytes, packed);

  return SMC_OK;
}

SMC_AVX2_TARGET static smc_status smc_hex_decode_avx2(const char *src,
                                                       size_t src_len,
                                                       uint8_t *dst) {
  size_t i = 0U;

  for (; (i + 64U) <= src_len; i += 64U) {
    smc_status status0 = smc_decode_32_hex_chars_avx2(src + i, dst + (i / 2U));
    smc_status status1;
    if (status0 != SMC_OK) {
      return status0;
    }
    status1 = smc_decode_32_hex_chars_avx2(src + i + 32U, dst + (i / 2U) + 16U);
    if (status1 != SMC_OK) {
      return status1;
    }
  }

  for (; (i + 32U) <= src_len; i += 32U) {
    smc_status status = smc_decode_32_hex_chars_avx2(src + i, dst + (i / 2U));
    if (status != SMC_OK) {
      return status;
    }
  }

  if (i < src_len) {
    return smc_hex_decode_scalar(src + i, src_len - i, dst + (i / 2U));
  }

  return SMC_OK;
}
#endif
