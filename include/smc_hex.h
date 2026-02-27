#ifndef SMC_HEX_H
#define SMC_HEX_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum smc_status {
  SMC_OK = 0,
  SMC_ERR_NULL_POINTER = 1,
  SMC_ERR_DST_TOO_SMALL = 2,
  SMC_ERR_INVALID_LENGTH = 3,
  SMC_ERR_INVALID_CHAR = 4,
  SMC_ERR_OVERLAP = 5
} smc_status;

smc_status smc_hex_encode(const uint8_t *src,
                          size_t src_len,
                          char *dst,
                          size_t dst_len,
                          size_t *written);

smc_status smc_hex_decode(const char *src,
                          size_t src_len,
                          uint8_t *dst,
                          size_t dst_len,
                          size_t *written);

size_t smc_hex_encode_required_size(size_t src_len);

#ifdef __cplusplus
}
#endif

#endif
