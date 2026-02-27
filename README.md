# simd-micro-codec

`simd-micro-codec` is a high-performance C library focused on Hex conversion.

- Encode: `bytes -> lowercase hex`
- Decode: `hex -> bytes`

The project intentionally keeps the scope narrow to prioritize speed, correctness, and simplicity.

## Features

- SIMD-optimized implementations
  - ARM64: NEON
  - x86_64: AVX2 (runtime dispatch)
- Scalar fallback path
- No dynamic memory allocation inside the library
- Strict argument validation with explicit status codes
- Standardized test, sanitizer, and static-analysis workflow

## Requirements

- C11 compiler
- `make`

Validated example environment:
- Apple Clang 17

## Quick Start

```sh
make test
make sanitize
make static-analysis
make compile-x86
```

Benchmark:

```sh
make bench
./build/bench 64
```

Comparison benchmark (OpenSSL / naive):

```sh
make bench-compare
./build/bench_compare 64
```

Recent sample result (`64MB`, `bench_compare`):

| Metric | smc | OpenSSL 3.6.1 | naive |
|---|---:|---:|---:|
| Encode GB/s | 18.740 | 1.394 | 1.980 |
| Decode GB/s | 8.199 | 0.379 | 0.530 |

Speedup (smc baseline):

1. Encode vs OpenSSL: `13.45x`
2. Decode vs OpenSSL: `21.64x`
3. Encode vs naive: `9.46x`
4. Decode vs naive: `15.46x`

Notes:

1. Benchmark numbers vary by CPU, OS, and compiler.
2. Use the same machine and command for fair comparison.

## API

Header: `include/smc_hex.h`

```c
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
```

## API Behavior

- `decode` input length must be even
- On failure, `*written` is always set to `0`
- Overlap between `src` and `dst` returns `SMC_ERR_OVERLAP`
- Insufficient output buffer returns `SMC_ERR_DST_TOO_SMALL`
- Set `SMC_FORCE_SCALAR=1` to force scalar implementation

## Usage

```c
#include "smc_hex.h"
#include <stdint.h>
#include <stdio.h>

int main(void) {
  const uint8_t src[] = {0xde, 0xad, 0xbe, 0xef};
  char hex[8];
  uint8_t out[4];
  size_t written = 0;

  if (smc_hex_encode(src, 4U, hex, sizeof(hex), &written) != SMC_OK) {
    return 1;
  }

  if (smc_hex_decode(hex, written, out, sizeof(out), &written) != SMC_OK) {
    return 1;
  }

  printf("ok\\n");
  return 0;
}
```

## Repository Layout

- `include/smc_hex.h`: Public API
- `src/smc_hex.c`: Implementation
- `tests/test_smc_hex.c`: Basic, boundary, and error tests
- `tests/test_fuzz.c`: Randomized fuzz-style tests
- `tests/test_thread_init.c`: Concurrent initialization test
- `bench/bench.c`: Throughput benchmark
- `bench/bench_compare.c`: OpenSSL and naive comparison benchmark

## License

MIT License. See `LICENSE` for details.

## Disclaimer

- This project is provided "as is", without warranties of any kind.
- Benchmark numbers in this repository are sample results, not performance guarantees.
- You are responsible for validating correctness, security, and performance in your own environment before production use.
- The authors and contributors are not liable for any damages resulting from the use of this software.

## Detailed Documentation

For architecture, API behavior, test strategy, and operational notes, see `DOCUMENTATION.md`.
