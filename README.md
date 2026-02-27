# simd-micro-codec

`simd-micro-codec` は、Hex変換専用の高速Cライブラリです。

- Encode: `bytes -> lowercase hex`
- Decode: `hex -> bytes`

機能を絞って、性能と信頼性を優先しています。

## 特徴

- SIMD最適化
  - ARM64: NEON
  - x86_64: AVX2（実行時判定）
- Scalarフォールバック
- ライブラリ内部で動的メモリ確保なし
- 厳格な引数検証と明確なステータスコード
- テスト、Sanitizer、静的解析を標準化

## 対応環境

- C11コンパイラ
- `make`

検証環境例:
- Apple Clang 17

## クイックスタート

```sh
make test
make sanitize
make static-analysis
make compile-x86
```

ベンチマーク:

```sh
make bench
./build/bench 64
```

外部比較ベンチ（OpenSSL/naive比較）:

```sh
make bench-compare
./build/bench_compare 64
```

直近実測（64MB, `bench_compare`）:

| Metric | smc | OpenSSL 3.6.1 | naive |
|---|---:|---:|---:|
| Encode GB/s | 19.617 | 1.560 | 2.001 |
| Decode GB/s | 8.614 | 0.413 | 0.560 |

速度倍率（smc基準）:

1. Encode vs OpenSSL: `12.57x`
2. Decode vs OpenSSL: `20.83x`
3. Encode vs naive: `9.80x`
4. Decode vs naive: `15.39x`

注記:

1. ベンチ値はCPU/OS/コンパイラ条件で変動します。
2. 同一環境・同一コマンドで比較してください。

## API

ヘッダ: `include/smc_hex.h`

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

## API契約

- `decode` 入力は偶数長が必須
- 失敗時は常に `*written = 0`
- `src` と `dst` のオーバーラップは `SMC_ERR_OVERLAP`
- バッファ不足は `SMC_ERR_DST_TOO_SMALL`
- `SMC_FORCE_SCALAR=1` で強制的にScalar実装を使用

## 使い方

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

## リポジトリ構成

- `include/smc_hex.h`: 公開API
- `src/smc_hex.c`: 実装
- `tests/test_smc_hex.c`: 基本/境界/異常系テスト
- `tests/test_fuzz.c`: ランダムテスト
- `tests/test_thread_init.c`: 並列初期化テスト
- `bench/bench.c`: スループット計測
- `SPEC.md`: 仕様書

## ライセンス

MIT License。詳細は `LICENSE` を参照してください。

## 詳細ドキュメント

設計・API契約・テスト戦略・運用上の注意は `DOCUMENTATION.md` を参照してください。
