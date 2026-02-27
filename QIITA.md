# CでHex変換を最大21.64倍高速化した話（AVX2/NEON対応）

Hex変換（`bytes <-> hex string`）は地味ですが、ログ処理やバイナリI/Oでは意外とボトルネックになります。  
そこで、Hex変換だけに機能を絞った小さなCライブラリ `simd-micro-codec` を作りました。

- Encode: `bytes -> lowercase hex`
- Decode: `hex -> bytes`
- ARM64はNEON、x86_64はAVX2（実行時判定）
- SIMDが使えない環境ではScalarにフォールバック
- ライブラリ内部で動的メモリ確保なし

---

## 何を重視したか

このライブラリは「多機能」ではなく、次の3つを優先しています。

1. 性能
2. 正確性
3. シンプルさ

APIは最小限です。

```c
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

---

## すぐ試す方法

```sh
make test
make sanitize
make static-analysis
make bench
./build/bench 64
```

比較ベンチ（OpenSSL/naive）:

```sh
make bench-compare
./build/bench_compare 64
```

---

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

  if (smc_hex_encode(src, 4U, hex, sizeof(hex), &written) != SMC_OK) return 1;
  if (smc_hex_decode(hex, written, out, sizeof(out), &written) != SMC_OK) return 1;

  printf("ok\n");
  return 0;
}
```

---

## 失敗時のルールを明確にした

運用中に扱いやすいよう、エラー時の挙動を固定しています。

- `decode` は偶数長必須（奇数は `SMC_ERR_INVALID_LENGTH`）
- 不正文字は `SMC_ERR_INVALID_CHAR`
- バッファ不足は `SMC_ERR_DST_TOO_SMALL`
- `src` と `dst` のオーバーラップは `SMC_ERR_OVERLAP`
- 失敗時は常に `*written = 0`

このあたりを曖昧にしないだけで、呼び出し側のバグ調査がかなり楽になります。

---

## ベンチマーク結果（64MB / 10回中央値）

まず結論として、同一条件で比較したとき `smc` はかなり差を付けました。

| Workload | smc | OpenSSL | naive | smc vs OpenSSL | smc vs naive |
|---|---:|---:|---:|---:|---:|
| Encode | 18.740 GB/s (0.053 ns/byte) | 1.394 GB/s (0.717 ns/byte) | 1.980 GB/s (0.505 ns/byte) | 13.45x | 9.46x |
| Decode | 8.199 GB/s (0.122 ns/byte) | 0.379 GB/s (2.640 ns/byte) | 0.530 GB/s (1.886 ns/byte) | 21.64x | 15.46x |

計測コマンド:

```sh
make bench-compare
./build/bench_compare 64
```

計測環境:

- OS: Darwin 25.3.0 (`arm64`)
- Compiler: Apple clang 17.0.0
- OpenSSL: 3.6.1

このベンチはウォームアップ3回 + 本計測10回で、中央値を採用しています。  
外れ値の影響を減らして、再現しやすい値に寄せています。

見どころ:

1. Encodeは `18.740 GB/s`。文字列化処理としてはかなり高いスループットです。
2. DecodeはEncodeより重い処理ですが、それでも `8.199 GB/s` を維持しています。
3. OpenSSL比ではDecodeが `21.64x` と特に差が大きく、`hex専用実装` の効果が明確に出ました。

もちろん値はCPUやコンパイラで変わりますが、同一環境での相対比較ではSIMD化の効果がはっきり確認できます。

---

## まとめ

Hex変換のような「単機能」でも、範囲を絞ると実装をかなり攻められます。  
特に、次の方針が効きました。

1. APIを最小化する
2. エラー時の挙動を固定する
3. SIMD + Scalarフォールバックで移植性を保つ
