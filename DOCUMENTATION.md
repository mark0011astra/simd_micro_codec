# simd-micro-codec 詳細ドキュメント

## 1. 概要

`simd-micro-codec` は、Hex変換に特化したC11ライブラリです。

- Encode: `bytes -> lowercase hex`
- Decode: `hex -> bytes`
- ARM64: NEON最適化
- x86_64: AVX2最適化（実行時判定）
- SIMD非対応環境ではScalar実装へフォールバック

対象をHex変換だけに絞ることで、性能と挙動の明確さを優先しています。

---

## 2. 設計方針

本ライブラリの実装方針は以下です。

1. APIを最小化して契約を固定する
2. 引数検証を関数先頭で完了する（Fail-Fast）
3. 失敗時の出力状態を一貫させる（`*written = 0`）
4. SIMDの有無に依存せず同じAPI契約を保つ
5. ライブラリ内部で動的メモリ確保を行わない

---

## 3. 公開API

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

### 3.1 `smc_hex_encode_required_size`

- 返値: 必要な出力バイト数（`src_len * 2`）
- オーバーフローが発生するサイズは `0` を返す
  - `src_len > SIZE_MAX / 2` の場合

### 3.2 `smc_hex_encode`

入力:

- `src`: 入力バイト列
- `src_len`: 入力サイズ
- `dst`: 出力先バッファ（終端 `\0` は書かない）
- `dst_len`: 出力先サイズ
- `written`: 実際に書いたバイト数

成功時:

- `SMC_OK`
- `*written = src_len * 2`

失敗時:

- 必ず `*written = 0`（`written != NULL` の場合）

注意点:

- `src_len == 0` の場合、`src` と `dst` は `NULL` でも良い
- 出力バッファ不足は `SMC_ERR_DST_TOO_SMALL`
- `src` と `dst` の領域が重なる場合は `SMC_ERR_OVERLAP`

### 3.3 `smc_hex_decode`

入力:

- `src`: Hex文字列（`0-9`, `a-f`, `A-F`）
- `src_len`: 入力文字数（偶数必須）
- `dst`: 出力先バッファ
- `dst_len`: 出力先サイズ
- `written`: 実際に書いたバイト数

成功時:

- `SMC_OK`
- `*written = src_len / 2`

失敗時:

- 必ず `*written = 0`（`written != NULL` の場合）

注意点:

- 奇数長入力は `SMC_ERR_INVALID_LENGTH`
- 無効文字を含む場合は `SMC_ERR_INVALID_CHAR`
- `src_len == 0` の場合、`src` と `dst` は `NULL` でも良い
- `src` と `dst` の領域が重なる場合は `SMC_ERR_OVERLAP`

---

## 4. ステータスコード一覧

| Code | 値 | 意味 |
|---|---:|---|
| `SMC_OK` | 0 | 成功 |
| `SMC_ERR_NULL_POINTER` | 1 | 必須ポインタが `NULL` |
| `SMC_ERR_DST_TOO_SMALL` | 2 | `dst_len` が不足 |
| `SMC_ERR_INVALID_LENGTH` | 3 | 長さ条件違反（Decode奇数長、Encodeサイズオーバーフロー） |
| `SMC_ERR_INVALID_CHAR` | 4 | Decode入力に16進以外の文字が含まれる |
| `SMC_ERR_OVERLAP` | 5 | `src` と `dst` のメモリ範囲が重複 |

---

## 5. メモリ重複（Overlap）ルール

Encode/Decodeともに、`src` と `dst` の範囲重複を禁止しています。

理由:

1. インプレース変換を許可すると、ベクトル化パスの安全性と実装複雑度が大きく悪化する
2. API契約を単純化し、実装差（SIMD/Scalar）による挙動差を防ぐ

許可される例:

- `src` と `dst` が完全に別領域
- `src_len == 0` または `dst_len == 0` で実処理が発生しないケース

拒否される例:

- `dst = (char *)(src + 1)` のような部分重なり
- Decode時に `dst = (uint8_t *)(src + 1)` のような部分重なり

---

## 6. SIMDディスパッチの仕組み

初回呼び出し時に、内部ディスパッチ関数を一度だけ初期化します。

- 既定値: Scalar実装
- ARM64 + NEONビルド時: NEON実装を選択
- x86_64ビルド時: `__builtin_cpu_supports("avx2")` が真ならAVX2実装を選択
- `SMC_FORCE_SCALAR=1` なら実行時に必ずScalarを選択
- `SMC_DISABLE_SIMD` を定義してビルドすると、SIMDコード自体を除外

初期化は `atomic_int` を使って同期しているため、複数スレッドから同時に初回呼び出しされても安全です。

---

## 7. スレッドセーフ性

API関数 `smc_hex_encode` / `smc_hex_decode` は、以下の前提でスレッドセーフです。

- 呼び出しごとに独立したバッファを渡す
- `written` を呼び出し間で共有しない

内部状態はディスパッチ関数ポインタの初期化のみで、初期化完了後は読み取り専用として扱われます。

---

## 8. ビルドと実行

必須:

- C11コンパイラ
- `make`

主要ターゲット:

| Target | 内容 |
|---|---|
| `make test` | 単体テスト + fuzzテスト + 動的メモリ未使用チェック |
| `make sanitize` | ASan/UBSan有効でテスト |
| `make static-analysis` | Clang Static Analyzer |
| `make bench` | ライブラリ vs 参照実装のベンチ |
| `make bench-compare` | ライブラリ vs OpenSSL vs naive比較 |
| `make compile-x86` | x86_64向けオブジェクトのクロスコンパイル |

注記:

- `bench-compare` は OpenSSL 開発ライブラリが必要です
- テストは `-Wall -Wextra -Werror -pedantic` を前提にビルドされます

---

## 9. テスト戦略

テストは次の3層で構成しています。

1. 決定的ユニットテスト（`tests/test_smc_hex.c`）
2. ランダムfuzzテスト（`tests/test_fuzz.c`）
3. 並列初期化テスト（`tests/test_thread_init.c`）

### 9.1 ユニットテストで検証する主な項目

- 基本Encode/Decodeの正しさ
- `written` の値
- エラー時 `*written = 0`
- Decodeの大文字小文字受理
- Overlap検知
- 0〜255全バイト文字ペアに対するDecode妥当性

### 9.2 fuzzテスト

- 10万ケースのランダム入力
- 参照実装との一致比較
- 無効文字注入時の `SMC_ERR_INVALID_CHAR` と `written=0` を検証

### 9.3 並列テスト

- 8スレッドで `encode -> decode -> memcmp` を反復
- 初回ディスパッチ初期化の競合を含む状況で整合性を確認

---

## 10. ベンチマークの読み方

`bench/bench.c` と `bench/bench_compare.c` は、次の条件で計測します。

- 入力: 既定64MB（引数で変更可能）
- ウォームアップ: 3回
- 本計測: 10回
- 指標: 中央値（median）
- 出力: `GB/s` と `ns/byte`

`GB/s` が高いほど高速、`ns/byte` が低いほど高速です。  
比較時は、同じバイナリ・同じ入力サイズ・同じCPU状態で計測してください。

---

## 11. 実装を組み込む最小例

ライブラリを単体でリンクする構成ではなく、`src/smc_hex.c` を一緒にコンパイルする想定です。

```sh
clang -std=c11 -O3 -Iinclude your_app.c src/smc_hex.c -o your_app
```

OpenSSL比較ベンチをビルドする場合:

```sh
clang -std=c11 -O3 -Iinclude bench/bench_compare.c src/smc_hex.c \
  -o bench_compare $(pkg-config --cflags --libs openssl)
```

---

## 12. 運用上の注意

1. Encode出力に終端 `\0` は付かない
2. Decode入力に空白や区切り文字は許可しない
3. 無効入力は修復せず、即時エラーとして返す
4. 大きなサイズを扱う前に `smc_hex_encode_required_size` で容量確認する

---

## 13. トラブルシューティング

`SMC_ERR_DST_TOO_SMALL` が出る:

- Encode: `dst_len >= src_len * 2` を満たしているか確認
- Decode: `dst_len >= src_len / 2` を満たしているか確認

`SMC_ERR_INVALID_LENGTH` が出る:

- Decode入力長が奇数になっていないか確認
- Encode対象サイズが `SIZE_MAX / 2` を超えていないか確認

`SMC_ERR_INVALID_CHAR` が出る:

- 入力が `0-9`, `a-f`, `A-F` のみか確認
- 改行、空白、`0x` 接頭辞が混入していないか確認

期待より遅い:

- `SMC_FORCE_SCALAR=1` が設定されていないか確認
- リリースビルド（`-O3`）で計測しているか確認
- ベンチ中に他の高負荷プロセスが走っていないか確認
