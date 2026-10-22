# Windows Hello に「このセキュリティ キーは使用できません」と出るとき

対象: `fido_uno_key`（ATmega328P）+ `fido_16u2_hid`（ATmega16U2）構成の DIY FIDO2 キー。

```
Windows Hello セットアップ
このセキュリティ キーは使用できません。別のセキュリティ キーを使用してください。
```

このダイアログは **Windows の WebAuthn スタック（webauthn.dll / CredentialUIBroker.exe）** が出すもので、
CTAP2 のどこで失敗しても **同じ文面** になります。したがって最初にやることは
「**16U2 と 328P のどちらで死んでいるか**」を確定させることです。

診断: [`tools/Get-WebAuthnTrace.ps1`](../tools/Get-WebAuthnTrace.ps1)（読み取りのみ・変更なし）

```powershell
# 管理者の PowerShell で
powershell -ExecutionPolicy Bypass -File .\tools\Get-WebAuthnTrace.ps1 -Mode Both -Clear -EnableLog
# → 120 秒の待ち時間の間に、エラーを 1 回だけ再現する
```

> **注意**: このスクリプトは UTF-8 **BOM 付き** で保存されています。BOM が無いと
> Windows PowerShell 5.1 がシステム ANSI（Shift-JIS）として読み、
> `Unterminated string literal` で 1 行も実行されません（`.gitattributes` で `*.ps1 -text`）。

---

## 1. これまでに確定したこと（実測）

トレース（`Microsoft-Windows-WebAuthN/Operational`）で **157 件の GetInfo** を集計した結果:

| 応答 | 件数 | 出どころ |
| --- | --- | --- |
| 完全な CBOR（≥2 バイト、status `0x00`） | 136 | **328P が正常応答** |
| 1 バイト `0x01` | 12 | **16U2 が合成**（`send_ctap_status`） |
| 1 バイト `0x02` | 2 | **16U2 が合成** |
| 1 バイト `0x7F` | **7** | **16U2 が合成** |

決定的なのは時刻です。

- 最後に 328P が正常応答したのは **10/23 03:49:40**（GetInfo を 152 バイトで返した）
- それ以降、328P からの CBOR 応答は **0 件**
- その間も 16U2 は CTAPHID_INIT（`0x86`）に応答し続けていた

```
[04:42:18.445] INIT 応答 OK          ← 16U2 は生きている（USB は正常）
[04:42:18.581] REQ 0x04 GetInfo
              RES 0x7F (1 バイト)    ← 16U2 が代わりに返した値
[04:42:18.581] デバイス スレッド終了
[04:42:18.687] エラー 0x80070032
```

**328P は UART に一切応答していない**（フレーム ACK すら返らない）。
16U2 は 4 回再送し、それでも ACK が無いので `send_ctap_status()` で `0x7F` を返しています。
`0x08`（getNextAssertion）も `0x0A`（credMgmt）も **一度も送られていない** ので、
未実装コマンドは今回の原因ではありません。

→ 症状は「**328P 単体のウエッジ**」。USB を挿し直すまで復帰しませんでした。

### なぜ `0x7F` を見て「ファーム内部エラー」と判断してはいけないか

`0x7F` は 2 か所から出ます。

| 出どころ | 条件 | 見分け方 |
| --- | --- | --- |
| **328P** `ctapErr(0x7F)` | 乱数・uECC・署名の失敗 | 応答が CBOR として妥当 / 直前まで同一コマンドが成功している |
| **16U2** `send_ctap_status(cid, 0x7F)` | 328P から応答が来ない（4 か所: UART 送信失敗・GetInfo 再送失敗・keepalive タイムアウト） | **1 バイトだけ**。`GetInfo` に対して返るのは構造上あり得ない（`buildCtap2GetInfo()` は必ず `0x00` で始まる CBOR を返す） |

**`REQ 0x04` に対して 1 バイトの `0x7F`** が返ったら、それは 328P ではなく 16U2 の応答です。

---

## 2. 328P ウエッジ対策（実装済み）

「挿し直すまで死ぬ」を「次のリクエストで自動復帰する」に変えました。

### 2.1 16U2 → 328P のハードリセット

ATmega16U2 の **PD7** は、Uno の 0.1 µF 自動リセット用コンデンサ経由で 328P の RESET に繋がっています。
16U2 は次の 2 つの場面でこの線をパルスし、328P を再起動します。

- `send_frame_acked()` が 4 回とも ACK を得られなかった（328P が UART を読んでいない）
- keepalive が上限に達した（フレームは ACK したが応答を返さない = コマンド内で停止）

その後 `boot_ready = false` に戻り、328P の `0xA6` ビーコンを最大 90 秒待ちます
（再起動直後は「直前コマンドの点滅表示」+ 起動時 P-256 鍵生成が走るため）。

> **前提 1**: Uno R3 の RESET-EN ジャンパ（半田ジャンパ）が導通していること。
> 切ってある個体ではこのパルスは無効で、従来どおり `0x7F` のままになります。
>
> **前提 2**: 同梱の `fido_16u2_hid.hex` は**この変更より前のビルド**です。
> 必ず再ビルドしてから書き込んでください（`.c` を変えただけでは効きません）。
>
> ```powershell
> powershell -ExecutionPolicy Bypass -File .\fido_16u2_hid\build_16u2.ps1     # .hex を再生成
> powershell -ExecutionPolicy Bypass -File .\fido_16u2_hid\flash_16u2_fido_hid.ps1
> ```
>
> 現在の症状（1 バイトの `0x7F`）は 16U2 側の判断なので、**16U2 の更新が必須**です。
> 328P 側（ウォッチドッグと LED 表示）は通常のスケッチ書き込みで反映されます。

### 2.2 328P 側のウォッチドッグ

`WDTO_8S` を有効化し、次の場所で明示的に供給します。

| 場所 | 理由 |
| --- | --- |
| `loop()` 先頭 | 通常の進行 |
| `initStorage()` の全消去ループ | EEPROM 全消去は約 3.4 秒 |
| `entropyCollectUntil()` | 256 回の ADC 読み取り |
| `waitForUserPresence()` / `holdBinaryPresence()` | 25 秒 / 1.5 秒の待ち |
| **`EccPoint_mult()` のビットループ（`eccFeed()`）** | 1 回の P-256 乗算が 20〜40 秒かかるため |

**`uECC_vli_modInv()` にはあえて供給していません。**
この関数は入力が壊れると `while (a != b)` が終わらない古典的な無限ループになり得ます。
そこで供給しないことで、本当に無限ループした場合は 8 秒でウォッチドッグが働き、
チップが自動再起動します（＝ウエッジが残らない）。

### 2.3 直前に実行していたコマンドの記録

`executeCtap2InPlace()` が CTAP コマンドバイトを EEPROM `1014` に保存し、
ウォッチドッグ再起動後は **L LED の点滅回数** でそれを知らせます（120ms 点灯 × N 回、2 セット）。

| 点滅数 | コマンド |
| --- | --- |
| 1 | `authenticatorMakeCredential` |
| 2 | `authenticatorGetAssertion` |
| 4 | `authenticatorGetInfo`（＝コマンド依存ではないウエッジ） |
| 6 | `authenticatorClientPIN` |
| 7 | `authenticatorReset` |
| 11 | `authenticatorSelection` |

再起動回数は EEPROM `1015` に加算されます。

---

## 3. Windows 側で先に潰すべき既知の問題

ファームを疑う前に、**YubiKey でも同じ症状になる**既知の問題を確認してください。

1. **パスキー許可がオフ**（Windows 11 24H2 以降）
   `設定 > プライバシーとセキュリティ > パスキー` の「アプリでのパスキーの作成と使用を許可する」がオンか。
   ここがオフだと、U2F のセキュリティキーでも **Windows セキュリティのダイアログ自体が出ず**に失敗します。
2. **Windows 11 24H2 のビルド不具合**
   build `26100.4652` 〜 `26100.6584` 未満では `セキュリティ キー > 管理` が失敗します。
   **KB5065426（build 26100.6584）で修正済み**。
   （参考: [Yubico サポート](https://support.yubico.com/hc/en-us/articles/21190316012444--resolved-Windows-Account-Management-in-Windows-11-24H2-Unable-to-manage-FIDO-application-on-Security-Key-YubiKey-or-YubiKey-Bio)）
3. **サードパーティ製の認証プロバイダー**（Duo、Kensington / VeriMark 等）
4. **「Microsoft アカウント用に Windows Hello サインインのみを許可する」がオン**
5. **スロット満杯 / 既存資格情報の衝突**（`0x28` / `0x19`）→ 🗑️ 鍵リセット（`CTAP2 07`）

---

## 4. トレースの読み方

| `RES` | 名前 | 次の手 |
| --- | --- | --- |
| `0x00` + CBOR | OK | 失敗しているのは**別のコマンド**（REQ を遡る） |
| `0x7F`（1 バイト） | **16U2 合成** | 328P が無応答。2 章の自動復帰が効いているか、RESET-EN を確認 |
| `0x7F`（CBOR として妥当） | 328P 内部エラー | uECC / 乱数 / 署名。LED の点滅でコマンドを特定 |
| `0x2A`（`REQ`=`0x08`/`0x0A`） | UNSUPPORTED_OPTION | 未実装。Windows の管理 UI を使うなら実装対象 |
| `0x28` | KEY_STORE_FULL | 5 スロット満杯 → 鍵リセット |
| `0x19` | CREDENTIAL_EXCLUDED | 既存資格情報と衝突 → 鍵リセット |
| `0x31` / `0x35` | PIN_INVALID / PIN_NOT_SET | PIN/UV の状態不整合 |
| `0x33` | PIN_AUTH_INVALID | pinUvAuthParam 検証・RP バインドで失敗 |
| `0x39` | REQUEST_TOO_LARGE | 512 バイト超 |

イベントが 1 件も出ない → ダイアログがキーに到達していない（プロバイダー無効・パスキー許可オフ・USB）。

---

## 5. 前提: 個人の Microsoft アカウントで「Windows へのサインイン」は原則できない

| やりたいこと | 使う画面 | 個人の Microsoft アカウント | 職場/学校 (Entra ID) |
| --- | --- | --- | --- |
| **Web のパスキー**（Microsoft アカウントのセキュリティ情報に追加） | `account.microsoft.com` → セキュリティ → 「サインイン方法の追加」 | 公式サポート対象 | サポート対象 |
| **Windows へのセキュリティキーサインイン**（ロック画面でキーを使う） | `設定 > アカウント > サインイン オプション > セキュリティ キー` | **非対応**（Entra ID 参加 + WHfB / Intune か GPO で有効化した環境のみ） | サポート対象 |

「Windows Hello セットアップ」というタイトルのダイアログは **Windows サインイン側**の経路です。
（参考: [FIDO2 セキュリティ キーによる Windows へのサインイン](https://learn.microsoft.com/ja-jp/entra/identity/authentication/howto-authentication-passwordless-security-key-windows)）

---

## 6. ファーム側の現状（Microsoft の「互換キー」要求との差）

| # | 要求 | 実装 | 備考 |
| --- | --- | --- | --- |
| 1 | Resident key | ✅ | 5 スロット、`rk: true` を広告 |
| 2 | Client PIN | ✅ | proto 1 / 2、setPIN / changePIN / getPINToken |
| 3 | hmac-secret | ✅ | 登録時の拡張 + 取得時の暗号化 salt |
| 4 | Multiple accounts per RP | ❌ | `authenticatorGetNextAssertion (0x08)` が `0x2A` |
| — | `credMgmt` | ❌ | `0x0A` 未実装（`設定 > セキュリティ キー > 管理` が使う） |
| — | Attestation | ❌ | 自己署名 packed。AAGUID はダミー |

このうち 1〜3 は満たしているので、**サイトのパスキー（Misskey / GitHub / Google 等）では動作します**。
4 と `credMgmt` は今回の症状とは無関係でしたが、Windows の管理 UI を使うなら実装対象です。

### Microsoft アカウントの認定（attestation）の壁

Microsoft は互換性を **FIDO Alliance MDS** で判断し、有効な attestation statement を要求します
（[ベンダー向け要件](https://learn.microsoft.com/en-us/entra/identity/authentication/concept-fido2-hardware-vendor)、
[FIDO2 準拠の要求](https://support.microsoft.com/ja-jp/accounts-billing/work-school/set-up-a-security-key-as-your-verification-method)）。
AAGUID がダミーで x5c を持たないこのキーは、**MSA のパスキー登録ではサーバー側で拒否され得ます**。
ファームのバグではなく、ベンダー認定（ルート CA + MDS 登録）が無いことによる制約です。

---

## 7. 次の実装候補

1. `authenticatorGetNextAssertion (0x08)` — 1 RP に複数資格情報がある場合の列挙
2. `authenticatorCredentialManagement (0x0A)` — `getCredsMetadata` / `enumerateRPs` / `enumerateCredentials` / `deleteCredential`、
   `getInfo` に `credMgmt: true`、PIN トークンの permission `cm (0x04)`
3. `authenticatorLargeBlobs (0x0C)` — EEPROM 1024 バイトの空きは約 10 バイトしかなく、フラッシュ側の設計から要検討
4. 328P のスタック余裕の確認 — `g_ioBuf` 544 + `g_eccHold` 272 + `g_secTmp` 128 + DRBG 72 = 1016 バイトが静的確保で、
   2048 バイトの SRAM ではスタックに 500 バイト前後しか残りません。ウエッジの引き金がここなら、
   `Serial` のバッファ削減（`-D SERIAL_RX_BUFFER_SIZE=32`）や `g_secTmp` の縮小が効きます
