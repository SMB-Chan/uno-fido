# Windows Hello に「このセキュリティ キーは使用できません」と出るとき

対象: `fido_uno_key`（ATmega328P）+ `fido_16u2_hid`（ATmega16U2）構成の DIY FIDO2 キー。

```
Windows Hello セットアップ
このセキュリティ キーは使用できません。別のセキュリティ キーを使用してください。
```

このダイアログは **Windows の WebAuthn スタック（webauthn.dll / CredentialUIBroker.exe）** が出すもので、
CTAP2 のどこで失敗しても **同じ文面** になります。つまり「キーがダメ」とは限らず、

- Windows 側の設定で止まっている
- ファームが返したステータスが期待外（未実装コマンド・PIN 検証・容量不足など）
- Microsoft アカウント側がキーを認定していない（＝キーの責任ではない）

のどれでも同じ画面になります。**まずどこで止まっているかを確定させる**のが本ドキュメントの目的です。

診断: [`tools/Get-WebAuthnTrace.ps1`](../tools/Get-WebAuthnTrace.ps1)（読み取りのみ・変更なし）

```powershell
# 管理者の PowerShell で
powershell -ExecutionPolicy Bypass -File .\tools\Get-WebAuthnTrace.ps1 -Mode Both -Clear -EnableLog
# → 120 秒の待ち時間の間に、エラーを 1 回だけ再現する
```

出力の `REQ` が Windows が投げた CTAP2 コマンド、`RES` がキーが返したステータスです。
[読み方の表](#4-トレースの読み方)で原因がほぼ確定します。

---

## 1. 前提: 個人の Microsoft アカウントで「Windows へのサインイン」は原則できない

いちばん多い落とし穴です。

| やりたいこと | 使う画面 | 個人の Microsoft アカウント | 職場/学校 (Entra ID) |
| --- | --- | --- | --- |
| **Web のパスキー**（Microsoft アカウントのセキュリティ情報に追加） | `account.microsoft.com` → セキュリティ → 「サインイン方法の追加」 | 公式サポート対象 | サポート対象 |
| **Windows へのセキュリティキーサインイン**（ロック画面でキーを使う） | `設定 > アカウント > サインイン オプション > セキュリティ キー` | **非対応**（Entra ID 参加 + Windows Hello for Business / Intune か GPO で有効化した環境のみ） | サポート対象 |

「Windows Hello セットアップ」というタイトルのダイアログは **この Windows サインイン側**の経路です。
個人アカウントでここを開くと、キーが正常でも `このセキュリティ キーは使用できません` で止まることがあります。
（参考: [Microsoft Entra: FIDO2 セキュリティ キーによる Windows へのサインイン](https://learn.microsoft.com/ja-jp/entra/identity/authentication/howto-authentication-passwordless-security-key-windows)）

**確認してほしいこと**: エラーが出たのは
`設定 > アカウント > サインイン オプション > セキュリティ キー > 管理` ですか？
それとも `account.microsoft.com` の「サインイン方法の追加」ですか？
後者で失敗しているなら、原因はファームではなく **キーの認定（attestation）** の可能性が高いです（[5 章](#5-microsoft-アカウントが要求する認定attestationの壁)）。

---

## 2. Windows 側で先に潰すべき既知の問題

ファームを疑う前に、**YubiKey でも同じ症状になる**既知の問題を確認してください。

1. **パスキー許可がオフ**（Windows 11 24H2 以降）
   `設定 > プライバシーとセキュリティ > パスキー` の「アプリでのパスキーの作成と使用を許可する」がオンか。
   ここがオフだと、U2F のセキュリティキーでも **Windows セキュリティのダイアログ自体が出ず**に失敗します。
   （スタートメニューの検索で "passkeys" と打つと `アカウント > パスキー` という別画面に飛ぶので注意）
2. **Windows 11 24H2 のビルド不具合**
   build `26100.4652` 〜 `26100.6584` 未満では、`セキュリティ キー > 管理` で PIN 変更や管理が失敗します。
   **KB5065426（build 26100.6584）で修正済み**。
   （参考: [Yubico サポート](https://support.yubico.com/hc/en-us/articles/21190316012444--resolved-Windows-Account-Management-in-Windows-11-24H2-Unable-to-manage-FIDO-application-on-Security-Key-YubiKey-or-YubiKey-Bio)）
3. **サードパーティ製の認証プロバイダー**
   Duo Security、Kensington / VeriMark のソフト、生体認証ドライバなどが Hello を乗っ取ることがあります。
   スクリプトの `[注意] サードパーティ製の認証プロバイダー` に出たら一旦アンインストール。
4. **「Microsoft アカウント用に Windows Hello サインインのみを許可する」がオン**
   `設定 > アカウント > サインイン オプション > 追加の設定` のトグル。オフにして再試行。
5. **スロット満杯 / 既存資格情報の衝突**
   このキーは EEPROM に **5 スロット**しか持ちません。過去のテストで埋まっていると
   `0x28 (KEY_STORE_FULL)`、同じ RP の資格情報が残っていると `0x19 (CREDENTIAL_EXCLUDED)` を返します。
   Windows はどちらも「このセキュリティ キーは使用できません」に丸めます。
   `web_app/index.html` の 🗑️ **鍵リセット**（`CTAP2 07` = authenticatorReset）で初期化してから試してください。

---

## 3. ファーム側の現状（Microsoft の「互換キー」要求との差）

Microsoft は Windows で使うキーに次の 4 機能を **必須** としています
（[Microsoft-compatible security key](https://learn.microsoft.com/en-us/windows/security/identity-protection/hello-for-business/microsoft-compatible-security-key)）。

| # | 要求 | このリポジトリの実装 | 備考 |
| --- | --- | --- | --- |
| 1 | Resident key（discoverable credential） | ✅ | `MAX_SLOTS = 5`、`rk: true` を広告 |
| 2 | Client PIN | ✅ | PIN/UV Auth Protocol 1 と 2、setPIN / changePIN / getPINToken(0x05,0x09) |
| 3 | hmac-secret | ✅ | makeCredential の拡張 + getAssertion の暗号化 salt |
| 4 | Multiple accounts per RP | ❌ | `authenticatorGetNextAssertion (0x08)` が `0x2A` を返すだけ |
| — | `credMgmt`（`設定 > セキュリティ キー > 管理` が使う） | ❌ | `authenticatorCredentialManagement (0x0A)` 未実装 |
| — | `largeBlobs` | ❌ | 未広告 |
| — | Attestation（認定・x5c 証明書チェーン） | ❌ | 自己署名の packed attestation。AAGUID はダミー |

`getNextAssertion` と `credMgmt` は **Windows / Chrome の実装が「あれば使う」** もので、
無いこと自体が即エラーになるとは限りません。ただし Windows 11 の
`セキュリティ キー > 管理` とパスキー一覧は `credMgmt` を前提にしています。
トレースで `0x0A` や `0x08` に `0x2A` が返っていれば、ここが直接の原因です。

---

## 4. トレースの読み方

`RES`（キーが返した 1 バイト目）で判断します。

| RES | 名前 | 意味 / 次の手 |
| --- | --- | --- |
| `0x00` | OK | そのコマンドは成功。失敗しているのは**別のコマンド**（REQ を遡る） |
| `0x2A` | UNSUPPORTED_OPTION | `REQ` が `0x08` なら getNextAssertion 未実装、`0x0A` なら credMgmt 未実装 → **ファームで実装可能** |
| `0x28` | KEY_STORE_FULL | 5 スロット満杯 → 鍵リセット |
| `0x19` | CREDENTIAL_EXCLUDED | 既存資格情報と衝突 → 鍵リセット |
| `0x2D` | NO_CREDENTIALS | look up 対象なし（Windows 側が RP ID を取り違えている場合も） |
| `0x31` / `0x35` | PIN_INVALID / PIN_NOT_SET | PIN/UV の状態不整合 |
| `0x33` | PIN_AUTH_INVALID | pinUvAuthParam の検証、または RP バインド（`PIN_RP_ADDR`）で失敗 → **ファーム要修正** |
| `0x39` | REQUEST_TOO_LARGE | 512 バイト超（Windows Hello の makeCredential は長くなりがち） |
| `0x7F` | ファーム内部エラー | 乱数・uECC・署名の失敗。LED が点滅していないか確認 |

`REQ` が `0x04`（GetInfo）で止まる → Windows 側（プロバイダー無効・パスキー許可オフ）。
イベントが 1 件も出ない → ダイアログがキーに到達していない（USB / 16U2 / プロバイダー）。

---

## 5. Microsoft アカウントが要求する認定（attestation）の壁

Microsoft は、パスキー/セキュリティキーの互換性を **FIDO Alliance Metadata Service (MDS)** で判断します。
ベンダーは MDS にメタデータを登録し、キーは **有効な attestation statement** を返す必要があります。
（[Microsoft Entra: FIDO2 セキュリティ キーのベンダー向け attestation 要件](https://learn.microsoft.com/en-us/entra/identity/authentication/concept-fido2-hardware-vendor)、
[FIDO2 準拠の要求](https://support.microsoft.com/ja-jp/accounts-billing/work-school/set-up-a-security-key-as-your-verification-method)）

このキーは AAGUID が `ELEGOO_UNO_FIDO2` のダミーで、attestation は自己署名（x5c なし）です。
そのため **Microsoft アカウントのパスキー登録では、サーバー側で拒否され得ます**。
これはファームのバグではなく、ベンダー認定（＝ベンダーのルート CA と MDS 登録）が無いことによる制約で、
個人が回避するのは現実的ではありません。

一方、**WebAuthn の RP が attestation を要求しないサイト（Misskey / GitHub / Google など）では普通に使えます**
（このリポジトリでもブラウザ経由の登録・ログインは成功している）。

---

## 6. それでも Windows 側で使いたい場合のロードマップ

トレースで「ファーム起因」と確定した場合、優先度順に次を実装できます。

1. `authenticatorGetNextAssertion (0x08)` — 1 RP に複数資格情報がある場合の列挙。
   `getInfo` の `maxCredentialCountInList` を 8 以上に広げるのが望ましい（CTAP2.1 の推奨）。
2. `authenticatorCredentialManagement (0x0A)` — `getCredsMetadata` / `enumerateRPs` / `enumerateCredentials` / `deleteCredential`。
   `getInfo` の `options` に `credMgmt: true` を追加。Windows の「セキュリティ キーの管理」が使えるようになります。
   PIN トークンの permission `cm (0x04)` の受け入れも必要。
3. `authenticatorLargeBlobs (0x0C)` — `credMgmt` とセットで広告するのが一般的。
   （32KB のフラッシュに収まるかは要調整。EEPROM 1024 バイトのうち空きは約 80 バイトしかありません）
4. `options.uv` / `pinUvAuthToken` の組み合わせの再確認、`transports: ["usb"]` の広告。

1〜2 は「Windows の管理 UI が動く」ところまで到達できますが、
**3〜4 を足しても MSA の認定要件は満たせません**（5 章）。
したがって現実的なゴールは、

- サイトのパスキー（Chrome / Edge / Misskey など）: **このキーで運用**
- Windows へのサインイン / Microsoft アカウントのパスキー: **認定キー（YubiKey 等）を使う**

という住み分けです。
