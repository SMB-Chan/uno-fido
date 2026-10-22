# uno-fido

Elegoo Uno R3（ATmega328P + ATmega16U2 を USB HID 化）で動く FIDO2 / CTAP2 セキュリティキー。

| ディレクトリ | 内容 |
| --- | --- |
| `fido_uno_key/` | 328P 側の CTAP2 実装（makeCredential / getAssertion / clientPIN / hmac-secret / credProtect） |
| `fido_16u2_hid/` | 16U2 を HID ブリッジにするファーム（`build_16u2.ps1` で `.hex` を再生成 → `flash_16u2_fido_hid.ps1` で書き込み） |
| `web_app/` | 実験用ラボ（ブラウザ標準 WebAuthn と、シリアル経由の CTAP2 生コマンド） |
| `test_connection/`, `fido_probe/` | シリアル接続の確認用スクリプトと HID プローブ |
| `docs/` | トラブルシューティング |
| `tools/` | 診断スクリプト |

## Windows Hello に登録できないとき

`このセキュリティ キーは使用できません。別のセキュリティ キーを使用してください。`
は Windows の WebAuthn スタックが返す汎用エラーです。原因の切り分け手順は
[docs/windows-hello.md](docs/windows-hello.md) にまとめてあります。

```powershell
# 管理者の PowerShell で（読み取りのみ）
powershell -ExecutionPolicy Bypass -File .\tools\Get-WebAuthnTrace.ps1 -Mode Both -Clear -EnableLog
```

120 秒の間にエラーを 1 回再現すると、Windows が投げた CTAP2 コマンドと
キーが返したステータス（`0x28` / `0x2A` / `0x33` …）が表示されます。

**1 バイトだけの `0x7F` は 16U2 が合成した値**で、328P が無応答であることを意味します。
16U2 はこの状態を検出すると 328P を自動でリセットして復帰させます（`docs/windows-hello.md` 2 章）。
