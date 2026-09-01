# gti-lookup

Google Threat Intelligence (GTI) から、インジケーターにキュレート済みの
**脅威アクター文脈**を付ける CLI 兼ローカル MCP サーバ。

> **Status: 開発中・未リリース。** 中核（`search` / `threat` / `ioc`、MCP
> サーバ、キャッシュ）は実装・オフラインテスト済みです。実 GTI API に対する
> live 検証が未了です。設計は
> [docs/ja/gti-lookup-rfp.ja.md](docs/ja/gti-lookup-rfp.ja.md) で確定しています。

姉妹の lookup 群が公開・コミュニティソースから答えるのに対し
（`otx-lookup` はコミュニティのキャンペーン報告を読む）、本ツールは
Mandiant/Google のキュレート済みカタログを読みます: インジケーターがどの
**脅威アクター**・**キャンペーン**・**マルウェアファミリー**に関連づくか、
そのアクターは誰を標的にするか、どのレポートが記述しているか。
アクター → IOC と IOC → アクターの双方向で引けます。

読むのは Google のインデックスだけなので、**調査対象にはパケットが一切
届きません**。また本ツールは**設計として読み取り専用**です — collection への
書き込みと検体アップロードは恒久的にスコープ外です。

## 必要なもの

- **Google Threat Intelligence ライセンス**とその API キー。無償の
  VirusTotal ティアでは不十分です。またすべてのクエリはライセンス保有者の
  アカウントに記録されます。

## インストール

未リリースのため、ソースからビルドしてください。

```bash
make build        # → dist/gti-lookup
```

## 設定

[config.example.toml](config.example.toml) を
`~/.config/gti-lookup/config.toml` にコピーし、API キーを設定します。
環境変数がファイルより優先されます: `GTI_LOOKUP_API_KEY`（または Google の
GTI ツール群が使う `VT_APIKEY`）、`GTI_LOOKUP_BASE_URL`、
`GTI_LOOKUP_THREAT_TTL_HOURS`、`GTI_LOOKUP_IOC_TTL_HOURS`、
`GTI_LOOKUP_TIMEOUT_SECONDS` など — 全設定は example ファイルに説明があります。

## コマンド

```
gti-lookup search <query> [--type threat-actor] [--order relevance-] [--limit N]
gti-lookup threat <collection-id> [--related <name> | --related-other <name>]
gti-lookup ioc <value ...> [--full] [--related <name> | --related-other <name>]
gti-lookup cache status|clear
gti-lookup mcp
gti-lookup version
```

- `search` はキュレート済みカタログの検索。`--type` で種別を絞ります
  （threat-actor / malware-family / campaign / report / software-toolkit /
  vulnerability / collection）
- `threat` は collection 1 件のレポート。`--related` で関連へピボット
  （associations, domains, files, hunting_rulesets, ...）
- `ioc` は形状からインジケーター種別を自動判別（MD5/SHA1/SHA256・IP・
  ドメイン・URL）し、GTI の `gti_assessment` と関連脅威を返します。複数値は
  順次処理（`--json` は JSONL）。既定はアクター文脈に絞った応答で、
  `--full` でフルレポートに opt-in
- 共通フラグ: `--json` / `--refresh`（キャッシュ迂回）/ `--limit` /
  `--timeout` / `--config`
- exit code: 0 = 回答完了（空回答も正答）、1 = 上流障害による欠落・劣化
  （出力に `INCONCLUSIVE`）、2 = 使用法・設定エラー

## MCP サーバ

`gti-lookup mcp` は stdio で MCP を話し、`search_threats` / `get_threat` /
`get_threat_related` / `lookup_ioc` / `get_ioc_related` / `cache_status` /
`get_usage` を公開します。`get_usage` が返す組み込みマニュアルが正典の
ツールリファレンスで、エラー回復表も含みます。ツールエラーは構造化 JSON
（`{code, message}`）。`get_threat` はツール応答内の description に上限を
かけます（切り捨ては計上され、`description_max` で解除可能）。

## ドキュメント

- [設計 (RFP)・日本語](docs/ja/gti-lookup-rfp.ja.md) /
  [English](docs/en/gti-lookup-rfp.md)

## 謝辞

ツール表面の設計は Google の
[mcp-security](https://github.com/google/mcp-security) GTI サーバ
（Apache-2.0）を参照しました。本プロジェクトは独立した Go 実装で、
コードの共有はありません。

## ライセンス

MIT — [LICENSE](LICENSE) を参照。
