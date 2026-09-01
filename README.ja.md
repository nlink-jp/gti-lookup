# gti-lookup

Google Threat Intelligence (GTI) から、インジケーターにキュレート済みの
**脅威アクター文脈**を付ける CLI 兼ローカル MCP サーバ。

> **Status: 開発中・未リリース。** スキャフォールド（設定・結果キャッシュ・
> MCP ハンドシェイク・`cache` コマンド）は動作します。lookup 系コマンド
> （`search` / `threat` / `ioc`）は未実装です。設計は
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
gti-lookup search <query>           脅威の検索（アクター/キャンペーン/ファミリー…）
gti-lookup threat <collection-id>   collection のキュレート済みレポート; --related でピボット
gti-lookup ioc <value>              ハッシュ/ドメイン/IP/URL のアクター文脈
gti-lookup cache status|clear       結果キャッシュの確認・削除
gti-lookup mcp                      ローカル MCP サーバとして起動 (stdio)
gti-lookup version                  バージョン表示
```

このビルドでは `search` / `threat` / `ioc` はプレースホルダで、その旨を
表示してエラー終了します。

## MCP サーバ

`gti-lookup mcp` は stdio で MCP を話します。このビルドが公開するのは
`cache_status` と `get_usage` で、lookup 系ツールはエンジンと共に実装されます。
`get_usage` は組み込みマニュアルを返す正典のツールリファレンスです。

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
