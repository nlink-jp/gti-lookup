# gti-lookup

Google Threat Intelligence (GTI) の脅威情報を引く CLI 兼ローカル MCP サーバ。
**GTI Standard ティアの機能セット**を搭載しています。

> 設計: [docs/ja/gti-lookup-rfp.ja.md](docs/ja/gti-lookup-rfp.ja.md)。
> RFP 以降のスコープ判断は AGENTS.md に記録しています。実 GTI API に対して
> live 検証済みです。

姉妹の lookup 群がそれぞれ無償ソースから 1 つの問いに答えるのに対し、
本ツールは正規ライセンスキーで Google のインデックスを読みます:
インジケーターがどのコミュニティ報告脅威に**関連づく**か、検体が Google の
サンドボックスでどう**振る舞う**か、GTI クエリ構文でのコーパス横断
**IOC 検索**、relationship ピボットと ATT&CK ツリー付きの**脆弱性
カタログ**、そして自アカウントの **LiveHunt ルールセット**。

読むのは Google のインデックスだけなので、**調査対象にはパケットが一切
届きません**。また本ツールは**設計として読み取り専用**です — collection・
ルールセットへの書き込みと検体アップロードは恒久的にスコープ外です。

## 必要なもの

**商用の Google Threat Intelligence アカウントが必須です。** 本ツールは
lookup シリーズの中で例外です: 姉妹ツールはアカウント不要
（rdns-lookup / doh-lookup / tor-exit-lookup / whois-lookup など）または
無償 API キーで動作します（abuse-lookup / otx-lookup / malware-lookup）が、
gti-lookup は**有償の GTI ライセンス**とその API キーなしには何もできません。
無償の VirusTotal ティアでは不十分で、匿名モードや無償の縮退モードも
ありません。また、すべてのクエリはライセンス保有者のアカウントに記録されます。

**搭載するのは GTI Standard ティアの機能セットです。** Enterprise 限定の
カタログ — キュレート済み脅威アクター・キャンペーン・レポート・threat
profiles・DTM — は意図的にスコープ外です: Standard ライセンスでは実行
（=テスト）できず、テストできない機能はリリースしないためです。脅威文脈は
インジケーターが関連づくコミュニティコレクション経由で得られます。

## インストール

Homebrew（macOS arm64、Apple notarize 済みビルド）:

```bash
brew install nlink-jp/tap/gti-lookup
```

または [releases ページ](https://github.com/nlink-jp/gti-lookup/releases)
からプラットフォーム別アーカイブを取得してください（darwin-arm64 zip は
notarize 済み、linux amd64/arm64 tar.gz、windows amd64 zip）。

ソースからのビルド:

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
gti-lookup search <query> [--type vulnerability] [--order relevance-]
gti-lookup search-iocs <query> [--order last_submission_date-]
gti-lookup threat <collection-id> [--related <name> | --related-other <name> | --mitre]
gti-lookup ioc <value ...> [--full] [--related <name> | --related-other <name>]
gti-lookup behaviour <hash> [--section <name>] [--offset N]
gti-lookup hunting [ruleset-id]
gti-lookup cache status|clear
gti-lookup mcp
gti-lookup version
```

- `search` はコレクションカタログの検索（Standard では vulnerability）
- `search-iocs` は GTI intelligence 構文での IOC コーパス検索
  （`entity:file`、`p:60+`、`fs:2024-01-01+`、`tag:` など）
- `threat` は collection 1 件のレポート。`--related` でピボット、
  `--mitre` で ATT&CK 戦術/技術ツリー
- `ioc` は形状からインジケーター種別を自動判別（MD5/SHA1/SHA256・IP・
  ドメイン・URL）し、関連脅威（ライセンスが提供する場合は
  `gti_assessment` も）を返します。複数値は順次処理（`--json` は JSONL）。
  `--full` でフルレポートに opt-in
- `behaviour` はサンドボックス挙動サマリ: まず区画の索引（サマリ全体は
  2 MB を超えうる）、`--section` / `--offset` / `--limit` で 1 区画を
  ページング
- `hunting` は自アカウントの LiveHunt ルールセット一覧・詳細（YARA 本文
  込み）。常に live・キャッシュしないので「ルールは反映されたか？」に
  答えます
- 共通フラグ: `--json` / `--refresh`（キャッシュ迂回）/ `--limit` /
  `--timeout` / `--config`
- exit code: 0 = 回答完了（空回答も正答）、1 = 上流障害による欠落・劣化
  （出力に `INCONCLUSIVE`）、2 = 使用法・設定エラー

## MCP サーバ

`gti-lookup mcp` は stdio で MCP を話し、`search_threats` / `search_iocs` /
`get_threat` / `get_threat_related` / `get_threat_mitre_tree` /
`lookup_ioc` / `get_ioc_related` / `get_file_behaviour` /
`list_hunting_rulesets` / `get_hunting_ruleset` / `cache_status` /
`get_usage` を公開します。`get_usage` が返す組み込みマニュアルが正典の
ツールリファレンスで、エラー回復表も含みます。ツールエラーは構造化 JSON
（`{code, message}`）。大きな応答はツール境界で予算管理します:
`get_threat` は description に上限（`description_max` で解除）、
`get_threat_mitre_tree` は既定コンパクト（`full: true` で解除）、
`get_file_behaviour` は索引→区画展開の 2 段構えです。

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
