# RFP: gti-lookup

> Generated: 2026-09-01
> Status: Draft

## 1. Problem Statement

既存の lookup 群は IOC の評判やコミュニティ由来のキャンペーン文脈（otx-lookup）までは
引けるが、Mandiant/Google 由来のキュレートされた**脅威アクター情報**が不足している。
正規 Google Threat Intelligence (GTI) ライセンス保有環境において、IOC やキーワードから
脅威アクター・キャンペーン・マルウェアファミリー情報を照会し、IR/脅威調査に文脈を
付加する。

オリジナル（google/mcp-security の server/gti）は uvx 実行・他社製 Python コードという
構成が組織基準に適合せず、環境展開性にも難があるため、cybersecurity-series lookup 群の
流儀（Go 単一バイナリ、CLI 兼 MCP、読み取り専用、構造化エラー、TTL キャッシュ）で
読み取り専用サブセットを再実装する。

対象ユーザーは組織内の IR/脅威調査ワークフロー（mcp-tactics 経由の Claude Code 利用
を含む）。

## 2. Functional Specification

### Commands / API Surface

**MCP ツール**（オリジナル約 36 ツールを 10 前後に集約）:

| ツール | 内容 | 元ツール | Phase |
|---|---|---|---|
| `search_threats(query, collection_type?, limit?, order_by?)` | collections 横断検索。`collection_type` enum: `threat-actor` / `campaign` / `malware-family` / `software-toolkit` / `report` / `vulnerability` / `all` | search_* 7 本を 1 本に集約 | 1 |
| `get_threat(id)` | collection ID → キュレート済みレポート（別名・標的業種/国・ATT&CK・出典・時期） | get_collection_report | 1 |
| `get_threat_related(id, relationship, limit?)` | collection の関連エンティティ（配下 IOC・関連アクター等） | get_entities_related_to_a_collection | 1 |
| `lookup_ioc(value, full?)` | hash/domain/IP/URL を自動判別。既定は `gti_assessment` + `associations` 中心の絞った応答、`full: true` でフルレポート | get_{file,domain,ip,url}_report 4 本を集約 | 1 |
| `get_ioc_related(value, relationship, limit?)` | IOC の relationship ピボット（contacted_* 等） | get_entities_related_to_a_* 4 本を集約 | 1 |
| `search_iocs(query, limit?, order_by?)` | GTI クエリ構文の intelligence 検索 | search_iocs | 2 |
| `get_threat_rules(collection_id, top_n?)` | collection に紐づく YARA/Sigma ルール | get_collection_rules | 2 |
| `get_hunting_ruleset(ruleset_id)` | hunting ruleset 直引き | get_hunting_ruleset | 2 |
| `cache_status()` | キャッシュ状態（シリーズ標準装備） | — | 1 |
| `get_usage()` | ツールリファレンス + エラー回復表（シリーズ標準装備） | — | 1 |

- IOC 種別の自動判別: hex 桁数 32/40/64 → MD5/SHA1/SHA256、IP/ドメイン/URL は形式判定
  （malware-lookup と同じ単一入力口の流儀）
- `relationship` 受け口は**厳選 enum + 自由文字列の併用**: アクター調査に効く主要
  relationship（associations、contacted_*、配下 IOC 等 10〜15 種）を enum で提示しつつ、
  GTI 側の任意名も通せる口を残す
- `lookup_ioc` の既定応答を絞るのは MCP 応答予算と既存 lookup 群との棲み分けのため。
  フルレポートは opt-in（otx-lookup の「機能は持つが既定オフ」方式）

**CLI**（MCP と鏡像のサブコマンド構成）:

```
gti-lookup search <query> [--type threat-actor|campaign|...] [--limit N]
gti-lookup threat <collection-id> [--related <relationship>]
gti-lookup ioc <value> [--full] [--related <relationship>]
gti-lookup rules <collection-id>          # Phase 2
gti-lookup hunting <ruleset-id>           # Phase 2
gti-lookup search-iocs <query>            # Phase 2
gti-lookup cache-status
```

### Input / Output

- 入力は引数 1 件照会（単発〜数十件想定。バルク最適化はスコープ外）
- 出力は JSON を stdout へ（jq フレンドリー）。診断は stderr
- exit 契約: 0 = 照会完了 / 1 = 上流障害（結果は出力） / 2 = 使用法エラー
  （malware-lookup と同契約）
- MCP ツールエラーは構造化 JSON `{code, message, details?}`

### Configuration

- `~/.config/gti-lookup/config.toml`（api_key、cache TTL、timeout）+ 環境変数
  override。macOS でも `~/.config` を探索する組織規約に従う
- キャッシュ TTL は対象別: collection レポートは長め、IOC assessment は短め。
  degraded 結果はキャッシュしない
- サンプル設定のキー値はプレースホルダ形式のみ（実キー・環境固有値は非コミット）

### External Dependencies

- GTI API v3（`https://www.virustotal.com/api/v3`）のみ。認証は `x-apikey` ヘッダ
- vt-py 相当の SDK は使わず Go 標準 net/http で REST 直叩き（splunk-mcp の前例）

## 3. Design Decisions

- **言語 = Go**: 再実装の動機そのもの。他社 Python + uvx 構成の排除、単一バイナリでの
  環境展開、既存の署名/notarize/tap リリースパイプラインへの合流
- **骨格**: data-toolbox-mcp の `internal/{transport,jsonrpc,mcpserver,toolerr}` を移植
  （正典は nlink-jp/knowledge の mcp-server-design.md）。tool ハンドラ層と GTI
  クライアントは新規実装
- **検索 7 ツールの 1 本集約**: 実体は同一 endpoint の type フィルタ違い。ツール一覧の
  トークン消費も抑える
- **補完関係**:
  - otx-lookup（コミュニティ由来のキャンペーン文脈）に対する Google/Mandiant
    キュレート文脈の担い手
  - malware-lookup（無ライセンス環境用の無償 3 ソース verdict）とは並存。
    gti-lookup は正規ライセンス保有環境専用
  - `lookup_ioc --full` は既存 lookup 群と重複する情報も返しうるが、既定応答を
    絞ることで共存する
- **明示的スコープ外**: 書き込み系（create/update collections、update_iocs_in_collection）、
  analyse_file（検体の第三者アップロード = OpSec 上の重大行為）、DTM 検索、
  threat profiles、collection timeline / MITRE tree（Phase 2 で採否判断）、
  バルク最適化、検体ダウンロード

## 4. Development Plan

### Phase 1: Core

- config ローダ / TTL キャッシュ / GTI REST クライアント
- `search_threats` / `get_threat` / `get_threat_related` / `lookup_ioc` /
  `get_ioc_related` / `cache_status` / `get_usage`
- CLI サブコマンド（search / threat / ioc / cache-status）
- テスト: httptest モックでのユニット + 応答整形（tests は必須、pure function +
  injected dependencies で設計）

### Phase 2: Features

- `search_iocs` / `get_threat_rules` / `get_hunting_ruleset`
- collection timeline / MITRE tree の採否判断
- live 実測 → AGENTS.md Gotchas へ反映（API 実挙動と公式ドキュメントのズレを記録）

### Phase 3: Release

- README.md / README.ja.md、CHANGELOG.md
- make build-all → 署名・notarize → homebrew-tap
- umbrella（cybersecurity-series）submodule 追加、org profile 更新
- **mcp-tactics 追随**（サーバ増減の追随義務）
- check-org.sh green

各 Phase は独立レビュー可能。

## 5. Required API Scopes / Permissions

- GTI ライセンス付き API キー 1 つのみ（`x-apikey` ヘッダ）。OAuth / IAM ロール不要
- 正規ライセンス保有環境で実行する前提（無償 VT API の規約問題は対象外 —
  その環境には malware-lookup が既にある）

## 6. Series Placement

Series: **cybersecurity-series**
Reason: lookup 群（asn/whois/abuse/otx/malware-lookup 等）の姉妹品。読み取り専用の
脅威情報照会ツールであり、シリーズの流儀（CLI 兼 MCP、構造化エラー、TTL キャッシュ、
get_usage、OpSec 明示）にそのまま合流する。

## 7. External Platform Constraints

- クォータ・レート制限はライセンス階梯依存。429 は構造化エラーで返し、degraded
  結果はキャッシュしない
- レポートオブジェクトが非常に大きい → attributes / relationships の厳選が必須
  （MCP 応答全体に予算を設ける）
- collection ID は `threat-actor--<hash>` 等の型付き形式。検索は GTI 独自クエリ構文
- DTM / threat profiles 等はライセンス階梯依存機能（本ツールではスコープ外）
- API 仕様の正典は gtidocs.virustotal.com。実測とズレたら AGENTS.md Gotchas に記録

---

## Discussion Log

- **目的の確定**: 要望は「脅威アクター情報の追加」。既存 lookup 群にない
  キュレート済みアクター文脈が動機。SCC / SecOps / SOAR サーバは対象外
- **再実装の動機**: uvx 実行 + 他社提供 Python コードが組織基準に不適合。
  Go 単一バイナリへの転換で環境展開性を確保
- **ライセンス**: 正規 GTI ライセンス保有環境で実行するため問題なし
- **名称**: `gti-intel` は GTI の "I" が既に intelligence で重言のため却下 →
  `gti-lookup` で確定（lookup 群の命名パターンに合致）
- **スコープ**: collections 系 + IOC レポートの両方向を採用（IOC → associations で
  アクターへ逆引き）。search_iocs / hunting rulesets は含める、DTM は除外。
  書き込み系 + analyse_file は除外で確定
- **検索ツール集約**: search_* 7 本 → `search_threats` 1 本 + `collection_type` enum
- **lookup_ioc の応答方針**: 当初案は assessment + associations に絞る（otx-lookup の
  棲み分け原則）だったが、正規ライセンスの価値を活かすためフルレポートも取得可能に。
  折衷として「既定は絞った応答、`full` パラメータで opt-in」を採用
- **relationship 受け口**: 厳選 enum + 自由文字列の併用（オリジナルは file だけで
  50 種以上列挙 → モデルの推測リスクと応答予算から厳選提示）
- **提供形態**: シリーズ慣例どおり CLI 兼 MCP
