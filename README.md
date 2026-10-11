# Local Agent Authentication Spike

OAuthをローカルエージェントで使うための、独立した技術検証repoです。
実サービスのAS、テナント、ユーザー、credentialは使用しません。
SDKは実際のMCPクライアントですが、ブラウザ操作とissuer・group照会は合成です。

## 実行

```sh
bun install --frozen-lockfile
bun run typecheck
bun test --reporter=junit --reporter-outfile=artifacts/tests.xml
bun run start
```

Bun 1.3.11、公式MCP SDK 1.32.1、jose 6.2.12を固定しています。
必要なら各コマンドを`mise exec --`で起動します。
`start`はloopbackに一時サーバーを起動し、認証と`whoami`を実行して終了します。
通常の対話ログインUIや常駐サービスを提供するコマンドではありません。
秘密はメモリのみ、生成artifactはparameter名・非機密結果のみです。
JUnit XMLには実行ホスト名が入るためgitignore対象にし、公開用には集計結果だけを保存します。

## 最小構成

- `client.ts`: 事前登録public client、公式SDK OAuth/Streamable HTTP、callback URI/stateの検証。
- `issuer.ts`: 合成AS。strict/optional PKCEとrefresh admissionを切り替え、差を実証。
- `security.ts`: joseによる署名/issuer/aud/exp検証、合成claim profile、callback/nonce。
- `lab.ts`: loopback入口、合成live group認可、最小の保護MCP `whoami`。
- `spike.test.ts`: 正常接続と否定試験。`artifacts/test-summary.json`が公開用の実行結果。
- `RESULTS.md`: 1ページ結果。`artifacts/smoke.json`が実SDKの安全な経路記録。

独自テストハーネスや実認証SDKは作りません。標準の`bun test`と公式MCP SDKを使います。
製品実装、社内docs配信、クラウドdeployは含みません。

## 検証の限界

JWTの形状はCognitoに近い`token_use/client_id/scope`に固定した合成profileです。
実Cognitoではcustom scope、JWT issuerとauthorize domainの関係、resource/aud、discoveryを確認します。
Entra直接では別profile（`tid/oid/azp/scp`、API app IDのaud）が必要です。
今回のASはそのどちらのサービスもエミュレートせず、実設定の成立を証明しません。

state検証はcallback受信側の責務です。SDKの`finishAuth(code)`だけでは検証できません。
今回はcallback URLをメモリで処理し、実callback listener・OS/browser・企業端末の挙動は未確認です。
nonce試験はOIDCを使う場合の局所検証です。通常のMCP OAuthフローはID tokenを要求しません。
Bearerの再使用は成功します。PKCE・CAを端末bindingやBearer replay防止と扱えません。

group判定はメモリ上のboolで、Graph API/資格情報/主体mappingは使用していません。
refresh rotationはgraceなしの合成挙動で、実Cognitoのgrace/寿命/失効を再現しません。
`/origin/mcp`の403はローカルroute検証です。別ネットワークoriginの閉塞やIAM/OACの実証ではありません。
署名鍵は起動時生成・固定です。JWKS discovery、鍵rotation、実AS token保存、SSRFの全経路は未検証です。
HTTPはloopback検証限定です。共有環境のHTTPS、証明書、proxy/CORS設計には使えません。

## 実環境へ進む条件

まず既存のissuer/metadata、clientのcallback/scopes、resource/APIの登録、CA対象を正規の読取で確認します。
非秘密IDは共有できてもtoken・secret・tenant設定の生出力は成果物へ含めません。
次の実機試験は、管理者が承認したcompany-managed PCとtest userを使います。
初回のinteractive loginは利用者が行い、MFA・consent・credentialを自動化しません。

既存設定が不足する場合の最小変更候補は以下です。今回はいずれも実施していません。

- Cognito経路: 検証専用public clientとcallback、検証resource/scope、client allowed scopes。
- Entra直接: 検証API登録のidentifier URI/委任scopeとpublic client callback、必要なconsent。
- 端末条件: 検証resourceのEnterprise AppをCA対象にし、承認homeへの必要なtrustのみ確認。

適用するtenant、app/client ID、callback、scope、影響user、CA範囲を特定してから承認を求めます。
新登録・grant・credential・AWS/Entra/Intune設定変更・外部repo作成/pushは承認前に行いません。
