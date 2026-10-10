# 同济导航 · Tongji Life

https://tongji.hachile.org — 同济校园站点导航与一次性账号认证证明码。

布局参考 [SmartHypercube/ustclife](https://github.com/SmartHypercube/ustclife)，感谢 Hypercube 与贡献者。页面、样式及后端为独立实现，未复制上游源码、图片或图标。本地 `ustclife/` 保留作参考，不提交、不部署。

## 当前状态

导航页面可以部署到 GitHub Pages。**正式认证尚未开放**：未申请同济开放平台应用，`public/config.js` 的 API 地址为空，Worker 默认 `AUTH_ENABLED=false`。不会生成模拟有效码，也不会使用官方文档里的演示客户端认证真实用户。

[官方学生申请指南](https://api.tongji.edu.cn/docs/intro/apply/student_apply)目前不向个人开发者开放；学生组织自建应用应由指导教师按教职工流程申请。获批后需完成官方环境联调，才可启用。

## 本地检查

需要 Node.js 24（测试使用内置 SQLite），不需要前端构建工具。

```powershell
cd D:\Desktop\hachile-workspace\tongji.hachile.org\worker
npm ci
npm test
cd ..
node tools/check.mjs
```

预览：任意静态服务器以 `public/` 为根目录，例如 `npx --yes http-server public -p 8080`。

## GitHub Pages

仓库 Settings → Pages → Source 选 **GitHub Actions**。`.github/workflows/pages.yml` 测试后仅发布 `public/`；Worker、配置模板及参考仓库不出现在网页部署产物里。

Cloudflare DNS 添加 `CNAME`：名称 `tongji`，目标 `gpddev.github.io`，先用 DNS only。Pages 设置 Custom domain 为 `tongji.hachile.org`，DNS 校验完成后开启 Enforce HTTPS。

## 获批后的后端配置

架构：GitHub Pages 前端 + Cloudflare Worker + D1。**禁止把学校 client_secret 填进前端或提交到 GitHub。**

1. 请学校为获批应用登记精确回调：`https://tongji-api.hachile.org/auth/callback`。只请求 `openid`，确认 S256 PKCE、`prompt=login` / `max_age=0` 和签名 ID token 的 `sub`、`aud`、`iss`、`exp`、`iat`、`nonce`、`auth_time` 声明可用。官方 OIDC discovery 当前明确支持 S256；具体获批应用仍需联调。无需申请学生档案、成绩、联系方式等数据权限。
2. 在 `worker/` 中执行 `npx wrangler login`、`npx wrangler d1 create tongji-identity`。
3. 复制 `wrangler.example.jsonc` 为 `wrangler.jsonc`，填 D1 UUID 和学校分配的 `CLIENT_ID`。该文件被 gitignore 忽略。保持 `AUTH_ENABLED=false`。Rate Limiter 的 `namespace_id` 在你的 Cloudflare 账号内必须唯一。
4. 执行 `npx wrangler secret put CLIENT_SECRET`，在终端安全输入密钥；执行 `npx wrangler d1 migrations apply tongji-identity --remote`、`npm run deploy`。配置里的 Custom Domain 会将接口绑定到 `tongji-api.hachile.org`。
5. 在受控联调中启用 `AUTH_ENABLED=true`，实测正确登录、取消授权、过期/错配 state、PKCE、签名/issuer/audience/nonce/auth_time 校验、重复回调、并发/重复核验、10 分钟过期及学校会话行为。任一声明或能力不符合要求时应保持关闭，不可直接删除校验绕过失败。
6. 联调通过后在 `public/config.js` 填 `https://tongji-api.hachile.org` 并提交。前端 CSP 和后端来源白名单均限定此正式域名及 `https://tongji.hachile.org`。

`npm run check -- --config wrangler.example.jsonc` 可以仅校验/打包模板，不发布、不连接生产数据库。

## API 与数据

| 路径 | 功能 |
| --- | --- |
| GET `/api/config` | 是否启用、有效期、一次性属性 |
| GET `/auth/start?consent=1` | 设置短期 Cookie，生成 state、nonce、PKCE 后跳转学校 |
| GET `/auth/callback` | 原子消耗 state，服务端换令牌并验证签名和声明；通过 fragment 返回证明码 |
| POST `/api/verify` | JSON `{ "code": "TJ-…" }`，原子消耗证明码，返回状态和时间 |

证明码含 128 位随机熵，有效 600 秒。D1 只存 SHA-256 码哈希和时间；没有姓名、学号、userid、sub 或原始令牌。会话存 state 哈希、nonce、PKCE verifier 与有效期。每 10 分钟 Cron 和每次认证开始时清理过期记录。验证使用 `DELETE ... RETURNING`，并发请求最多一次成功。

浏览器仅在内存中显示证明码，刷新丢失；URL fragment 到达后立即清除，不进入请求路径。OAuth state Cookie 使用 `__Host-`、Secure、HttpOnly、SameSite=Lax。学校令牌只短暂存在 Worker 内存，异常不输出令牌或上游错误。限流以 IP 哈希和路由为键，30 次/分钟/Cloudflare 机房，校园共享 NAT 可能需要调整；这不是全局精确限额。Worker 不启用请求日志；平台自身网络日志与备份按提供商政策处理。

证明只说明一次同济账号认证已完成，不能证明出示者是本人、仍然在读或属于某个院系。若核验请求中途断网，证明码可能已被消耗，需重新认证。正式学籍验证应使用学校签发的证明。

## 测试范围

本地测试使用 Node 内置 SQLite 执行真实迁移 SQL，使用临时 RSA 密钥签发 JWT，并模拟学校令牌端点和 JWKS。覆盖默认关闭、state/Cookie、PKCE、nonce/签名/issuer/audience/时效、一次性码并发消费、来源和长度限制、过期清理、错误脱敏。**未测试真实获批应用，也未部署 Worker 或生产 D1。**

参考：[同济授权码文档](https://api.tongji.edu.cn/docs/intro/develop/authentication_code)、[官方 OIDC discovery](https://api.tongji.edu.cn/keycloak/realms/OpenPlatform/.well-known/openid-configuration)、[Cloudflare Rate Limiting](https://developers.cloudflare.com/workers/runtime-apis/bindings/rate-limit/)。
