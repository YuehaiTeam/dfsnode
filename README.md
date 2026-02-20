# DFSNode

多协议文件服务节点，基于 WebDAV 构建，支持多种现代传输协议。

## 功能

### 多协议传输

DFSNode 同时支持以下协议，可按需开启：

| 协议 | 说明 |
|------|------|
| **HTTP** | 标准 HTTP/1.1 WebDAV 服务 |
| **HTTPS** | TLS 加密的 WebDAV 服务，支持自签证书自动生成与轮换 |
| **HTTP/3** | 基于 QUIC 的 HTTP/3 服务 |
| **WebTransport** | 基于 HTTP/3 的高速单向文件下载流 |
| **WebRTC** | 通过 DataChannel 进行点对点文件传输 |
| **SSH** | HTTP-over-SSH 端口转发隧道 |
| **SFTP** | 使用 SFTP 协议通过 SSH 下载文件 |

### 文件管理

- **WebDAV**：完整的 WebDAV 文件操作（浏览、上传、下载、创建目录、移动、复制、删除）
- **校验和**：自动计算并缓存文件的 SHA1/MD5 校验和（兼容 OwnCloud 协议）
- **TUS 断点续传**：支持 [TUS 协议](https://tus.io/) 的大文件分块续传上传，支持上传校验

### 认证与安全

- **Basic Auth**：用户名 + 密码认证；未配置密码时自动进入只读模式
- **签名下载**：基于 HMAC-SHA256 的 URL 签名机制，支持绑定文件路径、过期时间和 Range 范围
- **路径级权限**：可按路径前缀单独配置签名密钥或开放公开访问

### 网络与监控

- **STUN NAT 穿透**：自动探测公网地址，支持定时保活，公网地址变更时通过 HTTP POST 回调通知
- **Prometheus 指标**：内置 `/-/metrics` 端点，按协议统计请求数和流量；提供 `/minio/metrics/v3/...` 端点，兼容 MinIO 监控生态；定时向 VictoriaMetrics / Prometheus 远程写入指标

---

## 配置

DFSNode 支持两种配置方式：**命令行参数** 和 **YAML 配置文件**。命令行指定基础运行参数，配置文件管理认证、TUS、STUN 等高级功能。

> **注意**：`--username`/`--password`/`--sign-key` 与 `--config` 互斥，认证相关配置要么全部通过命令行传入，要么通过配置文件管理。

### 命令行参数

#### 基础参数

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `--root <DIR>` | 文件服务根目录 | `.`（当前目录） |
| `--prefix <PATH>` | URL 路径前缀 | `/` |

#### 端口与协议

至少需要指定一个端口，服务才会启动。

| 参数 | 说明 |
|------|------|
| `--http-port <PORT>` | HTTP 监听端口 |
| `--https-port <PORT>` | HTTPS 监听端口（需同时提供证书或开启 `--ssl-generate`） |
| `--http3-port <PORT>` | HTTP/3 (QUIC) 监听端口（需同时提供证书或开启 `--ssl-generate`） |
| `--ssh-port <PORT>` | SSH 监听端口 |

#### TLS 证书

| 参数 | 说明 |
|------|------|
| `--cert <FILE>` | TLS 证书文件路径（PEM 格式），需与 `--key` 配合 |
| `--key <FILE>` | TLS 私钥文件路径（PEM 格式），需与 `--cert` 配合 |
| `--ssl-generate` | 自动生成自签证书并定期轮换，无需手动提供证书文件 |

#### SSH

| 参数 | 说明 |
|------|------|
| `--ssh-host-key <FILE>` | SSH 主机密钥路径（PEM 格式），不指定则自动生成 Ed25519 密钥 |

#### 认证（与 `--config` 互斥）

| 参数 | 说明 |
|------|------|
| `--username <USER>` | Basic Auth 用户名，需与 `--password` 配合 |
| `--password <PASS>` | Basic Auth 密码，需与 `--username` 配合 |
| `--sign-key <HEX>` | HMAC-SHA256 签名密钥（Hex 编码） |

#### STUN / NAT 穿透

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `--stun-server <ADDR>` | STUN 服务器地址（可多次指定），需要 `--http3-port` | — |
| `--stun-interval-secs <N>` | STUN 保活间隔（秒） | `20` |

#### WebRTC

| 参数 | 说明 |
|------|------|
| `--enable-rtc` | 启用 WebRTC DataChannel 文件传输（需同时配置 `--http3-port` 和 `--stun-server`） |

#### 其他

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `--config <FILE>` | YAML 配置文件路径 | — |
| `--no-tcp-download` | 禁止通过 HTTP/1.1 和 HTTP/2 下载文件（仅允许 H3/WebTransport/WebRTC 下载） | 关闭 |
| `--real-ip <策略>` | 真实 IP 提取策略，可选值见下方说明 | — |
| `--webhook-url <URL>` | 公网地址变更回调 URL（支持在 URL 中嵌入 Basic Auth 凭据） | — |
| `--metrics-push-url <URL>` | 指标推送目标地址（可多次指定，支持在 URL 中嵌入 Basic Auth 凭据） | — |
| `--metrics-push-interval-secs <N>` | 指标推送间隔（秒） | `15` |

#### `--real-ip` 可选值

| 值 | 含义 |
|----|------|
| `XRealIp` | 取 `X-Real-IP` 头 |
| `RightmostXForwardedFor` | 取 `X-Forwarded-For` 最右侧 IP |
| `CfConnectingIp` | 取 Cloudflare `CF-Connecting-IP` 头 |
| `TrueClientIp` | 取 `True-Client-IP` 头 |
| `FlyClientIp` | 取 Fly.io `Fly-Client-IP` 头 |
| `RightmostForwarded` | 取 `Forwarded` 头最右侧 IP |

---

### YAML 配置文件

通过 `--config config.yaml` 加载。配置文件管理认证规则和高级功能。

```yaml
version: 1  # 必填，配置版本

# ===== 认证 =====
username: admin
password: your-password
sign_key: "abcdef0123456789..."  # HMAC-SHA256 密钥（Hex 编码）

# ===== 路径级权限 =====
# 按路径前缀覆盖全局认证策略
paths:
  /public:        false             # 完全公开，无需任何认证
  /protected:     true              # 使用全局 sign_key 验签
  /special:       "per-path-hex-key"  # 使用独立签名密钥

# ===== TUS 断点续传 =====
tus:
  enabled: true
  temp_dir: /tmp/dfs-tus           # 临时文件目录（默认：系统临时目录）
  upload_timeout_hours: 24         # 上传超时（小时）
  max_concurrent_uploads: 100      # 最大并发上传数
  max_upload_size: 5368709120      # 单文件上传上限（字节，默认 5GB）

# ===== STUN =====
stun:
  servers:                         # 也可用 server 指定单个
    - stun.l.google.com:19302
    - stun1.l.google.com:19302
  interval_secs: 20                # 保活间隔（秒）

# ===== Webhook =====
webhook_url: https://user:pass@example.com/webhook  # 支持 Basic Auth

# ===== 指标推送 =====
metrics_push:
  urls:                            # 也可用 url 指定单个
    - https://user:pass@victoria.example.com/api/v1/import/prometheus
  interval_secs: 15                # 推送间隔（秒）
```

### 快速上手示例

```bash
# 最简启动：当前目录作为只读 HTTP 文件服务
dfsnode --http-port 8080

# 带认证的 HTTPS 服务（自动生成证书）
dfsnode --root /data --https-port 8443 --ssl-generate \
  --username admin --password secret

# 全协议启动 + 配置文件
dfsnode --root /data \
  --http-port 8080 \
  --https-port 8443 \
  --http3-port 8443 \
  --ssh-port 2222 \
  --ssl-generate \
  --enable-rtc \
  --stun-server stun.l.google.com:19302 \
  --config config.yaml
```
