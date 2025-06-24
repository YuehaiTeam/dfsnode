# DFSNode

## 功能特性

- 静态文件服务（使用hyper-staticfile）
- 目录索引（可配置）
- 签名认证
- 配置热重载（从中央服务器）
- 范围请求支持
- Prometheus指标监控
- 高性能文件系统缓存
- 连接池限制

## 命令行参数

```bash
# 使用配置文件
./dfscdnd --config gw.yaml --dir ./data --port 8093

# 使用中央服务器
./dfscdnd --central https://server_id:server_token@example.com/gateway-central --dir ./data --port 8093
```

### 参数说明

- `--central`: 指定网关的配置服务器地址和认证信息，API调用使用basic认证
- `--config`: 指定配置文件路径
- `--dir`: 指定文件存储路径（默认：./data）
- `--port`: 指定网关监听的端口（默认：8093）

注意：`--central` 和 `--config` 只能选择其中一个，且必须提供其中一个。

## 配置文件格式

```yaml
paths:
  /default:
    autoindex: false  # 可选，是否启用目录索引
    signature: false  # 可选，是否需要签名认证
  /restricted:
    autoindex: false
    signature: "sign_token"  # 签名密钥
  /public:
    autoindex: true
```

## 签名格式

对于需要签名认证的路径，请求URL格式为：
```
/path/to/file?$=[signstr]
```

其中 `[signstr]` 的格式为：
```
{4byte hex unix过期时间}{hmac_sha256_hex}{4byte hex range start}{4byte hex range end}……{4byte hex range-n start}{4byte hex range-n end}
```

HMAC-SHA256的输入消息格式为：
```
/path/to/file\n{4byte hex unix过期时间}\n{4byte hex range start}{4byte hex range end}……{4byte hex range-n start}{4byte hex range-n end}
```

## Range验证

当签名中包含range信息时，客户端必须发送相应的Range HTTP Header，格式为：
```
Range: bytes=start1-end1,start2-end2,...
```

验证规则：
- 如果签名包含range信息，但客户端没有发送Range header，验证失败
- 如果签名包含range信息，客户端的Range header必须与签名中的range完全匹配
- 如果签名不包含range信息，客户端可以发送或不发送Range header

## 示例

1. 启动服务器：
```bash
cargo run -- --config gw.yaml --dir ./data --port 8093
```

2. 访问公共文件（不需要签名）：
```
http://localhost:8093/public/file.txt
```

3. 访问受限文件（需要签名）：
```
# 不包含range的签名
http://localhost:8093/restricted/file.txt?$=67890abc56789abcdef0123456789abcdef0123456789abcdef0123456789abcdef

# 包含range的签名，需要同时发送Range header
curl -H "Range: bytes=0-1023" "http://localhost:8093/restricted/file.txt?$=67890abc56789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0000000000000400"
```

## 构建

```bash
cargo build --release
```

## 运行

```bash
# 开发模式
cargo run -- --config gw.yaml

# 生产模式
./target/release/dfscdnd --config gw.yaml --dir /var/www --port 80
```
