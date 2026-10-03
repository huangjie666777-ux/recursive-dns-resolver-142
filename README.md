# recursive-dns

一个面向企业私有域多级权威环境的 DNS 递归解析后端（Go 1.27.1 + miekg/dns 1.1.63）。
不使用系统解析器，也不转发给任何递归器；从根提示出发以 RD=0 迭代查询权威服务器，
全部状态保存在内存中，不做 DNSSEC。

## 构建与测试

```sh
go build ./...
go test ./...
```

## 配置（JSON）

见 `config.example.json`：

| 字段 | 含义 |
| --- | --- |
| `listen_addr` / `listen_port` | 本机监听地址与高端口（>1024，UDP+TCP 同端口） |
| `root_hints` | IPv4 根提示列表（`name`/`ipv4`） |
| `upstream_port` | 所有权威上游的统一端口 |
| `upstream_timeout_ms` | 单个上游请求超时 |
| `query_deadline_sec` | 单次解析的总期限 |
| `max_upstream_queries` | 单次解析的上游请求数预算 |
| `max_delegation_depth` | 最大委深层数 |
| `cache_max_entries` | 缓存条数上限（LRU 淘汰） |
| `cache_max_negative_ttl` | 负缓存 TTL 上限 |

## 运行

```sh
go run . -config config.example.json
```

仅接受：单问题、IN 类、RD=1 的 A/AAAA 查询；其余返回 FORMERR/REFUSED。
响应保留请求 ID 与问题，`RA=1`、`AA=0`。

## 本机多级权威演示

`cmd/authdemo` 在回环地址上搭建 根(127.0.0.2) → test.(127.0.0.3) →
example.test.(127.0.0.4) 三级权威，统一使用端口 15354：

```sh
go run ./cmd/authdemo -port 15354 &
go run . -config config.example.json &

dig @127.0.0.1 -p 15353 www.example.test. A       # 正向 A
dig @127.0.0.1 -p 15353 alias.example.test. A     # 完整 CNAME 链
dig @127.0.0.1 -p 15353 missing.example.test. A   # NXDOMAIN + SOA
dig @127.0.0.1 -p 15353 www.example.test. AAAA # 演示环境含 AAAA 记录
```

重复查询可观察到缓存命中时 TTL 逐秒递减。

## 行为要点

- **委派追踪**：委派域必须是查询名的祖先且比当前区更深；胶水只采信委派域内
  该组 NS 的 A 记录，其他 Additional 一律忽略；无可信胶水时独立递归解析 NS 地址。
- **CNAME**：跟随至最终地址并返回完整链；检测别名环与 NS 解析依赖环。
- **失败语义**：上游超时/失败依次尝试其他 NS；全部失败、超期或预算耗尽返回
  SERVFAIL，绝不误报 NXDOMAIN。
- **上游校验**：校验事务 ID 与回显问题（miekg 客户端保证来源地址/端口匹配）；
  UDP 响应 TC=1 时对同一服务器用 TCP 重试；只接受对应名称的权威终态，
  区分 NXDOMAIN 与 NODATA。
- **缓存**：以忽略大小写的 (名称, 类型) 缓存完整结果；正结果取答案最小 TTL；
  负结果须有 SOA，取 min(SOA TTL, MINIMUM) 并受别名链 TTL 与配置上限约束；
  命中时各记录 TTL 按经过时间递减，过期与零 TTL 不复用；SERVFAIL 与半条链不缓存。
- **并发**：相同查询单飞合并，每个请求方拿到独立记录副本，互不串改。

## 文件结构

- `config.go` — JSON 配置加载与校验
- `upstream.go` — 上游交换、ID/问题校验、TC→TCP 重试
- `resolver.go` — 迭代递归、委派/胶水/CNAME/环检测、预算与期限
- `cache.go` — LRU 缓存、TTL 递减、负缓存
- `server.go` / `main.go` — UDP/TCP 服务与入口
- `cmd/authdemo/` — 本机三级权威演示
- `resolver_test.go` / `cache_test.go` — 端到端与缓存测试
