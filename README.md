# recursive-dns

企业私有域多级权威场景下的 DNS 递归解析后端（Go 1.27.1 + miekg/dns 1.1.63）。
不使用系统解析器，不做递归转发，不校验 DNSSEC；全部状态在内存中。

## 功能

- JSON 配置本机监听高端口、IPv4 根提示与统一上游端口（见 `config.json`）。
- UDP/TCP 仅接收单问题、IN 类、RD=1 的 A/AAAA 查询；其余返回 FORMERR/REFUSED。
- 从根提示以 RD=0 迭代查询，按 NS 委派逐层向下；委派域必须是问题名的祖先
  （或相等）且比当前区更深，否则拒绝。
- 胶水只采信 Additional 中"委派域内、且属于该组 NS"的 A 记录；无可信胶水时
  独立递归解析 NS 地址。
- 沿 CNAME 追踪到最终地址并返回完整链；检测别名环与解析依赖环
  （NS 地址解析回环），均返回 SERVFAIL。
- 校验上游来源（connected socket）、事务 ID 与回显问题；UDP 响应 TC=1 时
  向同一服务器改用 TCP 重试。
- 区分 NXDOMAIN 与 NODATA（存在但无该类型）；上游超时/失败依次尝试其他 NS，
  全部失败、期限或预算耗尽返回 SERVFAIL，绝不当作 NXDOMAIN。
- 响应保留客户端 ID 与问题，RA=1、AA=0。
- 缓存按忽略大小写的 (名称, 类型) 存完整结果：正结果取答案链最小 TTL；
  负结果必须有 SOA，取 min(SOA TTL, MINIMUM) 并受链上别名 TTL 限制；
  命中时各记录 TTL 按经过时间递减；过期与零 TTL 不复用；SERVFAIL 与
  半条链不入缓存。缓存条数、解析总期限、单次查询上游请求数均有限制。

## 文件

| 文件 | 职责 |
| --- | --- |
| `config.go` | JSON 配置加载、默认值与校验 |
| `server.go` | 客户端侧 UDP/TCP 服务、请求过滤、响应组装 |
| `resolver.go` | 迭代递归引擎：委派、胶水、CNAME、环检测、上游交换与校验 |
| `cache.go` | 结果缓存：TTL 规则、递减、容量淘汰 |
| `zone.go` | 示例/测试用的内存权威区服务器 |
| `demo.go` | 本机多级权威示例与演示驱动 |
| `main.go` | 入口 |

## 配置

```json
{
  "listen_addr": "127.0.0.1:8053",
  "root_hints": ["127.0.0.2"],
  "upstream_port": 15353,
  "upstream_timeout_ms": 2000,
  "resolve_timeout_ms": 8000,
  "max_upstream_queries": 64,
  "cache_max_entries": 1024
}
```

`root_hints` 只接受 IPv4 字面地址；所有上游权威共用 `upstream_port`。

## 构建与启动

```sh
go build -o recursive-dns .
./recursive-dns -config config.json
```

## 本机多级权威演示

`./recursive-dns -demo` 在 127.0.0.0/8 上启动四级权威（统一端口 15353）
并启动解析器（127.0.0.1:8053），随后用内置客户端演示解析：

- `127.0.0.2` 根 `.`：委派 `corp.test.`（含胶水）
- `127.0.0.3` `corp.test.`：`www` A/AAAA；委派 `dept.corp.test.`（含胶水）；
  委派 `eng.corp.test.`（**无胶水**，NS 为 `ns1.corp.test.`，需独立递归解析）
- `127.0.0.4` `dept.corp.test.`：`www` A、`alias` CNAME、`loop1/loop2`
  别名环、`txt-only`（NODATA 示例）
- `127.0.0.5` `eng.corp.test.`：`www` A

演示保持运行，可用外部客户端验证：

```sh
dig @127.0.0.1 -p 8053 www.dept.corp.test A        # NOERROR + A
dig @127.0.0.1 -p 8053 alias.dept.corp.test A      # 完整 CNAME 链
dig @127.0.0.1 -p 8053 www.eng.corp.test A         # 无胶水委派
dig @127.0.0.1 -p 8053 nosuch.dept.corp.test A     # NXDOMAIN + SOA
dig @127.0.0.1 -p 8053 txt-only.dept.corp.test A   # NODATA + SOA
dig @127.0.0.1 -p 8053 loop1.dept.corp.test A      # SERVFAIL（别名环）
dig @127.0.0.1 -p 8053 +tcp www.corp.test A        # TCP
```

连续查询同一名称可看到缓存命中时 TTL 逐秒递减。

## 测试

```sh
go test ./...
```

覆盖：胶水委派、多级委派、无胶水 NS 独立解析、CNAME 链、别名环、
NXDOMAIN/NODATA 区分、缓存命中与 TTL 递减、负缓存、预算耗尽走 SERVFAIL、
端到端 ID/问题保留与 RA=1/AA=0、UDP 截断后的 TCP 重试、零 TTL 不缓存、
容量淘汰、负缓存别名 TTL 上限。

