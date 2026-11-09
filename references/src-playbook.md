# SRC 打法速查（众测/企业 SRC 场景）

> 与 Pojun 平台版 `skills/src-hunting`（48 篇知识库 + 11 篇规则）同源蒸馏。
> 只在打 SRC/众测时叠加使用；通用纪律见 SKILL.md 主文件。

## 一、一种子闭环（节奏铁律）

模糊目标（只给集团名/品牌名、没有 URL 清单）时：

1. **起手落盘** `assets.md` 种子队列：用户原词 + 业务名/品牌 + SRC 范围域 +
   全资子公司域（多条）——禁止队列里只有原词一条。
2. **一种子闭环**：搜一个种子 → 去重/去废/去非存活 → 把剩下的活面**全部挖完**
   → 才标 done → 立刻搜下一条 pending。禁止多种子一次搜完再挖。
3. **一轮搜完 ≠ 任务结束**；「本种子收工」= 该种子剩余活面已挖完。
4. 打开是登录页：先找业务面（本 host 网关或跳转后的 host）；没会话就挖未登录面。
   **不是登录相关的一律不管**，不磨登录 HTML。
5. 进了会话立刻转**对象图/换 id 越权**（见 §三）。

## 二、FOFA 资产测绘速查

```
qbase64：查询语句 UTF-8 再 Base64；fields：host,ip,port,title,server；size 先小后翻页

domain="target.com"                      域名
cert.subject="品牌名"                     证书主体（找子公司资产最快）
icon_hash="xxx"                          相同 favicon 的同源站
body="actuator" / header="application/json"   特征内容
组合用 && ；排除用 !=
```

- 结果处理：去重 → 去废（打不开/非归属）→ 去非存活 → 活面全部入 assets.md 开挖。
- 归属闸：仅同 IP 不算归属；备案/证书/whois 证据齐全才纳入测试范围。
- 工具：Pojun 平台用 MCP 预设「FOFA 资产测绘」（uv --directory mcp-servers/fofa
  run python fofa.py，工具 get_alerts / get_alerts_onefox）。

## 三、短表打法精选（高价值、低误报、可复现）

| 认什么 | 打哪 | 出什么算成 |
|---|---|---|
| 对象存储先发 STS；key 是文件 md5；Policy 含 filename/Action | 凭证字段填 `*`/`/`，匿名领钥口先原样领默认凭证 → PutObject 任意 key → 桶域名公网读回 | 官方文件被覆盖/能读他人对象 |
| 业务网关代理对象存储 `/api/storage/sign`，query 吃 key | 无鉴权 GET `?key=/` 列举 → 按业务前缀读对象 | 列出并读到他人未公开对象 |
| 二维码登录回包带 token；登录页吃 `?token=` | 不登录把带 token 的登录 URL 给已登录会话打开 | 未登录端变成对方号 |
| 公示名录/目录接口（pageSize 可放大） | 不登录分页拉满 → 全字段统计 → 拼文件 URL 直接下载 | 批量姓名/电话/附件导出 |
| 运营配置 JSON 的 jumpUrl/skipPath 带会话票 | 抄出来当 Token 打 me/info，对照不带票的请求 | me 返回他人手机号/角色 |

完整版见 Pojun 主仓 `skills/src-hunting/references/打穿短表.md`（59 条 + 假点对照）。

## 四、SRC 纪律（覆盖通用纪律的加严项）

- **CORS 不挖**：SRC 上报价值低（`Access-Control-Allow-Origin: *` 泛滥且平台不收）；
  时间花在越权/逻辑上。
- **不登出/注销/吊销**：见 SKILL.md 铁律 5。
- **信息类低危少报**：目录列表、banner 泄露这类通常被拒；把时间投给能拿数据/权限的链。
- **报告口径**：按 SRC 平台要求；定级对照 SKILL.md §4 的 L 级；每条附可直接
  复现的请求序列与最小影响样本。
- **不磨登录 HTML**：401/403 的业务 API 现场改 path/method/头打；登录页本身
  只测可见的验证逻辑（弱口令 ≤3 组、验证码可复用、响应差异枚举）。

## 五、报告落盘

- 每个确认漏洞一文件 `findings/NNN-标题.md`，模板见 references/report-template.md；
- 严重性写 L 级依据（L3/L4 + 证据指针）；
- 收尾时按 SRC 平台格式合并输出（多数平台：漏洞名/等级/URL/复现/影响/修复建议）。
