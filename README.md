# service-mesh-mtls-rotation-convergence-planner
规划服务网格证书和信任包轮换的收敛顺序

## 概述

在服务网格中轮换根证书和中间 CA 时，不同代理对新信任包的确认（ACK）时间差异很大：
新代理可能只信任新根，旧代理仍只信任旧根，双向 mTLS 握手可能互相失败。
本工具根据抽象的证书元数据规划轮换的收敛顺序，划分四个阶段：

1. `distribute-new-root` — 按 rollout 波次把新根分发进各代理的信任包
2. `dual-trust` — 全部代理 ACK 新根，进入新旧双信任重叠期
3. `switch-issuance` — 签发切换到新中间 CA / 新根
4. `retire-old-root` — 旧根退役

**核心安全约束**：只要任一调用方向尚未同时具备新旧信任，就不能开始退役旧根。
此外以下情况都会阻止进入下一阶段：

- 代理 NACK 新根（可配置 `rollbackOnNack` 自动回滚到旧根单信任）
- 叶证书身份 URI 与代理期望身份不匹配
- 证书链缺少中间 CA
- 签发者（根或中间 CA）已停用

## 数据安全说明

本工具**只使用抽象证书元数据**（ID、有效期、状态、身份 URI、信任包中的根 ID 列表），
**不读取、不保存、不输出任何私钥或证书 PEM/DER 内容**。所有输入均为 JSON 元数据描述。

## 使用

```bash
node cli.js input.json   # 输出规划结果 JSON；若规划被阻塞，退出码为 1
node --test              # 运行测试
```

### 输入 schema（JSON）

```jsonc
{
  "now": 1700000000000,          // 当前时间（ms epoch）
  "roundMs": 3600000,            // 每个 rollout 波次的时长
  "oldRootId": "root-old",
  "newRootId": "root-new",
  "newIntermediateId": "ica-new",
  "rollbackOnNack": false,       // NACK 时是否自动回滚
  "roots": [{ "id": "root-old", "status": "active" }],
  "intermediates": [{ "id": "ica-old", "rootId": "root-old", "status": "active" }],
  "leaves": [{
    "id": "leaf-a", "proxyId": "proxy-a", "intermediateId": "ica-old",
    "identityUri": "spiffe://mesh/ns/default/sa/svc-a", "notAfter": 1700086400000
  }],
  "proxies": [{
    "id": "proxy-a", "service": "svc-a",
    "identityUri": "spiffe://mesh/ns/default/sa/svc-a",
    "wave": 1,                          // rollout 波次
    "trustBundle": ["root-old"],        // 当前信任的根
    "ack": { "root-new": true },        // 确认状态
    "nack": []                          // 可选：显式 NACK 的根
  }],
  "dependencies": [{ "caller": "svc-a", "callee": "svc-b" }]
}
```

### 输出

- `status`：`planned` / `blocked` / `rolled-back`
- `phases`：四个阶段各自的状态与阻塞项
- `rounds`：每轮每个代理的信任包内容、ACK/NACK 状态，以及该轮仍有风险的调用边
- `riskyEdges`：最终仍有握手风险的调用边（含失败原因）
- `safeRetirementTime`：旧根的安全退役时间（所有旧根叶证书过期且双信任收敛）；不可退役时为 `null`

## 测试

`node --test` 覆盖：双根重叠、部分 ACK、缺失中间 CA、NACK 回滚、身份 URI 不匹配、
签发者停用、NACK 不回滚保持阻塞。
