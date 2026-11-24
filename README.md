# splitrelease

离线、标准库实现的双源不可变日志发布认证工具。

它处理两组不同步记录：

- `logs.build_log`：产物摘要、固定的构建依赖；
- `logs.approval_log`：审批回执、自然人别名/标签变动、临时吊销。

一个经确认的双向检查点分别锁定两个源的前缀。检查点之后的事件只承认显式
`predecessors` 因果约束；**JSON 数组顺序和文件行序永远不作为因果证据**。在满足
前驱约束的前提下，工具遍历歧义窗口的所有合法拓扑序，判断发布候选为：

- `YES` / `always_releasable`：所有合法顺序都可发布；
- `NO` / `never_releasable`：不存在可发布前缀；
- `CASE` / `order_dependent`：至少存在一条通过前缀和一条拒绝前缀。

对 `YES` 候选，输出按“事件条数最少，再按 ID 字典序”决胜的自包含最小证据集合。
`protect` 则枚举 16 个拟议暂停点的全部 `2^16` 个子集，选择总停工时间最小的方案，
使所有 `CASE` 候选不再存在可提交前缀，同时所有 `mandatory: true` 的合规制品在暂停后的
剩余合法顺序下仍为 `YES`（即必然可发布，而不只是存在一条幸运顺序）。

## 运行环境

- Windows / Linux / macOS；
- Python 3.12；
- 仅标准库；
- 不需要联网，不安装第三方包。

在仓库根目录运行：

```bash
python -m splitrelease certify fixtures/sample_case.json
python -m splitrelease protect fixtures/sample_case.json
```

如果输入数据来自不可信解压目录，可使用隔离模式启动器（不会把当前工作目录加入
`sys.path`）：

```bash
python -I run_splitrelease.py certify D:\path\to\case.json --out report.json
python -I run_splitrelease.py protect D:\path\to\case.json --out plan.json
```

运行测试：

```bash
python -m unittest discover -s tests -v
```

重新生成合成夹具：

```bash
python run_splitrelease.py fixture sample --out fixtures/sample_case.json
python run_splitrelease.py fixture topo-small --out fixtures/topo_small_case.json
python run_splitrelease.py fixture large --out fixtures/large_case.json
```

`fixtures/large_case.json` 是生成好的 100,000 条普通日志样例，约 19 MB。

## CLI

所有输入、输出均为 UTF-8 JSON。

```text
python -m splitrelease certify CASE.json [--candidate ID] [--no-evidence] [--out report.json]
python -m splitrelease protect CASE.json [--out plan.json]
python -m splitrelease fixture {sample,topo-small,large} --out OUT.json
```

不指定 `--out` 时，报告以缩进 JSON 写到 stdout。错误输出也是 JSON：

```json
{"schema":"splitrelease.error/v1","error":"CaseError","message":"..."}
```

## 输入格式 `splitrelease.case/v1`

完整可解析示例见 [`fixtures/sample_case.json`](fixtures/sample_case.json)。最小结构：

```json
{
  "schema": "splitrelease.case/v1",
  "case_id": "example",
  "phases": {
    "ga": {"threshold": 3, "required_independent_groups": 2}
  },
  "logs": {
    "build_log": [],
    "approval_log": []
  },
  "checkpoint": {
    "checkpoint_id": "cp-bilateral-0001",
    "confirmed": true,
    "build_prefix": ["build-1"],
    "approval_prefix": ["alias-1", "vote-1"]
  },
  "windows": [
    {"id": "w-main", "event_ids": ["revoke-1", "vote-2", "restore-1"]}
  ],
  "candidates": [],
  "pause_points": []
}
```

### 通用事件字段

| 字段 | 说明 |
|---|---|
| `id` | 全局唯一、稳定的事件 ID |
| `kind` | 事件类型，见下 |
| `predecessors` | 显式因果前驱 ID 数组；唯一的因果证据 |

数组中的物理顺序可以任意打乱；测试包含逆序和按 ID 反排序对拍。

### 检查点

```json
"checkpoint": {
  "build_prefix": ["b1", "b2"],
  "approval_prefix": ["a1", "a2"]
}
```

两个数组分别锁定两个源的前缀，必须因果闭合：前缀事件的所有前驱也必须在前缀中。
检查点状态作为后续拓扑枚举的基线。夹具中所有无歧义的十万级普通记录均位于锁定前缀。

### 构建记录与依赖闭包

`kind: "artifact_built"`：

```json
{
  "id": "build-combo-1",
  "kind": "artifact_built",
  "artifact_id": "art-combo",
  "digest": "sha256:combo-v1",
  "dependencies": [
    {"artifact_id": "lib-util", "digest": "sha256:util-v1"}
  ]
}
```

候选通过 `artifact_id + artifact_digest` 固定一个不可变构建记录。工具递归解析
带摘要固定的直接/传递依赖，生成规范化依赖闭包摘要：

```text
depclosure-v1:<sha256 of canonical JSON>
```

审批票必须绑定这个 `closure_digest`。缺少依赖、摘要找不到或依赖成环时，候选为
`NO`，并在 `closure` 字段给出原因。

### 审批、自然人和别名

审批票：

```json
{
  "id": "vote-carol",
  "kind": "vote",
  "phase": "ga",
  "closure_digest": "depclosure-v1:...",
  "auth_ref": "key-carol",
  "person_id": "p-carol",
  "group_id": "grp-release-a",
  "group_name": "Release Approvers",
  "independence_key": "ind-release-a"
}
```

别名单/标签移动：

```json
{
  "id": "alias-move",
  "kind": "alias_binding",
  "auth_ref": "key-roving",
  "person_id": "p-mallory"
}
```

规则：

- 自然人身份以稳定 `person_id` 为准，不按姓名、别名或标签字符串合并；
- `auth_ref` 在票到达位置按当前已出现的别名绑定解析；
- 如果别名已移动到另一个自然人，而票中声明的 `person_id` 与解析结果不同，该票无效；
- 同一自然人即使使用多个别名或多张回执，也只计一个有效人/有效票数；
- 组身份只看稳定 `group_id` 和 `independence_key`；
- **相同 `group_name` 不是同一对象**。示例中两个独立组都叫
  `Release Approvers`，但 `group_id`/`independence_key` 不同，因此仍算两个独立组；
- 可变标签从一个制品或人移动到另一个对象时，不改变稳定 ID 和摘要绑定；夹具中的
  `tag_move` 只作记录，候选仍由 `artifact_id + artifact_digest` 固定。

### 临时吊销

```json
{
  "id": "revoke-carol",
  "kind": "revocation",
  "action": "revoke",
  "target_type": "person",
  "target_id": "p-carol"
}
```

恢复事件：

```json
{
  "id": "restore-carol",
  "kind": "revocation",
  "action": "restore",
  "target_type": "person",
  "target_id": "p-carol",
  "predecessors": ["revoke-carol"]
}
```

也支持 `target_type: "vote"` 直接吊销回执。若票到达时其自然人或该票处于吊销状态，
则该票不能计入；前缀终点仍处于吊销状态时也不计入。恢复后，且票不是在吊销窗口内到达，
则可有效。

### 阶段阈值

```json
"phases": {
  "ga": {"threshold": 3, "required_independent_groups": 2},
  "identity": {"threshold": 2, "required_independent_groups": 2}
}
```

候选中的 `"phase"` 选择当前阈值。通过条件为：

1. 不同有效自然人数 `>= threshold`；
2. 有效票覆盖的不同 `group_id` 数 `>= required_independent_groups`；
3. 有效票覆盖的不同 `independence_key` 数 `>= required_independent_groups`。

### 歧义窗口

```json
"windows": [
  {"id": "w-two-revocations", "event_ids": ["..."]}
]
```

候选通过 `"window_id": "w-two-revocations"` 引用窗口，也可用
`"ambiguous_event_ids": [...]` 内联。文档保证每个歧义窗口最多 16 个事件。

引擎不枚举 16! 个原始排列，而是做语义状态子集搜索：

- 位掩码表示已到达事件；
- 只允许所有显式前驱均已到达的事件成为下一步；
- 状态键包含别名表、吊销集合、已评估票的自然人/有效性；
- 相同语义状态合并，因此 `2^16` 规模可在普通 CPU 上完成。

小夹具测试另外使用朴素全拓扑序枚举（示例双吊销窗口恰有
`6! / (2×2) = 180` 个合法顺序）与状态搜索结果对拍。

### 候选

```json
{
  "id": "rc-combo",
  "artifact_id": "art-combo",
  "artifact_digest": "sha256:combo-v1",
  "phase": "ga",
  "window_id": "w-two-revocations",
  "mandatory": false
}
```

`mandatory: true` 只被 `protect` 使用，表示必办合规制品。

### 暂停点

```json
{
  "id": "pp16-contested-bundle",
  "downtime_minutes": 7,
  "hold_events": ["vote-carol", "vote-dave", "vote-roving"]
}
```

选中暂停点会扣留 `hold_events`。若某事件被扣留，其所有显式因果后继也进入有效扣留
集合，因为缺少必需前驱的后继不能作为完整证据重放。`protect` 对 16 个点做全子集枚举，
因此最多少 65,536 个子集。

## 认证输出

每个候选包含：

- `verdict` / `certify`；
- `closure.closure_digest`；
- `state_space`：语义状态数、终止状态数、通过/失败终止状态数；
- `pass_witness`：一条完整可复核通过前缀；
- `reject_witness`：一条完整、到达窗口末端的拒绝前缀；
- `minimal_evidence`：仅 `YES` 候选。

Witness 中：

- `checkpoint_prefix_order`：锁定基线的规范化重放顺序；
- `post_checkpoint_order`：所选合法拓扑序；
- `complete_review_prefix`：基线 ID + 窗口顺序；
- `steps[].tally`：每一步后的自然人、组和票数。

### 最小证据如何“排除所有反例”

最小证据包不是只挑一张成功票。对每个候选回执，它做对抗性闭包：

1. 加入该票；
2. 加入所有相同 `auth_ref`、且在因果上可能先于该票的别名/标签移动记录；
3. 从票中声明的自然人和别名可能解析到的自然人出发，加入所有针对这些自然人的吊销/恢复记录；
4. 加入所有针对该票的吊销/恢复记录；
5. 加入依赖闭包所需的全部构建记录；
6. 递归加入上述事件的所有显式因果前驱。

因此，证据包外的事件不可能改变包内票的自然人解析或吊销状态。随后工具对这个自包含
证据包再次遍历全部合法拓扑序；只有仍为 `YES` 才是合格证书。

搜索按证据事件集合的基数做分支限界，决胜键为：

```text
(minimal_event_count, lexicographically smallest sorted event ID tuple)
```

## 必需的双撤销组合样例

`rc-combo` 有两张锚点票和两个独立撤销竞争：

- `revoke-carol -> restore-carol`，与 `vote-carol` 并发；
- `revoke-dave -> restore-dave`，与 `vote-dave` 并发。

阈值为 3。两个锚点自然人和两个组始终有效，因此还需要 Carol 或 Dave 至少一张票：

- 只有 Carol 落入 `revoke < vote < restore`：Dave 有效，共 3 人，通过；
- 只有 Dave 落入不利顺序：Carol 有效，共 3 人，通过；
- 两者同时落入不利顺序：只剩 2 人，拒绝。

测试显式重放这三条完整顺序，并枚举全部 180 个拓扑序对拍。

## protect 输出

示例夹具的最优方案是：

```text
pp16-contested-bundle，总停工时间 7 分钟
```

它同时扣留 Carol、Dave 和 roving 三张争议票，使：

- `rc-combo`：`NO` / `pass_exists=false`；
- `rc-alias`：`NO` / `pass_exists=false`；
- `rc-safe`：仍为 `YES`，必办合规制品可发布。

`pp12-global-vote-gate` 虽然只停工 1 分钟，但会扣留 `rc-safe` 的必办票，因此被强制
约束排除。

## 性能

合成大夹具包含 100,000 条事件和最多 6 个事件的歧义窗口。普通 Windows CPU 上参考数据：

- 构建/索引约 1 秒；
- `certify` 约 2–3 秒；
- `protect` 全量枚举 65,536 个暂停子集约 3–5 秒（含一次认证和缓存）。

热点路径为线性索引；拓扑搜索只作用于候选引用的小窗口。测试
`tests/test_performance_100k.py` 会在临时进程内构造十万条日志并运行 `certify` 与
`protect`。

## 目录

```text
splitrelease/
  caseio.py      # JSON、校验、DAG、拓扑序
  closures.py    # 依赖闭包与规范摘要
  engine.py      # 状态子集搜索、前缀重放、计票
  evidence.py    # 最小自包含证据
  service.py     # certify_case / plan_protection
  fixtures.py    # sample/topo-small/large 合成夹具
  cli.py         # JSON CLI
tests/           # 拓扑对拍、认证、证据、protect、十万级性能
fixtures/        # 生成好的 JSON 夹具
```

## 设计边界

本实现把输入格式明确为上述 v1 契约。尤其是：歧义窗口必须完整列出会影响该候选的
检查点后事件；窗口外的十万级普通记录可以是无关噪声或已锁定前缀。这样才能在不枚举
十万阶乘排列的情况下，给出可复核且可复现的结论。
