# PERC20 安全审计报告（第 3 轮）— 电路 + 合约全量审查

- **日期：** 2026-06-11
- **范围：** `circuits/`（action 电路及全部子电路/gadget）、`contracts/`（PERC20、Factory、OrchardVerifier、Groth16 验证器、签名/哈希/Merkle 库）、电路↔Rust prover↔合约的跨层一致性、可信设置与部署流水线
- **方法：** 5 路并行专项审查（核心电路健全性、底层 gadget、代币合约、验证器合约、跨层绑定），逐约束/逐行追踪，结论互相交叉验证；对照 `docs/audit-*.md` 既往审计逐项核对修复状态
- **基线 commit：** `0230619`

---

## 1. 总体结论

代码库明显经过多轮内部加固（H-01、Issue A/B/C/D、L-01…L-05 等修复均以**真实约束**形式存在，而非仅注释）。本轮审查：

- **电路（circom）层面：未发现 Critical/High 健全性漏洞。** 所有标量乘法的比特分解均经 `Recompose254/64` 规范化（含 AliasCheck）、金额 64 位范围约束、子群检查、路径比特布尔约束、frozen 非成员证明绑定被花费的 `cm_old_x`（H-01 修复确认在位）、8 个逻辑公开值全部经 `PubHashAction` 绑定到唯一公开信号 `pub_hash`。
- **合约层面：未发现新的 Critical/High 代码缺陷。** 经典的"公开输入未做域范围检查 → nullifier 别名双花"漏洞已正确封堵；预编译返回值全部检查；CEI 顺序正确；签名方案（s 规范化、R 在曲线上、chainId+合约地址域分离）健全。
- **跨层绑定：电路 9 元素吸收顺序 ≡ `ActionPubHash.sol` ≡ Rust `action_pub_hash`，逐字节一致**；Poseidon 参数（RF=8/RP=56，Orchard 风格）、Merkle 层级域标签、frozen IMT 空根常量、两种 sighash 构造在三层间全部一致。
- **最大风险不在代码，而在流程：仓库提交的 `Groth16PairingVerifier.sol` 来自"毒废料公开"的 dev zkey，且 `Deploy.s.sol` 默认部署它**（C-01）。主网上线前必须完成真实 MPC 仪式并加部署时 VK 哈希断言。
- 其次是**中心化风险**：admin 可即时热替换 Groth16 验证器（H-01），issuer 可无上限 mint（M-01）。

**主网上线前的三个门槛：** ① 真实 MPC phase-2 仪式 + 部署脚本 VK 哈希断言（C-01）；② 验证器地址不可变或 timelock+多签（H-01/M-01）；③ frozen IMT 链下维护良构性测试（L-02）。

---

## 2. 发现汇总

| ID | 严重性 | 标题 | 位置 |
|---|---|---|---|
| C-01 | **Critical**（流程） | 部署路径默认携带 dev zkey 验证器，毒废料公开可重构 → 任意伪造证明 | `circuits/scripts/groth16_dev_setup.sh:37-46`、`Groth16PairingVerifier.sol`、`script/Deploy.s.sol:23` |
| H-01 | **High**（中心化） | admin 可无 timelock 即时热替换 Groth16 验证器 → 密钥失陷即可无限增发 | `contracts/orchardverifier/OrchardVerifier.sol:168-172` |
| M-01 | Medium | admin/issuer 权力集中：无上限 mint、setFrozenRoot 审查权、无 timelock/多签 | `PERC20.sol:107-110,134`、`OrchardVerifier.sol:162-197` |
| L-01 | Low | `BJJSubgroupCheck` 不在内部强制 on-curve 前置条件（纵深防御） | `circuits/babyjubjub/subgroup_check.circom:26-77` |
| L-02 | Low | frozen IMT 非成员证明的健全性依赖链下维护的有序 IMT 良构性 + 创世 `(0,·)` 叶 | `circuits/frozen_cmx_nonmember.circom`、链下索引器 |
| L-03 | Low | binding sighash 对相邻动态数组用 `abi.encodePacked`（当前不可利用，重构脆弱） | `contracts/crypto/signature/BindingSignature.sol:67-75` |
| L-04 | Low | `outCiphertext` 长度未校验（文档约定 80 字节） | `OrchardVerifier.sol:351` 附近 |
| L-05 | Low | frozen-root 宽限期允许新冻结的 note 在 ≤1 天内仍可花费；创世 0 根与"空黑名单"语义重合 | `OrchardVerifier.sol:152-158,314-323` |
| L-06 | Low | `v_old=0` 的 dummy/铸币动作发布证明者自选的 nullifier 与 cmx：状态膨胀 + dummy nullifier 复用导致 liveness revert；`nf==0` 约定未强制 | `circuits/action.circom:138-147`、`OrchardVerifier.sol:278-282` |
| I-01 | Info | `POSEIDON_CAP9` 字面量 > p（非规范形式），三层当前一致但第三方实现易踩坑 | `circuits/constants.circom:15`、`ActionPubHash.sol:22` |
| I-02 | Info | Poseidon 电路由 `PoseidonT3.sol` 自动生成 → 电路与合约可能共享同一常量 bug；建议对 Rust 参考实现加独立测试向量 | `circuits/scripts/gen_poseidon_circom.py` |
| I-03 | Info | NUMS 生成元（G_NOTE/H_NOTE/G_VALUE/G_RANDOM/G_NULLIFIER/G_SPEND_AUTH）来源未独立重推导（Pedersen 绑定性依赖其无已知 DLOG 关系） | `circuits/constants.circom:49-60`、`test/Generators.t.sol` |
| I-04 | Info | `recipientMeta` 在 PERC20 中恒为 0，不提供收款人绑定（pBTC 遗留字段） | `PERC20.sol:125,143,164` |
| I-05 | Info | `pub[3] != nfOld` 误用 `NullifierSpent()` 错误名，干扰排障 | `OrchardVerifier.sol:349` |
| I-06 | Info | 证明不绑定密文正确性（恶意发送方可发不可解密 note；已知并文档化） | `IEndpointCore.sol:45-50` |
| I-07 | Info | token name/symbol 未认证（仿冒风险）；合约刻意不实现完整 ERC-20 表面（无 balanceOf/approve/Transfer 事件） | `PERC20Factory.sol:57-59` |
| I-08 | Info | git 提交信息"commit_ivk-free"已过时——`commit_ivk` 在 HEAD 中是活跃的所有权绑定约束，并非死代码 | `circuits/action.circom:117-127` |
| I-09 | Info | 杂项：`FrozenCmxNonMember` 根相等用 `IsEqual` 多耗 2 约束；建议 `assert(FR_BITS()==254)`；nullifier 标量 mod-p 归约需确认 Rust prover 一致（liveness） | 多处 |

---

## 3. 重点发现详述

### C-01（Critical，流程/供应链）— dev 可信设置验证器位于生产部署路径

`circuits/scripts/groth16_dev_setup.sh` 用**硬编码公开熵**（`-e="privacybtc-dev-zkey"`）和**硬编码公开 beacon**（`0102…1f`）生成 zkey，并直接导出到 `contracts/orchardverifier/Groth16PairingVerifier.sol`——该文件已提交进仓库，而 `script/Deploy.s.sol:23` 的生产部署 `new ActionGroth16Verifier()` 嵌入的正是这个 VK。任何人都能从公开参数重构 simulation trapdoor，对任意 `pub_hash` 伪造有效证明——凭空铸造 note 或花费他人 note，链上的 binding/spend-auth 签名无法补救（攻击者同样自选这些密钥）。`circuits/README.md` 已声明 dev zkey 仅限开发，但**没有任何机制阻止把 dev 验证器部署上主网**——默认即不安全。

**建议：**
1. dev 验证器移出部署脚本消费的路径（放 gitignore 的 build 目录）；
2. 完成真实多方 phase-2 仪式，发布 transcript、贡献者证明与最终 zkey 哈希；
3. `Deploy.s.sol` 加部署时断言：所部署 VK 哈希 == 固定的生产 VK 哈希，不匹配即 revert；
4. ptau 使用公共可验证文件（如 Perpetual Powers of Tau）并固定其哈希（当前 `PTAU` 来源未固定）。

### H-01（High，中心化）— Groth16 验证器可被 admin 即时热替换

```solidity
function setGroth16Verifier(address groth16Verifier_) external onlyAdmin {
    if (groth16Verifier_ == address(0)) revert ZeroAddress();
    ...
    groth16Verifier = IActionGroth16Verifier(groth16Verifier_);
}
```

验证器是 note 良构性、价值承诺、nullifier 推导、Merkle 成员、frozen 非成员的**唯一**执行者；链上 Schnorr 检查不足以兜底。单一 admin EOA 失陷 → 指向恒真验证器（`test/MockVerifier.sol` 即现成原语）→ 隐蔽无限增发，打破 `totalSupply ≈ Σ note 价值`。VK 本身不可注入（嵌入字节码，这点是对的），但验证器**地址**是热指针。

**建议：** 验证器按池不可变（轮换 = 部署新资产），或 48–72h timelock + 多签；把验证器地址列入每个资产的信任假设，便于钱包监控轮换。

### M-01（Medium）— 权力集中

单一 `admin`（部署时 = `issuer`）掌握 `setGroth16Verifier`、`setFrozenRoot`（可冻结全部流通或定向审查）、`setMaxActions`、宽限期设置；`issuer` 另持无上限、无速率限制的 `mint`。现有缓解仅两步 admin 转移。**建议：** 多签+timelock；合规角色（setFrozenRoot）与资产角色分离；在标准文档中披露 issuer 信任边界，可选 mint 上限。

### L-02（Low）— frozen IMT 良构性是链下信任

电路内的区间约束本身正确（`low_val < cmx` 严格、`next==0 ∨ cmx < next`、叶/节点域标签 240/256+ 分离、深度 20 包含性绑定 `rt_frozen`），但如果 admin/索引器发布过含有畸形 low-leaf（区间重叠或指针跳跃）的根，被冻结的 note 将可证非成员而被花费。另需确认链上 IMT 初始化含创世 `(0, first)` 叶，否则首次冻结后小于最小叶值的 `cmx` 将无法证明非成员（liveness）。**建议：** IMT 更新代码路径中对"插入即证明 `val < new < next`"加不变量测试。

### L-03（Low）— `abi.encodePacked` 相邻动态数组

`nullifiers` 与 `commitments` 紧邻打包是教科书式哈希歧义模式。当前不可利用（两数组恒等长、challenge 另经 `bvk` 独立绑定 cv 集合），但若未来 mint 动作不再 push commitment 项即变脆弱。**建议：** 改 `abi.encode` 或前置显式长度。

### L-06（Low）— dummy 动作的 nullifier/cmx

`v_old=0` 时跳过 Merkle 检查（shield/dummy 路径），电路内已验证该门控无法被 `v_old≠0` 的证明者滥用（同一 `v_old` 信号同时被承诺与 64 位范围约束），且零价值输入不能凭空生造价值。残留影响：① 攻击者可插入垃圾 nullifier/cmx（状态膨胀；定向 grief 真实 note 不可行——需要受害者的 `nk/rho/psi`）；② 两次 mint 复用同一 dummy note → 第二次 `NullifierSpent` revert（自伤型 liveness）；③ 接口注释"mint 用 nf==0"与实现（派生非零 dummy nullifier）不符。dummy nullifier 与真实 nullifier 的碰撞由电路推导的确定性保证（需 Poseidon 原像），**该信任边界已经电路侧核实闭合**。

---

## 4. 已验证为健全的关键性质（覆盖面声明）

**电路：**
- 唯一公开信号 `pub_hash`；8 个逻辑公开值（anchor, cv_net_x/y, nf_old, rk_x/y, cmx, rt_frozen）逐一被独立约束并经 Poseidon sponge 绑定（`action.circom:210-219`），无未使用公开输入、无顺序歧义。
- 所有标量乘法位数组经 `Recompose254/64`（逐位布尔 + AliasCheck 规范性 + `Bits2Num===scalar`）绑定，杀死 mod-p 别名第二分解。
- `v_old/v_new/magnitude ∈ [0,2^64)`；价值平衡 `v_old−v_new === magnitude·(1−2·sign)` 与 `cv_net` 的符号化 Pedersen 承诺绑定正确（扭曲 Edwards 取负 `(−x,y)` 实现正确）。
- nullifier 对 `(nk, rho, psi, cm_old)` 确定（无证明者自由度→无换 nullifier 双花）；`nf_old_pub` 复用为新 note 的 `rho`，强制 ρ 唯一。
- 所有权绑定：`pk_d_old = [CommitIvk(ak_x,nk,rivk)]·g_d_old`（`commit_ivk` 活跃且承重，I-08）；`rk = ak + [alpha]·G_SPEND_AUTH` 随机化不破坏绑定。
- 5 个外部见证点全部过 `BJJSubgroupCheck`（完整 BabyAdd/BabyDbl 梯子证 `[ℓ]P=O` 且排除单位元）；circomlib 加法公式在 BabyJubJub 上完备（a 是平方、d 非平方），无例外点健全性问题。
- Merkle 路径比特布尔约束、mux 健全、32 层逐层域标签；frozen 非成员绑定**被花费的** `cm_old_x`（H-01 修复确认）。
- `LessThanField` 基于 `Num2Bits_strict` 全域无别名严格比较，127+127 位切分无重叠/遗漏。
- Poseidon permute：8 全轮+56 部分轮（Orchard 参数）、部分轮仅 lane0 过 S-box 且 lane1/2 显式约束传递、全文件零 `<--`。
- 老/新承诺同域标签（160-163）为**协议必需**（输出 cmx 必须等于后续花费的 cm_old_x，亦是 frozen 黑名单键匹配的前提），非缺失域分离。

**合约：**
- 全部 8 个 `pubFields < FIELD_MODULUS` 先于使用检查（别名双花封死）；`pub_hash` 链上重算绑定 calldata。
- 预编译 0x06/0x07/0x08 staticcall 返回值全检查，失败不会默认成功；配对输入 768 字节正确；proof 点 A 取负正确，曲线/子群成员由 EIP-196/197 预编译强制。
- 空 bundle 拒绝、`maxActions ∈ [1,16]`、零 cmx 拒绝、bundle 内/跨 bundle 的 nullifier 与 cmx 重复均拒绝；anchor 校验对所有动作（含 shield）无条件对 `_allRootsEver` 永久集执行——电路侧 `v_old=0` 路径的 anchor 自由度由此闭合。
- 检查-生效顺序安全：proof+签名（view）→ binding 签名 → 写 nullifier → 插树；唯一外部调用是状态写入前的 view staticcall，重入面≈0。
- 两种 Schnorr：`s < ℓ` 规范化、R 与 proof 出示点 on-curve、sighash 含 chainId+合约地址（跨链/跨实例防重放）、spend-auth 以 proof 中的 rk 验证未被 proof 约束的字段（epk/密文）。
- 价值守恒：`bvk = Σcv − vbScalar·G_VALUE`，符号位编码三层一致；`amount < ℓ` 防 mod-ℓ 别名；burn 下溢守卫。
- 工厂/克隆：实现合约构造时锁定、clone+initialize 原子、CREATE2 盐绑定 `msg.sender`、EIP-1167 字节码与 OZ 规范一致。
- 克隆实例间 nullifier/树/根/冻结状态完全隔离。

**跨层：**
- 公开输入映射表（电路吸收顺序 ↔ `ActionPubHash.sol` ↔ Rust `action_pub_hash` ↔ `pub_fields.rs` calldata 序列化）逐字节一致；`DOMAIN_ACTION_V1`、`CAP9`、`CAP3` 三层一致。
- Poseidon 常量（抽查首轮常量与 MDS）、Merkle 深度/层标签/空叶、frozen IMT 空根常量、两种 sighash 构造、价值平衡符号约定：三层一致。

---

## 5. 既往审计问题状态（docs/audit-*.md 对照）

| 既往 ID | 问题 | 状态 |
|---|---|---|
| C-1（audit-2）公开 `bundle()` 绕过 issuer/供应 | **已修复**（核心路径仅 internal） |
| H-1（audit-2）pubFields 域模数别名双花 | **已修复**（全字段 < p + `pub[3]==nfOld`） |
| M-1（audit-2）历史根 O(n) 移位 | **已修复**（O(1) 环形缓冲 + `_allRootsEver`） |
| L-1/L-2/L-3、I-1（audit-2）R 不在曲线上 / 重复 cmx / 状态写入顺序 / KZG 死代码 | **均已修复** |
| C-01（audit-2）dev 可信设置 | **未修复** → 本轮 **C-01** |
| H-01（audit-contracts-perc20-1）验证器热替换 | **未修复** → 本轮 **H-01** |
| M-01（同上）admin 权力集中 | **未修复（设计接受）** → 本轮 **M-01** |
| L-01…L-05（同上）on-curve 检查 / s 可锻性 / maxActions / 宽限期 / nullifier-binding 顺序 | **全部已修复（逐项核实在位）** |
| H-01（电路侧）frozen 绑定 cmx_pub 而非 cm_old_x | **已修复**（`c8.cmx <== c1.cm_old_x`） |
| Issue A/B（v_new 范围 / 路径比特布尔） | **已修复（约束在位）** |
| H-01（audit-perc20-sol）issuer 无 mint 上限 | **未修复** → 并入 **M-01** |

---

## 6. 上线前行动清单（按优先级）

1. **【必须】** 真实 MPC phase-2 仪式；dev 验证器移出部署路径；`Deploy.s.sol` 加 VK 哈希断言；固定 ptau 来源（C-01）。
2. **【必须】** 验证器不可变或 timelock+多签；admin/issuer 多签化，合规角色分离（H-01/M-01）。
3. **【强烈建议】** frozen IMT 插入良构性不变量测试 + 创世叶初始化确认（L-02）。
4. **【建议】** binding sighash 改 `abi.encode`（L-03）；`outCiphertext` 长度校验（L-04）；`NullifierSpent` 误名修正（I-05）；接口 `nf==0` 注释更正（L-06）。
5. **【建议】** `PubHashAction`/`Hash3` 对 Rust 参考实现的独立跨实现测试向量（I-01/I-02）；NUMS 生成元来源文档化与独立验证（I-03）；确认 Rust prover 的 nullifier 标量先 mod-p 再 mod-ℓ（I-09）。
6. **【可选】** `BJJSubgroupCheck` 内置 `BabyCheck()`（L-01）；`assert(FR_BITS()==254)`；宽限期激活事件。
