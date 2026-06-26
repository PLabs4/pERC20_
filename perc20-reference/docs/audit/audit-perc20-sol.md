# PERC20 单合约安全审计报告

> 审计对象：`contracts/ptoken/PERC20.sol`
>  
> 审计目标：评估其作为隐私资产发行标准（pERC20）核心实现的安全性
>  
> 审计模型：**Codex 5.3**
>  
> 审计日期：2026-06-03
>  
> 审计方式：人工静态审计（以单合约为主，结合直接继承语义做必要校验）
>  
> 修复状态更新：2026-06-03（已合入构造函数零地址校验）

评级：Critical / High / Medium / Low / Informational

---

## 1. 执行摘要

`PERC20.sol` 的核心职责清晰：暴露 `mint` / `burn` / `transfer`，并维护公开 `totalSupply`。关键的证明与状态机校验由继承层完成。就“外部攻击者直接绕过权限或伪造状态”而言，本次未发现可直接利用的致命漏洞。

但作为“标准级隐私资产发行合约”，仍有一类关键风险与一项治理建议：

1. **治理与发行风险（High）**：发行权限单点集中且无总量上限，密钥失陷时可无限增发。
2. **初始化稳健性不足（Medium/Low）**：构造函数关键地址参数非零校验问题已修复。

---

## 2. 审计范围

- 主审文件：`contracts/ptoken/PERC20.sol`
- 关联语义核对：`contracts/orchardverifier/OrchardVerifier.sol`、`contracts/interfaces/IPERC20.sol`

> 说明：本报告重点是单合约行为与其标准化可用性，不覆盖 Groth16 电路仓库本身。

---

## 3. 发现列表

### H-01（High）：发行权单点 + 无上限，私钥失陷可无限增发

**描述**

`mint` 仅受 `onlyIssuer` 控制，且实现未引入 `mint cap`、节流机制或时间锁。该设计在标准层属于强信任模型：发行人私钥一旦泄露或滥用，可持续增发。

**影响**

- 资产可被无限通胀，信用模型快速失效。
- 对“标准合约”用户容易造成“技术安全=经济安全”的误解。

**建议**

- 将 `issuer` 运行于多签（最低要求）。
- 标准增强可选项：全局上限、阶段上限、时间锁生效。
- 在标准文档中明确披露发行方信任假设。

---

### M-01（Medium，已修复）：构造函数未校验 `issuer_ != address(0)`

**描述**

历史问题：构造函数直接写入 `issuer = issuer_`，未做非零校验。

**影响**

- 若误配为零地址，`mint` 永不可用（`onlyIssuer` 永不满足）。
- 与管理权限绑定场景下，实例可能出现不可恢复或高成本恢复的治理问题。

**建议**

- 已修复：新增 `error ZeroIssuer();`，并在构造函数中加入非零校验。

---

### L-01（Low，已修复）：构造函数未校验 `groth16Verifier_ != address(0)`

**描述**

历史问题：构造函数未阻止零地址验证器参数。

**影响**

- 合约可能在部署后处于初始不可用状态（需后续管理操作修复）。
- 增加上线窗口期事故概率。

**建议**

- 已修复：新增 `error ZeroVerifier();`，并在构造函数中加入非零校验。

---

## 4. 正向观察

- `mint` / `burn` 均限制 `amount < SUBGROUP_ORDER`，避免金额与群标量错位。
- `burn` 具备符号位与供应下溢防护，公开账本语义清晰。
- `transfer` 不修改 `_totalSupply`，供应变化与操作类型职责分离明确。

---

## 5. 结论

在当前实现下，`PERC20.sol` 的基础流程可工作，且初始化零地址风险已修复。若作为“隐私资产发行标准模板”推广，剩余主要风险集中在发行治理模型（单点发行与无上限）。

1. 将发行权限部署为多签，并在标准文本中明确中心化信任边界。
2. 可选增加发行上限/时间锁等治理控制。

---

## 6. 修复落地记录

已在 `PERC20.sol` 中新增：

- `error ZeroIssuer();`
- `error ZeroVerifier();`

并在构造函数中加入：

- `if (issuer_ == address(0)) revert ZeroIssuer();`
- `if (groth16Verifier_ == address(0)) revert ZeroVerifier();`

同时已新增测试用例：

- `test_constructor_zero_issuer_reverts`
- `test_constructor_zero_verifier_reverts`

上述修复不改变现有对外接口语义，且可显著降低部署配置风险。
