# FIRST 官方 v4.0 示例上的规则 R（自动生成）

FIRST 示例文档 1.8 版中同时给出 v3.x 向量和 v4.0 向量的示例：43 个（其中 v3.0 向量 1 个）。每个示例取第一个 v3.x 向量和第一个 v4.0 向量（后面的向量是文档讨论的变体场景）。

| 范围 | n | 规则 R 得到完全相同的向量 | 严重性等级相同 | 规则 R 的等级更低 / 更高 |
|---|---|---|---|---|
| 全部示例 | 43 | 14（32.6%） | 34（79.1%） | 3 / 6 |
| 不含"新指标"一节 | 33 | 13（39.4%） | 27（81.8%） | 2 / 4 |
| "新指标"一节 | 10 | 1（10.0%） | 7（70.0%） | 1 / 2 |

## 逐指标：规则 R 与 FIRST 的 v4.0 向量一致的示例数

| AV | AC | AT | PR | UI | VC | VI | VA | SC | SI | SA |
|---|---|---|---|---|---|---|---|---|---|---|
| 43 | 39 | 34 | 43 | 37 | 34 | 35 | 39 | 35 | 34 | 34 |

（共 43 个示例。）

## 规则 R 无法产生的取值

FIRST 的 v4.0 向量中 AT:P 有 9 个（20.9%），UI:A 有 5 个（11.6%）；至少含其中之一的示例 14 个。
规则 R 把 AC 原样保留；FIRST 把 v3.x 的 AC:H 改为 AC:L 的示例：4 个（v3.x 为 AC:H 的共 5 个）。
v3.x 为 S:C 的示例 13 个，其中规则 R 的 VC/VI/VA/SC/SI/SA 六项与 FIRST 全部一致的：1 个。

## 明细

| CVE | 节 | v3.x 向量 | FIRST 的 v4.0 向量 | 规则 R | 相同 | 等级（FIRST / 规则 R） |
|---|---|---|---|---|---|---|
| CVE-2022-41741 | new_metric | AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H | AV:L/AC:L/AT:P/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N | AV:L/AC:H/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N | 否 | High / High |
| CVE-2020-3549 | new_metric | AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H | AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N | AV:N/AC:H/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N | 否 | High / Critical |
| CVE-2023-3089 | new_metric | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N | AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:L/VA:L/SC:N/SI:N/SA:N | AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N | 否 | High / High |
| CVE-2021-44714 | new_metric | AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N | AV:L/AC:L/AT:N/PR:N/UI:A/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N | AV:L/AC:L/AT:N/PR:N/UI:P/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N | 否 | Medium / Medium |
| CVE-2022-21830 | new_metric | AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N | AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N | AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:L/VA:N/SC:L/SI:L/SA:N | 否 | Medium / Medium |
| CVE-2022-22186 | new_metric | AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N | AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N | AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:L/SI:L/SA:N | 否 | Medium / Medium |
| CVE-2023-21989 | new_metric | AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:N/A:N | AV:L/AC:L/AT:N/PR:H/UI:N/VC:N/VI:N/VA:N/SC:H/SI:N/SA:N | AV:L/AC:L/AT:N/PR:H/UI:N/VC:H/VI:N/VA:N/SC:H/SI:N/SA:N | 否 | Medium / High |
| CVE-2020-3947 | new_metric | AV:L/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H | AV:L/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H | AV:L/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H | 是 | Critical / Critical |
| CVE-2023-48228 | new_metric | AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N | AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:N/SC:H/SI:H/SA:H | AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N | 否 | Critical / High |
| CVE-2023-30560 | new_metric | AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H | AV:P/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:H/SA:N | AV:P/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N | 否 | High / High |
| CVE-2014-0160 | classic | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N | AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N | AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N | 是 | High / High |
| CVE-2021-44228 | classic | AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H | AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N | AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H | 否 | Critical / Critical |
| CVE-2014-6271 | classic | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H | AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N | AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N | 是 | Critical / Critical |
| CVE-2013-6014 | classic | AV:A/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:H | AV:A/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:N/SC:H/SI:N/SA:H | AV:A/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:H/SC:H/SI:N/SA:H | 否 | Medium / High |
| CVE-2016-5729 | classic | AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H | AV:L/AC:L/AT:N/PR:H/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N | AV:L/AC:L/AT:N/PR:H/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H | 否 | High / Critical |
| CVE-2015-2890 | classic | AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:H/A:H | AV:L/AC:L/AT:P/PR:H/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N | AV:L/AC:L/AT:N/PR:H/UI:N/VC:N/VI:H/VA:H/SC:N/SI:N/SA:N | 否 | High / Medium |
| CVE-2018-3652 | classic | AV:P/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H | AV:P/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N | AV:P/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H | 否 | High / High |
| CVE-2024-6387 | class | AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H | AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N | AV:N/AC:H/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N | 否 | Critical / Critical |
| CVE-2023-30545 | class | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N | AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N | AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N | 是 | High / High |
| CVE-2021-23846 | class | AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N | AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N | AV:N/AC:H/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N | 否 | High / High |
| CVE-2023-22394 | class | AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H | AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:L | AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N | 否 | High / High |
| CVE-2022-24682 | class | AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N | AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N | AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:L/VA:N/SC:L/SI:L/SA:N | 否 | Medium / Medium |
| CVE-2020-0926 | class | AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N | AV:N/AC:L/AT:N/PR:L/UI:P/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N | AV:N/AC:L/AT:N/PR:L/UI:P/VC:L/VI:L/VA:N/SC:L/SI:L/SA:N | 否 | Medium / Medium |
| CVE-2024-55228 | class | AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:H | AV:N/AC:L/AT:N/PR:L/UI:A/VC:H/VI:H/VA:H/SC:L/SI:L/SA:N | AV:N/AC:L/AT:N/PR:L/UI:P/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H | 否 | High / Critical |
| CVE-2023-5602 | class | AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N | AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N | AV:N/AC:L/AT:N/PR:N/UI:P/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N | 否 | Medium / Medium |
| CVE-2022-20759 | class | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H | AV:N/AC:L/AT:P/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N | AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N | 否 | High / High |
| CVE-2021-34724 | class | AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:N | AV:L/AC:L/AT:N/PR:H/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N | AV:L/AC:L/AT:N/PR:H/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N | 是 | High / High |
| CVE-2023-28311 | class | AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H | AV:L/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N | AV:L/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N | 是 | High / High |
| CVE-2022-22965 | class | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H | AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N | AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N | 否 | Critical / Critical |
| CVE-2022-20826 | class | AV:P/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H | AV:P/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N | AV:P/AC:H/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N | 否 | Medium / Medium |
| CVE-2022-21500 | class | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N | AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N | AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N | 是 | High / High |
| CVE-2021-32570 | class | AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N | AV:N/AC:L/AT:N/PR:H/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N | AV:N/AC:L/AT:N/PR:H/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N | 是 | Medium / Medium |
| CVE-2022-26134 | class | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H | AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N | AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N | 是 | Critical / Critical |
| CVE-2023-20245 | class | AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:N | AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:L/SA:N | AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:N/SC:N/SI:L/SA:N | 否 | Medium / Medium |
| CVE-2024-1233 | class | AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L | AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:N/SC:L/SI:L/SA:L | AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N | 否 | Medium / Medium |
| CVE-2023-28728 | class | AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H | AV:L/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N | AV:L/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N | 是 | High / High |
| CVE-2022-47379 | class | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H | AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H | AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N | 否 | Critical / High |
| CVE-2020-10627 | class | AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N | AV:A/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N | AV:A/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N | 是 | High / High |
| CVE-2020-28196 | class | AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H | AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N | AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N | 是 | High / High |
| CVE-2023-20048 | class | AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:H | AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:N/VA:N/SC:H/SI:L/SA:H | AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:L/VA:H/SC:H/SI:L/SA:H | 否 | Medium / High |
| CVE-2024-23897 | class | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H | AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H | AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N | 否 | Critical / Critical |
| CVE-2026-31431 | class | AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H | AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N | AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N | 是 | High / High |
| CVE-2026-42903 | class | AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H | AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N | AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N | 是 | High / High |
