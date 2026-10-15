# Rule R on FIRST's official v4.0 examples (generated automatically)

Examples in version 1.8 of FIRST's examples document with both a v3.x and a v4.0 vector: 43 (of which 1 with a v3.0 vector). The first v3.x and the first v4.0 vector of each example are used (later vectors are variant scenarios discussed in the document).

| Scope | n | Rule R gives the identical vector | Same severity band | Rule R's band lower / higher |
|---|---|---|---|---|
| all examples | 43 | 14 (32.6%) | 34 (79.1%) | 3 / 6 |
| without the "new metrics" section | 33 | 13 (39.4%) | 27 (81.8%) | 2 / 4 |
| "new metrics" section | 10 | 1 (10.0%) | 7 (70.0%) | 1 / 2 |

## Per metric: examples where rule R agrees with FIRST's v4.0 vector

| AV | AC | AT | PR | UI | VC | VI | VA | SC | SI | SA |
|---|---|---|---|---|---|---|---|---|---|---|
| 43 | 39 | 34 | 43 | 37 | 34 | 35 | 39 | 35 | 34 | 34 |

(43 examples in total.)

## Values that rule R cannot produce

FIRST's v4.0 vectors contain AT:P in 9 examples (20.9%) and UI:A in 5 (11.6%); examples with at least one of them: 14.
Rule R keeps AC unchanged; examples where FIRST changes v3.x AC:H to AC:L: 4 (of 5 with AC:H in v3.x).
Examples with S:C in v3.x: 13; of these, examples where rule R agrees with FIRST on all six of VC/VI/VA/SC/SI/SA: 1.

## Details

| CVE | Section | v3.x vector | FIRST's v4.0 vector | Rule R | Identical | Band (FIRST / rule R) |
|---|---|---|---|---|---|---|
| CVE-2022-41741 | new_metric | AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H | AV:L/AC:L/AT:P/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N | AV:L/AC:H/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N | no | High / High |
| CVE-2020-3549 | new_metric | AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H | AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N | AV:N/AC:H/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N | no | High / Critical |
| CVE-2023-3089 | new_metric | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N | AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:L/VA:L/SC:N/SI:N/SA:N | AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N | no | High / High |
| CVE-2021-44714 | new_metric | AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N | AV:L/AC:L/AT:N/PR:N/UI:A/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N | AV:L/AC:L/AT:N/PR:N/UI:P/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N | no | Medium / Medium |
| CVE-2022-21830 | new_metric | AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N | AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N | AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:L/VA:N/SC:L/SI:L/SA:N | no | Medium / Medium |
| CVE-2022-22186 | new_metric | AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N | AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N | AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:L/SI:L/SA:N | no | Medium / Medium |
| CVE-2023-21989 | new_metric | AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:N/A:N | AV:L/AC:L/AT:N/PR:H/UI:N/VC:N/VI:N/VA:N/SC:H/SI:N/SA:N | AV:L/AC:L/AT:N/PR:H/UI:N/VC:H/VI:N/VA:N/SC:H/SI:N/SA:N | no | Medium / High |
| CVE-2020-3947 | new_metric | AV:L/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H | AV:L/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H | AV:L/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H | yes | Critical / Critical |
| CVE-2023-48228 | new_metric | AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N | AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:N/SC:H/SI:H/SA:H | AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N | no | Critical / High |
| CVE-2023-30560 | new_metric | AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H | AV:P/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:H/SA:N | AV:P/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N | no | High / High |
| CVE-2014-0160 | classic | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N | AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N | AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N | yes | High / High |
| CVE-2021-44228 | classic | AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H | AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N | AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H | no | Critical / Critical |
| CVE-2014-6271 | classic | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H | AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N | AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N | yes | Critical / Critical |
| CVE-2013-6014 | classic | AV:A/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:H | AV:A/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:N/SC:H/SI:N/SA:H | AV:A/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:H/SC:H/SI:N/SA:H | no | Medium / High |
| CVE-2016-5729 | classic | AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H | AV:L/AC:L/AT:N/PR:H/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N | AV:L/AC:L/AT:N/PR:H/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H | no | High / Critical |
| CVE-2015-2890 | classic | AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:H/A:H | AV:L/AC:L/AT:P/PR:H/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N | AV:L/AC:L/AT:N/PR:H/UI:N/VC:N/VI:H/VA:H/SC:N/SI:N/SA:N | no | High / Medium |
| CVE-2018-3652 | classic | AV:P/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H | AV:P/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N | AV:P/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H | no | High / High |
| CVE-2024-6387 | class | AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H | AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N | AV:N/AC:H/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N | no | Critical / Critical |
| CVE-2023-30545 | class | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N | AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N | AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N | yes | High / High |
| CVE-2021-23846 | class | AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N | AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N | AV:N/AC:H/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N | no | High / High |
| CVE-2023-22394 | class | AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H | AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:L | AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N | no | High / High |
| CVE-2022-24682 | class | AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N | AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N | AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:L/VA:N/SC:L/SI:L/SA:N | no | Medium / Medium |
| CVE-2020-0926 | class | AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N | AV:N/AC:L/AT:N/PR:L/UI:P/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N | AV:N/AC:L/AT:N/PR:L/UI:P/VC:L/VI:L/VA:N/SC:L/SI:L/SA:N | no | Medium / Medium |
| CVE-2024-55228 | class | AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:H | AV:N/AC:L/AT:N/PR:L/UI:A/VC:H/VI:H/VA:H/SC:L/SI:L/SA:N | AV:N/AC:L/AT:N/PR:L/UI:P/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H | no | High / Critical |
| CVE-2023-5602 | class | AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N | AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N | AV:N/AC:L/AT:N/PR:N/UI:P/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N | no | Medium / Medium |
| CVE-2022-20759 | class | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H | AV:N/AC:L/AT:P/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N | AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N | no | High / High |
| CVE-2021-34724 | class | AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:N | AV:L/AC:L/AT:N/PR:H/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N | AV:L/AC:L/AT:N/PR:H/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N | yes | High / High |
| CVE-2023-28311 | class | AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H | AV:L/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N | AV:L/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N | yes | High / High |
| CVE-2022-22965 | class | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H | AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N | AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N | no | Critical / Critical |
| CVE-2022-20826 | class | AV:P/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H | AV:P/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N | AV:P/AC:H/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N | no | Medium / Medium |
| CVE-2022-21500 | class | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N | AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N | AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N | yes | High / High |
| CVE-2021-32570 | class | AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N | AV:N/AC:L/AT:N/PR:H/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N | AV:N/AC:L/AT:N/PR:H/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N | yes | Medium / Medium |
| CVE-2022-26134 | class | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H | AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N | AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N | yes | Critical / Critical |
| CVE-2023-20245 | class | AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:N | AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:L/SA:N | AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:N/SC:N/SI:L/SA:N | no | Medium / Medium |
| CVE-2024-1233 | class | AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L | AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:N/SC:L/SI:L/SA:L | AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N | no | Medium / Medium |
| CVE-2023-28728 | class | AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H | AV:L/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N | AV:L/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N | yes | High / High |
| CVE-2022-47379 | class | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H | AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H | AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N | no | Critical / High |
| CVE-2020-10627 | class | AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N | AV:A/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N | AV:A/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N | yes | High / High |
| CVE-2020-28196 | class | AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H | AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N | AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N | yes | High / High |
| CVE-2023-20048 | class | AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:H | AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:N/VA:N/SC:H/SI:L/SA:H | AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:L/VA:H/SC:H/SI:L/SA:H | no | Medium / High |
| CVE-2024-23897 | class | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H | AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H | AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N | no | Critical / Critical |
| CVE-2026-31431 | class | AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H | AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N | AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N | yes | High / High |
| CVE-2026-42903 | class | AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H | AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N | AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N | yes | High / High |
