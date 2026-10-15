# 5% of the labels + v3.1 auxiliary task against all labels, no auxiliary task, 25 epochs (temporal split, seeds 0–2; generated automatically)


## all: n = 21,900

| Variant | Seeds | Mean macro-F1 (mean ± sd) | Band accuracy |
|---|---|---|---|
| 5% + v3.1 auxiliary | 3 | 0.618 ± 0.004 | 0.609 |
| all labels, baseline 25 epochs | 3 | 0.622 ± 0.002 | 0.606 |

| A − B | Common seeds | Mean macro-F1 difference | Band accuracy difference |
|---|---|---|---|
| 5% + v3.1 auxiliary − all labels, baseline 25 epochs | 3 | -0.004 [-0.007, -0.001] | +0.003 [-0.002, +0.008] |

## non-derived: n = 16,749

| Variant | Seeds | Mean macro-F1 (mean ± sd) | Band accuracy |
|---|---|---|---|
| 5% + v3.1 auxiliary | 3 | 0.562 ± 0.008 | 0.526 |
| all labels, baseline 25 epochs | 3 | 0.568 ± 0.002 | 0.515 |

| A − B | Common seeds | Mean macro-F1 difference | Band accuracy difference |
|---|---|---|---|
| 5% + v3.1 auxiliary − all labels, baseline 25 epochs | 3 | -0.006 [-0.009, -0.003] | +0.012 [+0.006, +0.018] |

## R-inconsistent: n = 2,602

| Variant | Seeds | Mean macro-F1 (mean ± sd) | Band accuracy |
|---|---|---|---|
| 5% + v3.1 auxiliary | 3 | 0.550 ± 0.003 | 0.520 |
| all labels, baseline 25 epochs | 3 | 0.567 ± 0.001 | 0.522 |

| A − B | Common seeds | Mean macro-F1 difference | Band accuracy difference |
|---|---|---|---|
| 5% + v3.1 auxiliary − all labels, baseline 25 epochs | 3 | -0.017 [-0.023, -0.010] | -0.001 [-0.015, +0.013] |
