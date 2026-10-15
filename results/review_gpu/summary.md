# Additional GPU runs: ten-epoch training, pseudo-labels and pipeline (T2 temporal split, seeds 0–2; generated automatically)

Completed runs: baseline (5 epochs) 3/3; v3.1 auxiliary (5 epochs) 3/3; baseline (10 epochs) 3/3; v3.1 auxiliary (10 epochs) 3/3; pseudo-labels (5 epochs) 3/3; DeBERTa pipeline (5 epochs) 3/3


## Mean ± standard deviation of each variant: all test labels (21,900)

| Variant | Seeds | mean_macro_f1 | exact_match | score_mae | band_acc | under_rate | hc_recall | Best epoch |
|---|---|---|---|---|---|---|---|---|
| baseline (5 epochs) | 3 | 0.606 ± 0.003 | 0.186 ± 0.009 | 1.440 ± 0.025 | 0.568 ± 0.003 | 0.163 ± 0.013 | 0.820 ± 0.018 | 4, 5, 5 / 5 |
| v3.1 auxiliary (5 epochs) | 3 | 0.644 ± 0.001 | 0.237 ± 0.004 | 1.169 ± 0.028 | 0.624 ± 0.003 | 0.137 ± 0.010 | 0.827 ± 0.007 | 5, 4, 4 / 5 |
| baseline (10 epochs) | 3 | 0.617 ± 0.001 | 0.201 ± 0.005 | 1.348 ± 0.053 | 0.592 ± 0.005 | 0.160 ± 0.036 | 0.816 ± 0.048 | 6, 7, 8 / 10 |
| v3.1 auxiliary (10 epochs) | 3 | 0.645 ± 0.004 | 0.237 ± 0.010 | 1.181 ± 0.017 | 0.631 ± 0.008 | 0.160 ± 0.010 | 0.796 ± 0.018 | 4, 6, 4 / 10 |
| pseudo-labels (5 epochs) | 3 | 0.643 ± 0.003 | 0.242 ± 0.011 | 1.130 ± 0.013 | 0.635 ± 0.006 | 0.130 ± 0.018 | 0.833 ± 0.026 | 4, 4, 4 / 5 |
| DeBERTa pipeline (5 epochs) | 3 | 0.601 ± 0.003 | 0.219 ± 0.008 | 1.138 ± 0.013 | 0.622 ± 0.007 | 0.111 ± 0.002 | 0.858 ± 0.007 | 5, 5, 5 / 5 |

## Mean ± standard deviation of each variant: without derived labels (16,749)

| Variant | Seeds | mean_macro_f1 | exact_match | score_mae | band_acc | under_rate | hc_recall | Best epoch |
|---|---|---|---|---|---|---|---|---|
| baseline (5 epochs) | 3 | 0.536 ± 0.003 | 0.109 ± 0.010 | 1.657 ± 0.038 | 0.467 ± 0.005 | 0.189 ± 0.018 | 0.832 ± 0.020 | 4, 5, 5 / 5 |
| v3.1 auxiliary (5 epochs) | 3 | 0.587 ± 0.005 | 0.164 ± 0.003 | 1.315 ± 0.034 | 0.537 ± 0.003 | 0.157 ± 0.013 | 0.839 ± 0.007 | 5, 4, 4 / 5 |
| baseline (10 epochs) | 3 | 0.553 ± 0.005 | 0.125 ± 0.008 | 1.546 ± 0.077 | 0.496 ± 0.005 | 0.187 ± 0.047 | 0.827 ± 0.051 | 6, 7, 8 / 10 |
| v3.1 auxiliary (10 epochs) | 3 | 0.590 ± 0.007 | 0.168 ± 0.009 | 1.330 ± 0.029 | 0.547 ± 0.011 | 0.186 ± 0.013 | 0.806 ± 0.019 | 4, 6, 4 / 10 |
| pseudo-labels (5 epochs) | 3 | 0.594 ± 0.000 | 0.173 ± 0.009 | 1.265 ± 0.013 | 0.552 ± 0.008 | 0.148 ± 0.022 | 0.845 ± 0.028 | 4, 4, 4 / 5 |
| DeBERTa pipeline (5 epochs) | 3 | 0.565 ± 0.003 | 0.193 ± 0.004 | 1.198 ± 0.012 | 0.561 ± 0.007 | 0.126 ± 0.007 | 0.861 ± 0.009 | 5, 5, 5 / 5 |

## Paired bootstrap: A − B (each averaged over seeds 0–2; 95% interval)

| A − B | Scope | Mean macro-F1 difference | Band accuracy difference | Underestimation difference | Score MAE difference |
|---|---|---|---|---|---|
| v3.1 auxiliary (10 epochs) − baseline (10 epochs) | all | +0.027 [+0.025, +0.029] | +0.039 [+0.035, +0.043] | -0.000 [-0.003, +0.003] | -0.168 [-0.181, -0.155] |
| v3.1 auxiliary (10 epochs) − baseline (10 epochs) | without derived | +0.037 [+0.035, +0.039] | +0.051 [+0.046, +0.056] | -0.001 [-0.005, +0.003] | -0.217 [-0.233, -0.198] |
| v3.1 auxiliary (5 epochs) − baseline (5 epochs) | all | +0.038 [+0.036, +0.040] | +0.055 [+0.051, +0.059] | -0.026 [-0.029, -0.023] | -0.272 [-0.288, -0.256] |
| v3.1 auxiliary (5 epochs) − baseline (5 epochs) | without derived | +0.051 [+0.049, +0.054] | +0.071 [+0.065, +0.076] | -0.031 [-0.035, -0.027] | -0.342 [-0.358, -0.322] |
| baseline (10 epochs) − baseline (5 epochs) | all | +0.011 [+0.010, +0.013] | +0.024 [+0.020, +0.027] | -0.003 [-0.006, -0.000] | -0.092 [-0.105, -0.080] |
| baseline (10 epochs) − baseline (5 epochs) | without derived | +0.017 [+0.015, +0.019] | +0.029 [+0.025, +0.033] | -0.001 [-0.004, +0.002] | -0.111 [-0.126, -0.094] |
| v3.1 auxiliary (10 epochs) − v3.1 auxiliary (5 epochs) | all | +0.001 [-0.001, +0.002] | +0.007 [+0.004, +0.011] | +0.023 [+0.020, +0.025] | +0.012 [+0.003, +0.022] |
| v3.1 auxiliary (10 epochs) − v3.1 auxiliary (5 epochs) | without derived | +0.003 [+0.001, +0.005] | +0.010 [+0.005, +0.014] | +0.029 [+0.026, +0.032] | +0.015 [+0.002, +0.028] |
| pseudo-labels (5 epochs) − baseline (5 epochs) | all | +0.037 [+0.035, +0.040] | +0.066 [+0.062, +0.071] | -0.033 [-0.036, -0.030] | -0.310 [-0.325, -0.295] |
| pseudo-labels (5 epochs) − baseline (5 epochs) | without derived | +0.057 [+0.055, +0.060] | +0.085 [+0.080, +0.091] | -0.041 [-0.044, -0.037] | -0.392 [-0.410, -0.372] |
| v3.1 auxiliary (5 epochs) − pseudo-labels (5 epochs) | all | +0.001 [-0.001, +0.003] | -0.011 [-0.015, -0.008] | +0.007 [+0.005, +0.010] | +0.038 [+0.028, +0.048] |
| v3.1 auxiliary (5 epochs) − pseudo-labels (5 epochs) | without derived | -0.006 [-0.008, -0.004] | -0.015 [-0.019, -0.011] | +0.010 [+0.006, +0.013] | +0.050 [+0.038, +0.062] |
| DeBERTa pipeline (5 epochs) − baseline (5 epochs) | all | -0.004 [-0.008, -0.001] | +0.054 [+0.048, +0.059] | -0.052 [-0.056, -0.048] | -0.302 [-0.322, -0.283] |
| DeBERTa pipeline (5 epochs) − baseline (5 epochs) | without derived | +0.029 [+0.026, +0.033] | +0.095 [+0.088, +0.101] | -0.062 [-0.067, -0.057] | -0.460 [-0.479, -0.438] |
| v3.1 auxiliary (5 epochs) − DeBERTa pipeline (5 epochs) | all | +0.042 [+0.040, +0.045] | +0.001 [-0.003, +0.006] | +0.027 [+0.023, +0.030] | +0.030 [+0.015, +0.046] |
| v3.1 auxiliary (5 epochs) − DeBERTa pipeline (5 epochs) | without derived | +0.022 [+0.018, +0.025] | -0.024 [-0.029, -0.019] | +0.031 [+0.027, +0.035] | +0.117 [+0.103, +0.133] |

## Per-metric macro-F1 (all test labels / without derived; mean over seeds)

| Variant | AV | AC | AT | PR | UI | VC | VI | VA | SC | SI | SA |
|---|---|---|---|---|---|---|---|---|---|---|---|
| baseline (5 epochs) | 0.577 / 0.540 | 0.662 / 0.592 | 0.645 / 0.615 | 0.550 / 0.541 | 0.589 / 0.544 | 0.695 / 0.537 | 0.683 / 0.498 | 0.746 / 0.542 | 0.548 / 0.535 | 0.553 / 0.541 | 0.420 / 0.412 |
| v3.1 auxiliary (5 epochs) | 0.721 / 0.688 | 0.680 / 0.596 | 0.645 / 0.624 | 0.667 / 0.694 | 0.631 / 0.593 | 0.733 / 0.599 | 0.721 / 0.593 | 0.755 / 0.573 | 0.549 / 0.538 | 0.558 / 0.548 | 0.421 / 0.416 |
| baseline (10 epochs) | 0.634 / 0.597 | 0.659 / 0.591 | 0.641 / 0.613 | 0.589 / 0.595 | 0.597 / 0.555 | 0.711 / 0.561 | 0.697 / 0.536 | 0.746 / 0.550 | 0.545 / 0.535 | 0.549 / 0.540 | 0.420 / 0.414 |
| v3.1 auxiliary (10 epochs) | 0.735 / 0.701 | 0.679 / 0.590 | 0.645 / 0.623 | 0.671 / 0.703 | 0.618 / 0.581 | 0.733 / 0.608 | 0.717 / 0.594 | 0.756 / 0.581 | 0.549 / 0.540 | 0.560 / 0.552 | 0.426 / 0.422 |
| pseudo-labels (5 epochs) | 0.722 / 0.689 | 0.688 / 0.616 | 0.600 / 0.583 | 0.673 / 0.704 | 0.590 / 0.564 | 0.726 / 0.611 | 0.724 / 0.613 | 0.757 / 0.569 | 0.574 / 0.567 | 0.581 / 0.574 | 0.440 / 0.439 |
| DeBERTa pipeline (5 epochs) | 0.721 / 0.690 | 0.677 / 0.591 | 0.458 / 0.444 | 0.645 / 0.704 | 0.509 / 0.484 | 0.694 / 0.620 | 0.707 / 0.627 | 0.713 / 0.576 | 0.555 / 0.551 | 0.566 / 0.563 | 0.372 / 0.371 |

## Reference: TF-IDF pipeline (rule R; results/pipeline_baseline)

| Scope | Mean macro-F1 | Exact | MAE | Band accuracy | Underestimation | H+C recall |
|---|---|---|---|---|---|---|
| all | 0.565 | 0.167 | 1.392 | 0.541 | 0.127 | 0.858 |
| non_derived | 0.546 | 0.164 | 1.310 | 0.539 | 0.150 | 0.851 |
