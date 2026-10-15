# Baselines v0 (CPU, generated automatically)

Metrics: meanF1 = mean macro-F1 over the 11 v4 metrics; exact = share with all 11 metrics correct; MAE = mean absolute error of the v4.0 score; 
band = severity band accuracy; under = underestimation rate (predicted band < true band); HC-rec = share of true High/Critical labels predicted as High/Critical; ρ = Spearman rank correlation of the scores


## T1 · temporal (training 10,396 / test 13,077)

| Method | meanF1 | exact | MAE | band | under | HC-rec | ρ | F1-AV | F1-AC | F1-AT | F1-PR | F1-UI | F1-VC | F1-VI | F1-VA | F1-SC | F1-SI | F1-SA |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| majority | 0.286 | 0.084 | 1.89 | 0.519 | 0.456 | 0.000 | nan | 0.23 | 0.48 | 0.48 | 0.20 | 0.30 | 0.16 | 0.19 | 0.15 | 0.31 | 0.31 | 0.32 |
| rule_R | 0.865 | 0.801 | 0.14 | 0.951 | 0.009 | 0.988 | 0.943 | 0.97 | 0.92 | 0.48 | 0.98 | 0.60 | 0.94 | 0.95 | 0.98 | 0.93 | 0.93 | 0.82 |
| cond_map | 0.868 | 0.768 | 0.16 | 0.942 | 0.015 | 0.978 | 0.940 | 0.97 | 0.92 | 0.63 | 0.98 | 0.74 | 0.95 | 0.95 | 0.97 | 0.88 | 0.85 | 0.72 |
| tfidf_lr+v31 | 0.871 | 0.780 | 0.15 | 0.944 | 0.017 | 0.983 | 0.941 | 0.97 | 0.92 | 0.67 | 0.98 | 0.71 | 0.95 | 0.95 | 0.98 | 0.88 | 0.87 | 0.70 |

By label type (meanF1 / F1 of the v4-specific metrics / band accuracy / underestimation rate):
- majority: derived(n=5,151) 0.321/0.359/0.806/0.164; independent(n=6,765) 0.256/0.338/0.336/0.643; other(n=1,161) 0.252/0.330/0.312/0.659
- rule_R: derived(n=5,151) 0.924/0.833/1.000/0.000; independent(n=6,765) 0.840/0.737/0.922/0.014; other(n=1,161) 0.814/0.675/0.901/0.020
- cond_map: derived(n=5,151) 0.908/0.799/1.000/0.000; independent(n=6,765) 0.837/0.739/0.907/0.023; other(n=1,161) 0.810/0.675/0.892/0.039
- tfidf_lr+v31: derived(n=5,151) 0.757/0.466/0.987/0.013; independent(n=6,765) 0.861/0.786/0.918/0.020; other(n=1,161) 0.838/0.727/0.904/0.020

## T1 · loso:VulDB (training 10,591 / test 12,882)

| Method | meanF1 | exact | MAE | band | under | HC-rec | ρ | F1-AV | F1-AC | F1-AT | F1-PR | F1-UI | F1-VC | F1-VI | F1-VA | F1-SC | F1-SI | F1-SA |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| majority | 0.268 | 0.014 | 3.21 | 0.024 | 0.000 | 1.000 | nan | 0.24 | 0.49 | 0.50 | 0.18 | 0.31 | 0.08 | 0.08 | 0.08 | 0.33 | 0.33 | 0.33 |
| rule_R | 0.919 | 0.965 | 0.02 | 1.000 | 0.000 | 1.000 | 0.988 | 1.00 | 1.00 | 0.50 | 1.00 | 0.62 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 |
| cond_map | 0.896 | 0.849 | 0.05 | 0.998 | 0.000 | 1.000 | 0.967 | 1.00 | 0.98 | 0.49 | 1.00 | 0.49 | 1.00 | 1.00 | 1.00 | 1.00 | 0.98 | 0.93 |
| tfidf_lr+v31 | 0.904 | 0.887 | 0.03 | 1.000 | 0.000 | 1.000 | 0.972 | 1.00 | 0.95 | 0.49 | 1.00 | 0.57 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 0.93 |

By label type (meanF1 / F1 of the v4-specific metrics / band accuracy / underestimation rate):
- majority: derived(n=12,882) 0.268/0.361/0.024/0.000
- rule_R: derived(n=12,882) 0.919/0.823/1.000/0.000
- cond_map: derived(n=12,882) 0.896/0.777/0.998/0.000
- tfidf_lr+v31: derived(n=12,882) 0.904/0.798/1.000/0.000

## T1 · loso:VulnCheck (training 17,169 / test 6,304)

| Method | meanF1 | exact | MAE | band | under | HC-rec | ρ | F1-AV | F1-AC | F1-AT | F1-PR | F1-UI | F1-VC | F1-VI | F1-VA | F1-SC | F1-SI | F1-SA |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| majority | 0.257 | 0.002 | 2.31 | 0.345 | 0.633 | 0.000 | nan | 0.22 | 0.48 | 0.47 | 0.19 | 0.28 | 0.09 | 0.12 | 0.05 | 0.30 | 0.30 | 0.33 |
| rule_R | 0.841 | 0.677 | 0.25 | 0.915 | 0.016 | 0.983 | 0.891 | 0.92 | 0.93 | 0.47 | 0.95 | 0.56 | 0.86 | 0.89 | 0.94 | 0.95 | 0.94 | 0.83 |
| cond_map | 0.823 | 0.634 | 0.30 | 0.895 | 0.032 | 0.962 | 0.874 | 0.92 | 0.88 | 0.61 | 0.94 | 0.64 | 0.87 | 0.89 | 0.92 | 0.90 | 0.87 | 0.61 |
| tfidf_lr+v31 | 0.860 | 0.651 | 0.27 | 0.911 | 0.019 | 0.980 | 0.891 | 0.92 | 0.86 | 0.68 | 0.95 | 0.65 | 0.87 | 0.90 | 0.94 | 0.95 | 0.94 | 0.80 |

By label type (meanF1 / F1 of the v4-specific metrics / band accuracy / underestimation rate):
- majority: independent(n=6,304) 0.257/0.337/0.345/0.633
- rule_R: independent(n=6,304) 0.841/0.751/0.915/0.016
- cond_map: independent(n=6,304) 0.823/0.726/0.895/0.032
- tfidf_lr+v31: independent(n=6,304) 0.860/0.804/0.911/0.019

## T2 · temporal (training 16,097 / test 21,900)

| Method | meanF1 | exact | MAE | band | under | HC-rec | ρ | F1-AV | F1-AC | F1-AT | F1-PR | F1-UI | F1-VC | F1-VI | F1-VA | F1-SC | F1-SI | F1-SA |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| majority | 0.276 | 0.051 | 1.46 | 0.469 | 0.492 | 0.000 | nan | 0.22 | 0.48 | 0.46 | 0.23 | 0.29 | 0.14 | 0.16 | 0.13 | 0.30 | 0.30 | 0.32 |
| tfidf_lr | 0.605 | 0.237 | 1.33 | 0.598 | 0.136 | 0.854 | 0.523 | 0.62 | 0.66 | 0.53 | 0.61 | 0.63 | 0.70 | 0.70 | 0.75 | 0.53 | 0.53 | 0.40 |

By label type (meanF1 / F1 of the v4-specific metrics / band accuracy / underestimation rate):
- majority: derived(n=5,151) 0.317/0.359/0.806/0.164; independent(n=7,242) 0.261/0.336/0.343/0.635; v4_only(n=4,264) 0.259/0.323/0.401/0.554; other(n=5,243) 0.253/0.317/0.367/0.566
- tfidf_lr: derived(n=5,151) 0.624/0.420/0.904/0.074; independent(n=7,242) 0.580/0.551/0.572/0.096; v4_only(n=4,264) 0.488/0.451/0.436/0.237; other(n=5,243) 0.524/0.478/0.466/0.171

## T2 · loso:VulDB (training 25,115 / test 12,882)

| Method | meanF1 | exact | MAE | band | under | HC-rec | ρ | F1-AV | F1-AC | F1-AT | F1-PR | F1-UI | F1-VC | F1-VI | F1-VA | F1-SC | F1-SI | F1-SA |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| majority | 0.272 | 0.000 | 3.21 | 0.024 | 0.000 | 1.000 | nan | 0.24 | 0.49 | 0.50 | 0.18 | 0.31 | 0.08 | 0.08 | 0.12 | 0.33 | 0.33 | 0.33 |
| tfidf_lr | 0.366 | 0.018 | 2.83 | 0.152 | 0.065 | 0.976 | 0.264 | 0.46 | 0.50 | 0.50 | 0.22 | 0.48 | 0.25 | 0.30 | 0.33 | 0.33 | 0.33 | 0.33 |

By label type (meanF1 / F1 of the v4-specific metrics / band accuracy / underestimation rate):
- majority: derived(n=12,882) 0.272/0.361/0.024/0.000
- tfidf_lr: derived(n=12,882) 0.366/0.391/0.152/0.065

## T2 · loso:VulnCheck (training 30,568 / test 7,429)

| Method | meanF1 | exact | MAE | band | under | HC-rec | ρ | F1-AV | F1-AC | F1-AT | F1-PR | F1-UI | F1-VC | F1-VI | F1-VA | F1-SC | F1-SI | F1-SA |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| majority | 0.277 | 0.006 | 1.51 | 0.337 | 0.643 | 0.000 | nan | 0.23 | 0.48 | 0.47 | 0.24 | 0.28 | 0.09 | 0.11 | 0.22 | 0.29 | 0.30 | 0.32 |
| tfidf_lr | 0.562 | 0.225 | 1.13 | 0.572 | 0.104 | 0.920 | 0.546 | 0.55 | 0.50 | 0.55 | 0.65 | 0.64 | 0.61 | 0.58 | 0.56 | 0.59 | 0.59 | 0.37 |

By label type (meanF1 / F1 of the v4-specific metrics / band accuracy / underestimation rate):
- majority: independent(n=7,429) 0.277/0.335/0.337/0.643
- tfidf_lr: independent(n=7,429) 0.562/0.548/0.572/0.104

## T2 · loso:GitHub_M (training 32,868 / test 5,129)

| Method | meanF1 | exact | MAE | band | under | HC-rec | ρ | F1-AV | F1-AC | F1-AT | F1-PR | F1-UI | F1-VC | F1-VI | F1-VA | F1-SC | F1-SI | F1-SA |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| majority | 0.283 | 0.004 | 1.73 | 0.412 | 0.150 | 1.000 | nan | 0.24 | 0.48 | 0.43 | 0.26 | 0.29 | 0.20 | 0.10 | 0.23 | 0.29 | 0.29 | 0.31 |
| tfidf_lr | 0.481 | 0.110 | 1.66 | 0.484 | 0.226 | 0.775 | 0.391 | 0.34 | 0.50 | 0.52 | 0.54 | 0.52 | 0.57 | 0.56 | 0.56 | 0.43 | 0.42 | 0.33 |

By label type (meanF1 / F1 of the v4-specific metrics / band accuracy / underestimation rate):
- majority: v4_only(n=5,129) 0.283/0.322/0.412/0.150
- tfidf_lr: v4_only(n=5,129) 0.481/0.444/0.484/0.226