"""DeBERTa 推理测速（本机 CPU）：第 7.6 节"微调编码器可在本地运行"的依据。

- 模型结构与我们的模型相同：DeBERTa-v3-base + 11 个 v4.0 输出头（预测时不用辅助头）；
  推理耗时只取决于结构，与权重的具体数值无关，所以输出头用随机初始化即可（训练时未保存权重）；
- 输入与训练时相同："描述 + CWE 编号"，截断到 256 个词元；
- 从时间划分测试集中随机抽 500 条（种子 0）；
- 两种场景：逐条（batch = 1，前 100 条，报告中位数与 95 分位延迟）和批量（batch = 32，报告吞吐量，含分词时间）；
- 计时前先预热。
输入：models/deberta-v3-base（从 hf-mirror.com 下载的 config.json、pytorch_model.bin、spm.model、tokenizer_config.json）
运行：.venv-llm/Scripts/python.exe src/bench_inference.py（该环境装有分词器需要的 sentencepiece）
输出：results/bench_inference.json
"""

import json
import os
import platform
import sys
import time
from pathlib import Path

import numpy as np
import torch

sys.path.insert(0, str(Path(__file__).resolve().parent))
from baselines_v0 import CUTOFF, M40, load  # noqa: E402
from train_encoder import MultiHeadCVSS  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
MODEL_DIR = ROOT / "models" / "deberta-v3-base"
N, N_SINGLE, MAX_LEN, SEED = 500, 100, 256, 0  # 抽样总数；其中前 N_SINGLE 条用于逐条延迟，全部 N 条用于批量吞吐


@torch.inference_mode()
def run(model, tok, texts):
    enc = tok(texts, truncation=True, max_length=MAX_LEN, padding=True, return_tensors="pt")
    logits = model(enc["input_ids"], enc["attention_mask"])
    return {k: logits[k].argmax(-1) for k in M40}


def main():
    from transformers import AutoModel, AutoTokenizer
    df = load()
    texts = df[df["pub"] >= CUTOFF]["text"].sample(N, random_state=SEED).tolist()
    tok = AutoTokenizer.from_pretrained(MODEL_DIR)
    encoder = AutoModel.from_pretrained(MODEL_DIR).float()
    model = MultiHeadCVSS(encoder, encoder.config.hidden_size, n_sources=1, source_mode="none").eval()
    n_tokens = [min(len(tok(t)["input_ids"]), MAX_LEN) for t in texts]

    run(model, tok, texts[:8])  # 预热
    run(model, tok, texts[:1])
    lat = []
    for t in texts[:N_SINGLE]:  # 逐条
        t0 = time.perf_counter()
        run(model, tok, [t])
        lat.append(time.perf_counter() - t0)
    t0 = time.perf_counter()  # 批量
    for i in range(0, N, 32):
        run(model, tok, texts[i:i + 32])
    total = time.perf_counter() - t0

    res = {"n_sampled_cves": N, "single_latency_n_cves": N_SINGLE, "batch32_n_cves": N, "max_len": MAX_LEN,
           "mean_tokens": float(np.mean(n_tokens)), "median_tokens": float(np.median(n_tokens)),
           "single_latency_ms_median": 1000 * float(np.median(lat)), "single_latency_ms_p95": 1000 * float(np.percentile(lat, 95)),
           "batch32_total_s": total, "batch32_cves_per_s": N / total,
           "cpu": platform.processor(), "logical_cores": os.cpu_count(), "torch_threads": torch.get_num_threads(),
           "torch": torch.__version__, "transformers": __import__("transformers").__version__, "precision": "float32"}
    out = ROOT / "results" / "bench_inference.json"
    out.write_text(json.dumps(res, indent=1, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(res, indent=1, ensure_ascii=False))


if __name__ == "__main__":
    main()
