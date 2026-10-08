"""W3 编码器模型：DeBERTa-v3 / ModernBERT + 11 个 v4.0 指标分类头（可选：来源感知层）。

在 GPU 平台（如 AutoDL）上运行；本机可以用 --smoke_test 在 CPU 上跑通流程（随机初始化的小模型，不下载任何东西）。

来源感知层（--source_mode crowd）：
  模型先输出"去掉来源习惯后"的潜在分布 p(z|x)，再对每个来源 s、每个指标 m 乘一个可学习的转移矩阵
  T[s,m]（行 = 潜在取值，列 = 该来源记录的取值）：p(y|x,s) = p(z|x) · T[s,m]；训练损失在 p(y|x,s) 上计算。
  正则项 λ·mean(trace(T)) 参考 Tanno et al., CVPR 2019（doi:10.1109/cvpr.2019.01150）：
  最小化迹，促使来源矩阵吸收系统性偏差，而分类器保持"干净"。
  评测时：对未见来源用 p(z|x)；对训练中见过的来源，另外报告 p(z|x)·T[s] 的结果。

用法示例（在项目根目录）：
  python src/train_encoder.py --task T2 --split temporal --model microsoft/deberta-v3-base --source_mode none
  python src/train_encoder.py --task T2 --split temporal --model microsoft/deberta-v3-base --source_mode crowd --trace_lambda 0.01
  python src/train_encoder.py --smoke_test
"""

import argparse
import json
import random
import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.utils.data import DataLoader, Dataset

sys.path.insert(0, str(Path(__file__).resolve().parent))
from baselines_v0 import CUTOFF, M31, M40, SHORT, evaluate, load, source_type_map  # noqa: E402
from cvss_utils import V31_METRICS, V40_METRICS  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
LABELS = {k: V40_METRICS[k] for k in M40}
L2I = {k: {v: i for i, v in enumerate(vals)} for k, vals in LABELS.items()}
L2I31 = {k: {v: i for i, v in enumerate(vals)} for k, vals in V31_METRICS.items()}


def set_seed(seed):
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    torch.cuda.manual_seed_all(seed)


# ---------------- 数据 ----------------

def build_text(row, task, with_source):
    parts = []
    if with_source:
        parts.append(f"[SOURCE] {row['source']}")
    parts.append(row["text"])
    if task == "T1":
        parts.append("[CVSS 3.1] " + " ".join(f"{k}:{row['x31_' + k]}" for k in M31))
    return " ".join(parts)


IGNORE = -100  # 缺失标签（辅助样本没有 v4 标签；部分 v4 样本没有 v3.1 标签）


def first_cwe(cna, adp):
    """一个 CVE 的第一个 CWE 编号：先看 CNA 容器，再看 ADP 容器；都没有时返回 None。"""
    for c in list(cna) + list(adp):
        return c
    return None


def label_matrix(df, prefix, label_index):
    cols = []
    for k, idx in label_index.items():
        col = df[prefix + k] if prefix + k in df else pd.Series([None] * len(df), index=df.index)
        cols.append(col.map(idx).fillna(IGNORE).astype(np.int64).values)
    return np.stack(cols, axis=1)


class CVEDataset(Dataset):
    """v4 标签在 y_* 列，v3.1 标签在 z_* 列（用于辅助任务）；缺失记为 IGNORE。"""

    def __init__(self, df, tokenizer, max_len, task, with_source, source_index):
        self.texts = [build_text(r, task, with_source) for _, r in df.iterrows()]
        self.labels = label_matrix(df, "y_", L2I)
        self.labels31 = label_matrix(df, "z_", L2I31)
        self.labels_ps = label_matrix(df, "p_", L2I)  # --pseudo_v4：辅助样本的 v4 伪标签（规则 R 换算），其余样本为 IGNORE
        self.labels_cwe = (df["c_CWE"].fillna(IGNORE).astype(np.int64).values if "c_CWE" in df
                           else np.full(len(df), IGNORE, dtype=np.int64))  # 只有 --aux_cwe 时训练集才有这一列
        self.src = df["source"].map(lambda s: source_index.get(s, source_index["__OTHER__"])).values
        self.tok, self.max_len = tokenizer, max_len

    def __len__(self):
        return len(self.texts)

    def __getitem__(self, i):
        return self.texts[i], self.labels[i], self.labels31[i], self.src[i], self.labels_cwe[i], self.labels_ps[i]

    def collate(self, batch):
        texts, labels, labels31, src, labels_cwe, labels_ps = zip(*batch)
        enc = self.tok(list(texts), truncation=True, max_length=self.max_len, padding=True, return_tensors="pt")
        enc["labels"] = torch.tensor(np.stack(labels))
        enc["labels31"] = torch.tensor(np.stack(labels31))
        enc["labels_cwe"] = torch.tensor(np.array(labels_cwe, dtype=np.int64))
        enc["labels_ps"] = torch.tensor(np.stack(labels_ps))
        enc["src"] = torch.tensor(src)
        return enc


def aux_pool(split, heldout_source, max_n, seed, exclude=None):
    """辅助任务样本：只有 v3.1、没有 CNA v4.0 的 CVE。时间划分时只用 2026 年前的；留一来源时去掉被留出的来源。
    exclude：要先去掉的 CVE（--exclude_ids 的 pool 键），在抽样之前去掉，所以样本数不变（池子够大时）。"""
    from pilot_transfer import v31_pool  # 延迟导入：只有 --aux_v31 时才需要
    pool = v31_pool() if split == "temporal" else v31_pool(before_cutoff=False)
    pool["source"] = pool["cna_short_name"].fillna("UNKNOWN")
    if heldout_source:
        pool = pool[pool["source"] != heldout_source]
    if exclude:
        n0 = len(pool)
        pool = pool[~pool["cve_id"].isin(exclude)]
        print(f"辅助样本池去掉截止日期后更新过的 {n0 - len(pool):,} 条，剩 {len(pool):,} 条", flush=True)
    if len(pool) > max_n:
        pool = pool.sample(max_n, random_state=seed)
    return pool


# ---------------- 模型 ----------------

class MultiHeadCVSS(nn.Module):
    def __init__(self, encoder, hidden, n_sources, source_mode, aux_v31=False, dropout=0.1, n_cwe=0):
        super().__init__()
        self.encoder, self.source_mode = encoder, source_mode
        self.dropout = nn.Dropout(dropout)
        self.heads = nn.ModuleDict({k: nn.Linear(hidden, len(v)) for k, v in LABELS.items()})
        # 辅助任务：8 个 v3.1 指标头（键名加 "v31_" 前缀，避免与同名的 v4 指标冲突）
        self.aux_heads = nn.ModuleDict({"v31_" + k: nn.Linear(hidden, len(v)) for k, v in V31_METRICS.items()}) if aux_v31 else None
        # 对照实验：CWE 类别头（--aux_cwe），与 v3.1 辅助头二选一
        self.cwe_head = nn.Linear(hidden, n_cwe) if n_cwe else None
        if source_mode == "crowd":
            # 转移矩阵参数初始化为"接近单位阵"（对角线 logits = 4）：一开始假设来源没有偏差
            self.trans = nn.ParameterDict({
                k: nn.Parameter(torch.eye(len(v)).repeat(n_sources, 1, 1) * 4.0) for k, v in LABELS.items()
            })

    def forward(self, input_ids, attention_mask, token_type_ids=None):
        out = self.encoder(input_ids=input_ids, attention_mask=attention_mask)
        h = self.dropout(out.last_hidden_state[:, 0])  # 取第一个 token 的表示
        logits = {k: head(h) for k, head in self.heads.items()}
        if self.aux_heads is not None:
            logits.update({k: head(h) for k, head in self.aux_heads.items()})
        if self.cwe_head is not None:
            logits["cwe"] = self.cwe_head(h)
        return logits

    def source_probs(self, logits, src):
        """p(y|x,s) = p(z|x) · T[s]，逐个 v4 指标计算。"""
        out = {}
        for k in M40:
            T = torch.softmax(self.trans[k][src].float(), dim=-1)  # (B, K, K)，每行和为 1
            # GPU 半精度（bf16）推理时 logits 是 bf16，统一转成 float32 再相乘，避免类型不一致
            out[k] = torch.bmm(torch.softmax(logits[k].float(), -1).unsqueeze(1), T).squeeze(1)
        return out

    def trace_penalty(self):
        return torch.stack([torch.softmax(p, -1).diagonal(dim1=1, dim2=2).sum(-1).mean() for p in self.trans.values()]).mean()


def masked_nll(log_probs, target, weight=None):
    """忽略 IGNORE 标签的负对数似然（可带类别权重）；整批都缺失时返回 0（保持计算图）。"""
    m = target != IGNORE
    return F.nll_loss(log_probs[m], target[m], weight=weight) if m.any() else log_probs.sum() * 0.0


def class_weights(train, mode, device):
    """按训练集 v4 标签频率计算类别权重：inv_sqrt 为 (N / (K·n_c))^0.5；none 返回 None。"""
    if mode == "none":
        return None
    out = {}
    for k in M40:
        counts = train["y_" + k].map(L2I[k]).dropna().astype(int).value_counts()
        n = np.array([counts.get(i, 0) for i in range(len(LABELS[k]))], dtype=float) + 1.0  # +1 平滑，避免除零
        w = (n.sum() / (len(n) * n)) ** 0.5
        out[k] = torch.tensor(w, dtype=torch.float32, device=device)
    return out


def compute_loss(model, logits, labels, labels31, src, args, cw=None, labels_cwe=None, labels_ps=None):
    cw = cw or {}
    if args.source_mode == "crowd":
        probs = model.source_probs(logits, src)
        loss = sum(masked_nll(torch.log(probs[k].clamp_min(1e-8)), labels[:, i], cw.get(k)) for i, k in enumerate(M40)) / len(M40)
        loss = loss + args.trace_lambda * model.trace_penalty()
    else:
        loss = sum(masked_nll(F.log_softmax(logits[k], -1), labels[:, i], cw.get(k)) for i, k in enumerate(M40)) / len(M40)
    if model.aux_heads is not None:
        aux = sum(masked_nll(F.log_softmax(logits["v31_" + k], -1), labels31[:, i]) for i, k in enumerate(V31_METRICS)) / len(V31_METRICS)
        loss = loss + (1.0 if args.v31_only else args.aux_lambda) * aux  # 流水线只有 v3.1 这一项损失
    if args.pseudo_v4 and labels_ps is not None:  # 伪标签对照：与 v4 真标签同样的类别权重，整体乘 λ（与辅助任务的权重相同）
        ps = sum(masked_nll(F.log_softmax(logits[k], -1), labels_ps[:, i], cw.get(k)) for i, k in enumerate(M40)) / len(M40)
        loss = loss + args.aux_lambda * ps
    if getattr(model, "cwe_head", None) is not None and labels_cwe is not None:
        loss = loss + args.aux_lambda * masked_nll(F.log_softmax(logits["cwe"], -1), labels_cwe)
    return loss


@torch.no_grad()
def predict(model, loader, device, amp_dtype, use_source_T=False):
    """返回 (预测类别 DataFrame, {指标: 概率数组 (n, K)})。"""
    model.eval()
    probs_all = {k: [] for k in M40}
    for batch in loader:
        batch = {k: v.to(device) for k, v in batch.items()}
        with torch.autocast(device_type=device.type, dtype=amp_dtype, enabled=amp_dtype is not None):
            logits = model(batch["input_ids"], batch["attention_mask"])
        probs = model.source_probs(logits, batch["src"]) if use_source_T else {k: torch.softmax(logits[k].float(), -1) for k in M40}
        for k in M40:
            probs_all[k].append(probs[k].float().cpu().numpy())
    probs_all = {k: np.concatenate(v) for k, v in probs_all.items()}
    preds = pd.DataFrame({k: np.array(LABELS[k])[p.argmax(1)] for k, p in probs_all.items()})
    return preds, probs_all


@torch.no_grad()
def predict_pipeline(model, loader, device, amp_dtype):
    """流水线（--v31_only）：用 v3.1 头预测 v3.1 向量，再按规则 R 换算成 v4.0 向量。"""
    from rq1_stats import rule_convert
    model.eval()
    preds = {k: [] for k in V31_METRICS}
    for batch in loader:
        batch = {k: v.to(device) for k, v in batch.items()}
        with torch.autocast(device_type=device.type, dtype=amp_dtype, enabled=amp_dtype is not None):
            logits = model(batch["input_ids"], batch["attention_mask"])
        for k in V31_METRICS:
            preds[k].append(logits["v31_" + k].float().argmax(-1).cpu().numpy())
    v31 = pd.DataFrame({k: np.array(V31_METRICS[k])[np.concatenate(v)] for k, v in preds.items()})
    return pd.DataFrame([rule_convert({k: r[k] for k in M31}) for _, r in v31.iterrows()])[M40]


# ---------------- 划分 ----------------

def make_split(df, split, task):
    data = df[df["has_v31"]] if task == "T1" else df
    if split == "temporal":
        train, test = data[data["pub"] < CUTOFF], data[data["pub"] >= CUTOFF]
    elif split.startswith("loso:"):
        s = split.split(":", 1)[1]
        train, test = data[data["source"] != s], data[data["source"] == s]
    else:
        raise ValueError(split)
    # 验证集：训练集里最晚发布的 10%（按时间，避免泄漏）
    train = train.sort_values("pub")
    n_val = max(1, int(0.1 * len(train)))
    return train.iloc[:-n_val], train.iloc[-n_val:], test


# ---------------- 烟雾测试用：本地随机小模型 ----------------

def smoke_components(texts):
    from tokenizers import Tokenizer, models, normalizers, pre_tokenizers, trainers
    from transformers import BertConfig, BertModel, PreTrainedTokenizerFast
    tk = Tokenizer(models.WordPiece(unk_token="[UNK]"))
    tk.normalizer = normalizers.BertNormalizer(lowercase=True)
    tk.pre_tokenizer = pre_tokenizers.BertPreTokenizer()
    tk.train_from_iterator(texts, trainers.WordPieceTrainer(vocab_size=3000, special_tokens=["[PAD]", "[UNK]", "[CLS]", "[SEP]"]))
    tok = PreTrainedTokenizerFast(tokenizer_object=tk, unk_token="[UNK]", pad_token="[PAD]", cls_token="[CLS]", sep_token="[SEP]")
    enc = BertModel(BertConfig(vocab_size=3000, hidden_size=64, num_hidden_layers=2, num_attention_heads=2, intermediate_size=128))
    return tok, enc, 64


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--task", default="T2", choices=["T1", "T2"])
    ap.add_argument("--split", default="temporal")
    ap.add_argument("--model", default="microsoft/deberta-v3-base")
    ap.add_argument("--source_mode", default="none", choices=["none", "feature", "crowd"])
    ap.add_argument("--top_sources", type=int, default=15, help="crowd 模式下单独建矩阵的来源数，其余归入 __OTHER__")
    ap.add_argument("--trace_lambda", type=float, default=0.01)
    ap.add_argument("--epochs", type=int, default=3)
    ap.add_argument("--lr", type=float, default=2e-5)
    ap.add_argument("--head_lr", type=float, default=1e-3, help="分类头与转移矩阵的学习率")
    ap.add_argument("--batch_size", type=int, default=32)
    ap.add_argument("--max_len", type=int, default=256)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--aux_v31", action="store_true", help="贡献 3：加 8 个 v3.1 辅助头，并加入只有 v3.1 标签的 CVE 一起训练（仅 T2）")
    ap.add_argument("--aux_lambda", type=float, default=0.5, help="v3.1 辅助损失的权重")
    ap.add_argument("--aux_max", type=int, default=60000, help="辅助样本最多取多少条（随机抽样）")
    ap.add_argument("--class_weight", default="none", choices=["none", "inv_sqrt"], help="v4 各指标的类别加权（缓解类别不均衡）")
    ap.add_argument("--train_frac", type=float, default=1.0,
                    help="标签效率实验：只用这个比例的 v4 训练标签（按种子随机抽样）；验证集、测试集和辅助样本不变")
    ap.add_argument("--aux_cwe", action="store_true",
                    help="对照实验：辅助任务改为预测 CWE 类别（前 --cwe_top 个 + 其他），辅助样本与 --aux_v31 完全相同（同一个池、同一个种子）")
    ap.add_argument("--cwe_top", type=int, default=50, help="CWE 辅助任务保留的类别数（其余并为'其他'）")
    ap.add_argument("--no_cwe_in_text", action="store_true",
                    help="输入只用描述、去掉 CWE 编号；CWE 辅助对照必须加，否则模型可以直接从输入里抄出答案")
    ap.add_argument("--aux_shuffle", action="store_true",
                    help="负对照（与 --aux_v31 同用）：把所有用于辅助任务的 v3.1 向量在样本之间整体打乱，保留标签分布与数据量，只破坏标签与描述的对应关系")
    ap.add_argument("--exclude_ids", default=None,
                    help="时间信息敏感性（第二轮审稿 P2）：src/late_update_ids.py 生成的 JSON；从 2026 年前的 v4 训练/验证样本（键 v4）"
                         "和辅助样本池（键 pool）里去掉容器在截止日期后更新过的 CVE；只用于时间划分")
    ap.add_argument("--pseudo_v4", action="store_true",
                    help="伪标签对照：辅助样本（与 --aux_v31 相同的池和种子）的 v3.1 向量按规则 R 换算成 v4 伪标签，直接监督 v4 头，损失权重 λ")
    ap.add_argument("--v31_only", action="store_true",
                    help="DeBERTa 版流水线：只用辅助样本训练 v3.1 头（不用任何 v4 标签），预测时把 v3.1 向量按规则 R 换算成 v4")
    ap.add_argument("--frac_mode", default="random", choices=["random", "earliest"],
                    help="--train_frac 的取法：random 按种子随机抽样；earliest 取发布日期最早的那部分（第四轮审稿 M4：模拟 v4.0 刚开始采用时的标签）")
    ap.add_argument("--save_encoder", action="store_true",
                    help="顺序微调的第一阶段（第四轮审稿 M3）：把验证集上最佳轮次的编码器权重存为 encoder.pt（约 0.7 GB），一般与 --v31_only 同用")
    ap.add_argument("--init_encoder", default=None,
                    help="顺序微调的第二阶段：从 --save_encoder 存下的 encoder.pt 初始化编码器，再只用 v4 标签微调（不能与辅助任务同用）")
    ap.add_argument("--out", default=None)
    ap.add_argument("--skip_existing", action="store_true", help="结果已存在（results.json）时直接跳过，便于中断后续跑")
    ap.add_argument("--smoke_test", action="store_true")
    args = ap.parse_args()
    if args.aux_v31 and args.task == "T1":
        ap.error("T1 的输入里已经有 v3.1 向量，v3.1 辅助任务没有意义；--aux_v31 只用于 T2")
    if args.aux_v31 and args.aux_cwe:
        ap.error("--aux_v31 与 --aux_cwe 只能二选一")
    if args.aux_cwe and args.task == "T1":
        ap.error("--aux_cwe 只用于 T2")
    if args.aux_shuffle and not args.aux_v31:
        ap.error("--aux_shuffle 只能与 --aux_v31 一起用")
    if sum([args.aux_v31, args.aux_cwe, args.pseudo_v4, args.v31_only]) > 1:
        ap.error("--aux_v31、--aux_cwe、--pseudo_v4、--v31_only 只能选一个")
    if (args.pseudo_v4 or args.v31_only) and args.task == "T1":
        ap.error("--pseudo_v4 与 --v31_only 只用于 T2")
    if args.init_encoder and (args.aux_v31 or args.aux_cwe or args.pseudo_v4 or args.v31_only):
        ap.error("--init_encoder 是顺序微调的第二阶段，只用 v4 标签，不能与辅助任务同用")
    if args.smoke_test:
        args.epochs, args.batch_size, args.model = 1, 16, "smoke-bert-tiny"

    # 运行名：默认超参数（3 轮、无类别加权、λ=0.5）时与 W3 的命名一致；非默认值自动加后缀，避免覆盖
    suffix = ""
    if (args.aux_v31 or args.aux_cwe or args.pseudo_v4) and args.aux_lambda != 0.5:
        suffix += f"_lam{args.aux_lambda:g}"
    if args.epochs != 3:
        suffix += f"_e{args.epochs}"
    if args.class_weight != "none":
        suffix += f"_cw{args.class_weight}"
    if args.train_frac < 1:
        suffix += f"_frac{'early' if args.frac_mode == 'earliest' else ''}{args.train_frac:g}"
    if args.init_encoder:
        suffix += "_seq"
    if args.save_encoder:  # 另起运行名，不覆盖已有的同配置结果（如表 S10 的 DeBERTa 流水线）
        suffix += "_enc"
    if args.exclude_ids:
        if args.split != "temporal":
            ap.error("--exclude_ids 只用于时间划分")
        suffix += "_xlate"
    run_name = args.out or (f"{args.task}_{args.split.replace(':', '-')}_{Path(args.model).name}_{args.source_mode}"
                            f"{'_aux' if args.aux_v31 else ''}{'shuf' if args.aux_shuffle else ''}{'_auxcwe' if args.aux_cwe else ''}"
                            f"{'_pseudo' if args.pseudo_v4 else ''}{'_v31only' if args.v31_only else ''}"
                            f"{'_desconly' if args.no_cwe_in_text else ''}{suffix}_s{args.seed}")
    out_dir = ROOT / "results" / "encoder" / run_name
    if args.skip_existing and (out_dir / "results.json").exists() and (not args.save_encoder or (out_dir / "encoder.pt").exists()):
        print(f"已存在，跳过：{run_name}", flush=True)
        return
    set_seed(args.seed)

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    amp_dtype = torch.bfloat16 if device.type == "cuda" and torch.cuda.is_bf16_supported() else None

    df = load()
    for k in M31:  # v4 样本自带的同来源 v3.1 标签，也作为辅助任务的监督
        df["z_" + k] = df["x31_" + k]
    df["cwe1"] = [first_cwe(a, b) for a, b in zip(df["cwe_cna"], df["cwe_adp"])]
    if args.no_cwe_in_text:
        df["text"] = df["description"].str.strip()
    excl = json.loads(Path(args.exclude_ids).read_text(encoding="utf-8")) if args.exclude_ids else None
    if excl:  # 只去掉 2026 年前的 v4 样本（训练与验证）；测试集不变
        drop = df["cve_id"].isin(set(excl["v4"])) & (df["pub"] < CUTOFF)
        df = df[~drop]
        print(f"v4 训练/验证样本去掉截止日期后更新过的 {int(drop.sum()):,} 条", flush=True)
    train, val, test = make_split(df, args.split, args.task)
    if args.smoke_test:
        train, val, test = train.sample(400, random_state=0), val.sample(100, random_state=0), test.sample(200, random_state=0)
    if args.train_frac < 1:  # 标签效率实验：只在训练部分抽样，验证集固定（仍是最晚的 10%），辅助样本在下面照常加入
        if args.frac_mode == "earliest":  # 条数与随机抽样时相同，只是取最早发布的
            train = train.sort_values("pub", kind="stable").head(int(round(len(train) * args.train_frac)))
        else:
            train = train.sample(frac=args.train_frac, random_state=args.seed)
        print(f"只用 {args.train_frac:g} 的 v4 训练标签（{args.frac_mode}）：{len(train):,} 条", flush=True)
    if args.aux_v31 or args.aux_cwe or args.pseudo_v4 or args.v31_only:  # 各种用法都取完全相同的辅助样本（同一个池、同一个种子）
        heldout = args.split.split(":", 1)[1] if args.split.startswith("loso:") else None
        aux = aux_pool(args.split, heldout, 300 if args.smoke_test else args.aux_max, args.seed,
                       exclude=set(excl["pool"]) if excl else None)
        use = {"aux_v31": "其 v3.1 标签", "aux_cwe": "其 CWE 类别", "pseudo_v4": "规则 R 换算出的 v4 伪标签", "v31_only": "其 v3.1 标签（流水线，不用 v4 标签）"}
        print(f"辅助样本（只有 v3.1 的 CVE，监督用{next(v for k, v in use.items() if getattr(args, k))}）：{len(aux):,} 条", flush=True)
        aux["cwe1"] = [first_cwe(a, b) for a, b in zip(aux["cwe_cna"], aux["cwe_adp"])]
        if args.no_cwe_in_text:
            aux["text"] = aux["description"].str.strip()
        if args.pseudo_v4:
            from rq1_stats import rule_convert
            conv = [rule_convert({k: r["z_" + k] for k in M31}) for _, r in aux.iterrows()]
            for k in M40:
                aux["p_" + k] = [c[k] for c in conv]
        cols = ["text", "source", "pub"] + (["z_" + k for k in M31] if (args.aux_v31 or args.v31_only) else
                                            ["p_" + k for k in M40] if args.pseudo_v4 else ["cwe1"])
        if args.v31_only:  # 流水线不使用任何 v4 训练标签：训练集只剩辅助样本
            train = aux[cols].reset_index(drop=True)
        else:
            train = pd.concat([train, aux[cols]], ignore_index=True)
        if args.aux_shuffle:  # 整行打乱 v3.1 向量（v4 训练样本自带的 v3.1 与辅助样本一起），各指标之间的关系保持不变
            zc = ["z_" + k for k in M31]
            has = train[zc[0]].notna().to_numpy()
            perm = np.random.default_rng(args.seed).permutation(int(has.sum()))
            train.loc[has, zc] = train.loc[has, zc].to_numpy()[perm]
            print(f"已打乱 {int(has.sum()):,} 条 v3.1 向量（负对照）", flush=True)
    cwe_vocab = None
    if args.aux_cwe:  # CWE 类别表只用训练部分（v4 训练样本 + 辅助样本）建立
        cwe_vocab = train["cwe1"].dropna().value_counts().head(args.cwe_top).index.tolist()
        cidx = {c: i for i, c in enumerate(cwe_vocab)}
        train["c_CWE"] = train["cwe1"].map(lambda c: cidx.get(c, len(cwe_vocab)) if isinstance(c, str) else None)
        is_aux = train["y_AV"].isna()  # 辅助样本没有 v4 标签
        cwe_info = {"vocab": cwe_vocab, "n_v4_rows": int((~is_aux).sum()), "n_aux_rows": int(is_aux.sum()),
                    "cwe_coverage_v4": float(train.loc[~is_aux, "c_CWE"].notna().mean()),
                    "cwe_coverage_aux": float(train.loc[is_aux, "c_CWE"].notna().mean()),
                    "share_other": float((train["c_CWE"] == len(cwe_vocab)).sum() / train["c_CWE"].notna().sum())}
        print(f"CWE 辅助任务：{len(cwe_vocab) + 1} 类（前 {len(cwe_vocab)} 个 CWE + 其他）；训练样本中有 CWE 的占 {train['c_CWE'].notna().mean():.1%}"
              f"（v4 样本 {cwe_info['cwe_coverage_v4']:.1%}，辅助样本 {cwe_info['cwe_coverage_aux']:.1%}；归入'其他'的占 {cwe_info['share_other']:.1%}）", flush=True)

    has_v4 = train["y_AV"].notna() if "y_AV" in train else pd.Series(False, index=train.index)
    top = train[has_v4]["source"].value_counts().head(args.top_sources).index.tolist()  # 只按有 v4 标签的样本选来源
    source_index = {s: i for i, s in enumerate(top)}
    source_index["__OTHER__"] = len(top)

    if args.smoke_test:
        tok, encoder, hidden = smoke_components(train["text"].tolist())
    else:
        from transformers import AutoModel, AutoTokenizer
        tok = AutoTokenizer.from_pretrained(args.model)
        # transformers 5.x 默认按权重文件里的精度加载（deberta-v3 会被加载成 float16）。
        # 用 AdamW 直接训练 float16 权重会在第一步更新后产生 NaN，所以统一转成 float32 主权重；
        # 前向计算仍在 bf16 自动混合精度下进行。
        encoder = AutoModel.from_pretrained(args.model).float()
        hidden = encoder.config.hidden_size
    if args.init_encoder:  # 顺序微调：编码器从第一阶段（只用 v3.1 标签训练）的权重开始，分类头重新初始化
        encoder.load_state_dict(torch.load(args.init_encoder, map_location="cpu"), strict=True)
        print(f"编码器从 {args.init_encoder} 初始化（顺序微调第二阶段）", flush=True)

    with_source = args.source_mode == "feature"
    ds = {n: CVEDataset(d, tok, args.max_len, args.task, with_source, source_index) for n, d in [("train", train), ("val", val), ("test", test)]}
    loaders = {n: DataLoader(d, batch_size=args.batch_size, shuffle=(n == "train"), collate_fn=d.collate) for n, d in ds.items()}

    model = MultiHeadCVSS(encoder, hidden, len(source_index), args.source_mode, aux_v31=args.aux_v31 or args.v31_only,
                          n_cwe=(len(cwe_vocab) + 1) if args.aux_cwe else 0).to(device)
    enc_params = list(model.encoder.parameters())
    other = [p for n, p in model.named_parameters() if not n.startswith("encoder.")]
    opt = torch.optim.AdamW([{"params": enc_params, "lr": args.lr}, {"params": other, "lr": args.head_lr}], weight_decay=0.01)
    total = args.epochs * len(loaders["train"])
    sched = torch.optim.lr_scheduler.LambdaLR(opt, lambda s: min(1.0, (s + 1) / max(1, int(0.06 * total))) * max(0.0, (total - s) / total))

    cw = class_weights(train, args.class_weight, device) if "y_AV" in train else None
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "args.json").write_text(json.dumps(vars(args), indent=1), encoding="utf-8")
    if cwe_vocab is not None:
        (out_dir / "cwe_vocab.json").write_text(json.dumps(cwe_info, indent=1), encoding="utf-8")

    best_f1, best_epoch, best_state, log = -1.0, -1, None, []
    t0, nan_steps = time.time(), 0
    for epoch in range(args.epochs):
        model.train()
        for step, batch in enumerate(loaders["train"]):
            batch = {k: v.to(device) for k, v in batch.items()}
            with torch.autocast(device_type=device.type, dtype=amp_dtype, enabled=amp_dtype is not None):
                logits = model(batch["input_ids"], batch["attention_mask"])
            loss = compute_loss(model, {k: v.float() for k, v in logits.items()}, batch["labels"], batch["labels31"], batch["src"], args, cw,
                                labels_cwe=batch["labels_cwe"], labels_ps=batch["labels_ps"])
            # 发散保护：loss 连续 20 步为 NaN/Inf 就终止本次运行（无人值守时避免白白消耗 GPU）
            nan_steps = nan_steps + 1 if not torch.isfinite(loss) else 0
            if nan_steps >= 20:
                raise RuntimeError(f"loss 连续 {nan_steps} 步为 NaN/Inf，终止本次运行：{run_name}")
            opt.zero_grad(set_to_none=True)
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            opt.step()
            sched.step()
            if step % 100 == 0:
                print(f"epoch {epoch} step {step}/{len(loaders['train'])} loss {loss.item():.4f} ({time.time() - t0:.0f}s)", flush=True)
        # 用验证集的平均 Macro-F1 选最佳 epoch（验证集不看测试标签）
        val_pred = predict_pipeline(model, loaders["val"], device, amp_dtype) if args.v31_only else predict(model, loaders["val"], device, amp_dtype)[0]
        val_res = evaluate(val.reset_index(drop=True), val_pred)
        log.append({"epoch": epoch, "val_mean_macro_f1": val_res["mean_macro_f1"], "val_band_acc": val_res["band_acc"],
                    "val_under_rate": val_res["under_rate"]})
        print(f"epoch {epoch} val meanF1 {val_res['mean_macro_f1']:.4f}", flush=True)
        if val_res["mean_macro_f1"] > best_f1:
            best_f1, best_epoch = val_res["mean_macro_f1"], epoch
            best_state = {k: v.detach().cpu().clone() for k, v in model.state_dict().items()}

    model.load_state_dict(best_state)
    if args.save_encoder:
        torch.save({k: v.detach().cpu() for k, v in model.encoder.state_dict().items()}, out_dir / "encoder.pt")
        print(f"编码器权重已保存：{out_dir / 'encoder.pt'}", flush=True)
    test_r = test.reset_index(drop=True)
    if args.v31_only:  # 流水线的 v4 头没有训练过，只保存换算后的预测
        pred = predict_pipeline(model, loaders["test"], device, amp_dtype)
    else:
        pred, test_probs = predict(model, loaders["test"], device, amp_dtype)
        _, val_probs = predict(model, loaders["val"], device, amp_dtype)
    results = {"val_log": log, "best_epoch": best_epoch, "val_best_mean_f1": best_f1, "latent": evaluate(test_r, pred)}
    pred.assign(cve_id=test_r["cve_id"], source=test_r["source"]).to_parquet(out_dir / "pred_latent.parquet", index=False)
    if not args.v31_only:
        # 保存最佳 epoch 在验证集与测试集上的各指标概率（风险敏感解码、校准分析、种子集成都要用）
        np.savez_compressed(out_dir / "probs.npz",
                            val_cve_id=val["cve_id"].to_numpy(dtype=str), test_cve_id=test_r["cve_id"].to_numpy(dtype=str),
                            **{f"val_{k}": v.astype(np.float16) for k, v in val_probs.items()},
                            **{f"test_{k}": v.astype(np.float16) for k, v in test_probs.items()})
    if args.source_mode == "crowd":
        pred_s, _ = predict(model, loaders["test"], device, amp_dtype, use_source_T=True)
        results["with_source_T"] = evaluate(test_r, pred_s)
        pred_s.assign(cve_id=test_r["cve_id"], source=test_r["source"]).to_parquet(out_dir / "pred_with_source_T.parquet", index=False)
        with torch.no_grad():
            results["transition_matrices"] = {k: {s: torch.softmax(p[i], -1).cpu().numpy().round(3).tolist() for s, i in source_index.items()}
                                              for k, p in model.trans.items()}
    results["by_source"] = {}
    for s in test_r["source"].value_counts().head(5).index:
        m = (test_r["source"] == s).values
        if m.sum() >= 30:
            results["by_source"][s] = evaluate(test_r[m], pred[m])["mean_macro_f1"]
    # 按标签类型拆分（derived / independent / v4_only / other，分型来自 label_provenance.py）
    types = test_r["source"].map(source_type_map()).fillna("other")
    results["by_type"] = {}
    for t in ["derived", "independent", "v4_only", "other"]:
        m = (types == t).values
        if m.sum() >= 30:
            r = evaluate(test_r[m], pred[m])
            results["by_type"][t] = {k: r[k] for k in SHORT} | {
                "v4_specific_f1": float(np.mean([r["per_metric"][k]["macro_f1"] for k in ["AT", "UI", "SC", "SI", "SA"]]))}
    (out_dir / "results.json").write_text(json.dumps(results, indent=1, ensure_ascii=False, default=float), encoding="utf-8")
    print(f"TEST meanF1 {results['latent']['mean_macro_f1']:.4f} exact {results['latent']['exact_match']:.4f} "
          f"MAE {results['latent']['score_mae']:.3f} | saved to {out_dir}", flush=True)


if __name__ == "__main__":
    main()
