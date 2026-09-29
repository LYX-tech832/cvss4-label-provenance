"""AutoCVSS 零样本基线的外部驱动脚本（W4）。

本文件是我们自己写的代码：只 import 并原样调用 AutoCVSS 的函数，不修改 AutoCVSS 的任何文件
（AutoCVSS 许可证规定：修改或衍生归 NEC 所有、不得分发；论文中须致谢 NEC Laboratories Europe）。
复用的 AutoCVSS 函数：
  zero_shot_STD_DTD_cvss_v40.classify_description / get_label_from_raw_output   —— 逐指标零样本分类
  eval_utils.postprocess_v40_prediction   —— "DONT_KNOW"或调用失败时取最保守标签（与原论文一致）
  cvss_v40_metrics.utils.makeCVSS40VectorString   —— 长标签 → 向量字符串

LLM 端点：任何 OpenAI 兼容接口（本地 vLLM，或托管 API）。
  地址用 --base_url 或环境变量 OPENAI_BASE_URL；密钥只从环境变量 OPENAI_API_KEY 读取（本地 vLLM 可不设）。
  不要把密钥写在命令行或代码里。

测试集：2026 年发布的 T2 测试集（与 baselines_v0 相同），按标签类型分层抽样（默认共 2,000 条），
每条 11 次调用；原始输出（含每次调用的 token 用量）逐条追加写入 raw.jsonl，中断后重跑会自动跳过已完成的调用。
DeepSeek V4 默认开启思考模式；本脚本默认用 --thinking disabled 关闭它（对应 AutoCVSS 的无 CoT 设置）。
思考模式的开关通过我们自己创建的 OpenAI 客户端附加到每次请求上，AutoCVSS 的代码不做任何改动。

用法（在项目根目录）：
  python src/run_autocvss_baseline.py --model <服务端模型名> --smoke_test     # 先用 3 条 CVE 试通
  python src/run_autocvss_baseline.py --model <服务端模型名> --prompt DTD
  DeepSeek 示例：--base_url https://api.deepseek.com --model deepseek-v4-pro --mode json
"""

import argparse
import importlib.metadata
import json
import os
import re
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import numpy as np
import pandas as pd
from tqdm import tqdm

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "external" / "AutoCVSS"))
from baselines_v0 import CUTOFF, M40, SHORT, evaluate, load, source_type_map  # noqa: E402
from cvss_utils import parse_vector  # noqa: E402

LONG = {  # 我们的指标缩写 → AutoCVSS 的指标长名
    "AV": "attackVector", "AC": "attackComplexity", "AT": "attackRequirements", "PR": "privilegesRequired",
    "UI": "userInteraction", "VC": "confidentialityImpactVulnerableSystem", "VI": "integrityImpactVulnerableSystem",
    "VA": "availabilityImpactVulnerableSystem", "SC": "confidentialityImpactSubsequentSystem",
    "SI": "integrityImpactSubsequentSystem", "SA": "availabilityImpactSubsequentSystem",
}
USAGE_FIELDS = ("prompt_tokens", "prompt_cache_hit_tokens", "prompt_cache_miss_tokens", "completion_tokens", "reasoning_tokens")


def sample_test(n_per_type, seed):
    df = load()
    test = df[df["pub"] >= CUTOFF].copy()
    test["label_type"] = test["source"].map(source_type_map()).fillna("other")
    parts = []
    for t, n in n_per_type.items():
        g = test[test["label_type"] == t]
        parts.append(g.sample(min(n, len(g)), random_state=seed))
    return pd.concat(parts).reset_index(drop=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True, help="端点上的模型名，例如 vLLM 启动时的模型路径或托管 API 的模型 ID")
    ap.add_argument("--base_url", default=os.environ.get("OPENAI_BASE_URL", "http://localhost:8000/v1"))
    ap.add_argument("--prompt", default="DTD", choices=["DTD", "STD"], help="DTD = 详细任务描述；STD = 简短描述（均为无 CoT）")
    ap.add_argument("--mode", default="json", choices=["json", "tools", "md_json"], help="instructor 的结构化输出模式；本地 vLLM 建议 json")
    ap.add_argument("--n_per_type", default="derived=300,independent=700,v4_only=500,other=500")
    ap.add_argument("--workers", type=int, default=16, help="并发请求数")
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--api_key_file", default=str(ROOT / ".deepseek_key"),
                    help="存放 API 密钥的文本文件（只含密钥本身）；环境变量 OPENAI_API_KEY 优先。脚本只读取，不打印")
    ap.add_argument("--thinking", default="disabled", choices=["disabled", "enabled", "default"],
                    help="DeepSeek V4 的思考模式（官方默认开启）。disabled = 关闭，对应 AutoCVSS 的无 CoT 设置（默认）；"
                         "enabled = 开启；default = 不传该参数，由端点自己决定")
    ap.add_argument("--thinking_style", default="deepseek", choices=["deepseek", "qwen"],
                    help="思考开关的传法：deepseek = extra_body.thinking（DeepSeek 接口）；qwen = chat_template_kwargs.enable_thinking（vLLM 部署的 Qwen3）")
    ap.add_argument("--reasoning_effort", default=None, choices=["low", "high", "max"],
                    help="思考模式下的推理强度（DeepSeek 默认 high），只在 --thinking enabled 时有意义")
    ap.add_argument("--temperature", type=float, default=None,
                    help="采样温度；不设则用接口默认值（AutoCVSS 原代码没有设置温度）。思考模式下 DeepSeek 忽略该参数")
    ap.add_argument("--run_tag", default="", help="重复运行的标记（如 rep1）：同一批 CVE（由 --seed 决定）再调用一次，结果写到单独的目录")
    ap.add_argument("--smoke_test", action="store_true")
    args = ap.parse_args()

    import instructor
    from openai import OpenAI

    from autocvss.cvss_v40_metrics.utils import makeCVSS40VectorString
    from autocvss.eval_utils import postprocess_v40_prediction
    from autocvss.zero_shot_STD_DTD_cvss_v40 import classify_description, get_label_from_raw_output

    mode = {"json": instructor.Mode.JSON, "tools": instructor.Mode.TOOLS, "md_json": instructor.Mode.MD_JSON}[args.mode]
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key and Path(args.api_key_file).exists():
        api_key = Path(args.api_key_file).read_text(encoding="utf-8").strip()
    print("API 密钥来源：", "环境变量" if os.environ.get("OPENAI_API_KEY") else ("密钥文件" if api_key else "未设置（本地 vLLM 可不设）"), flush=True)
    oa = OpenAI(base_url=args.base_url, api_key=api_key or "EMPTY")
    body = {}
    if args.thinking != "default":
        if args.thinking_style == "deepseek":
            body["thinking"] = {"type": args.thinking}
        else:  # vLLM 上的 Qwen3：通过对话模板开关思考
            body["chat_template_kwargs"] = {"enable_thinking": args.thinking == "enabled"}
    if args.reasoning_effort:
        body["reasoning_effort"] = args.reasoning_effort
    extra_kw = {} if args.temperature is None else {"temperature": args.temperature}
    if body or extra_kw:  # 在我们自己的客户端上给每次请求附加参数；AutoCVSS 的调用代码保持原样
        _create = oa.chat.completions.create

        def _create_with_params(*a, **kw):
            if body:
                kw["extra_body"] = {**body, **(kw.get("extra_body") or {})}
            for key, v in extra_kw.items():
                kw.setdefault(key, v)
            return _create(*a, **kw)

        oa.chat.completions.create = _create_with_params
    client = instructor.from_openai(oa, mode=mode)

    n_per_type = {k: int(v) for k, v in (x.split("=") for x in args.n_per_type.split(","))}
    test = sample_test(n_per_type, args.seed)
    if args.smoke_test:
        test = test.groupby("label_type").head(1).head(3).reset_index(drop=True)

    tag = re.sub(r"[^A-Za-z0-9._-]+", "_", Path(args.model).name)
    think_tag = {"disabled": "", "enabled": f"_think{args.reasoning_effort or ''}", "default": "_apidefault"}[args.thinking]
    think_tag += "" if args.temperature is None else f"_t{args.temperature:g}"
    out_dir = ROOT / "results" / "autocvss_baseline" / (f"{tag}_{args.prompt}{think_tag}_s{args.seed}" + (f"_{args.run_tag}" if args.run_tag else "")
                                                         + ("_smoke" if args.smoke_test else ""))
    out_dir.mkdir(parents=True, exist_ok=True)
    raw_path = out_dir / "raw.jsonl"
    done = {}
    if raw_path.exists():
        for line in raw_path.read_text(encoding="utf-8").splitlines():
            r = json.loads(line)
            done[(r["cve_id"], r["metric"])] = r["label"]

    tasks = [(row.cve_id, row.description, k) for row in test.itertuples() for k in M40 if (row.cve_id, k) not in done]
    lock = threading.Lock()

    def work(task):
        cve_id, desc, k = task
        raw = classify_description(desc, LONG[k], with_cot=False, with_long_description=(args.prompt == "DTD"),
                                   client=client, model_name=args.model)
        label = get_label_from_raw_output(raw, LONG[k])  # 失败时为 None
        rec = {"cve_id": cve_id, "metric": k, "label": label}
        usage = getattr(getattr(raw, "_raw_response", None), "usage", None)  # instructor 附在结果上的原始响应
        if usage is not None:  # 记录 token 用量（含缓存命中与推理 token），用于核算费用
            u = usage.model_dump()
            rec["usage"] = {f: u.get(f) for f in USAGE_FIELDS[:-1]}
            rec["usage"]["reasoning_tokens"] = (u.get("completion_tokens_details") or {}).get("reasoning_tokens")
        with lock, raw_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        return cve_id, k, label

    print(f"测试 CVE {len(test):,} 条；待调用 {len(tasks):,} 次（已完成 {len(done):,} 次）；端点 {args.base_url}；模型 {args.model}", flush=True)
    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        for fut in tqdm(as_completed([ex.submit(work, t) for t in tasks]), total=len(tasks)):
            cve_id, k, label = fut.result()
            done[(cve_id, k)] = label

    # 汇总：DONT_KNOW / 调用失败 → 最保守标签（沿用 AutoCVSS 的做法），拼成向量再转成我们的短标签
    rows, fallback = [], {k: 0 for k in M40}
    for cve_id in test["cve_id"]:
        long_labels = {}
        for k in M40:
            raw = done.get((cve_id, k))
            fallback[k] += raw in (None, "DONT_KNOW")
            long_labels[LONG[k]] = postprocess_v40_prediction(raw, LONG[k])
        rows.append(parse_vector(makeCVSS40VectorString(**long_labels), "4.0"))
    pred = pd.DataFrame(rows)

    usage_total = {f: 0 for f in USAGE_FIELDS}
    for line in raw_path.read_text(encoding="utf-8").splitlines():
        for f, v in (json.loads(line).get("usage") or {}).items():
            usage_total[f] += v or 0
    results = {"n": len(test), "model": args.model, "prompt": args.prompt,
               "thinking": args.thinking, "thinking_style": args.thinking_style, "reasoning_effort": args.reasoning_effort,
               "temperature": args.temperature, "base_url": args.base_url,
               "usage_total": usage_total,
               "versions": {p: importlib.metadata.version(p) for p in ("instructor", "openai", "langfuse")},
               "fallback_rate": {k: v / len(test) for k, v in fallback.items()},
               "overall": {k: v for k, v in evaluate(test, pred).items() if k in SHORT}}
    results["by_type"] = {}
    for t in ["derived", "independent", "v4_only", "other"]:
        m = (test["label_type"] == t).values
        if m.sum() >= 3:
            r = evaluate(test[m].reset_index(drop=True), pred[m].reset_index(drop=True))
            results["by_type"][t] = {k: r[k] for k in SHORT} | {
                "v4_specific_f1": float(np.mean([r["per_metric"][k]["macro_f1"] for k in ["AT", "UI", "SC", "SI", "SA"]]))}
    pred.assign(cve_id=test["cve_id"], source=test["source"], label_type=test["label_type"]).to_parquet(out_dir / "predictions.parquet", index=False)
    (out_dir / "results.json").write_text(json.dumps(results, indent=1, ensure_ascii=False), encoding="utf-8")
    print(json.dumps({k: results[k] for k in ["n", "overall", "by_type"]}, indent=1, ensure_ascii=False))
    print("回退到最保守标签的比例：", {k: round(v, 3) for k, v in results["fallback_rate"].items()})
    print("token 用量合计：", usage_total)


if __name__ == "__main__":
    main()
