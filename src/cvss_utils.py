"""CVSS v3.1 / v4.0 向量解析工具。

只保留基础指标（Base metrics）；向量里若带有威胁/环境/补充指标（如 E:P、CR:H），一律忽略。
取值定义见 FIRST 规范：
  v3.1  https://www.first.org/cvss/v3.1/specification-document
  v4.0  https://www.first.org/cvss/v4.0/specification-document
"""

V31_METRICS = {
    "AV": ["N", "A", "L", "P"],
    "AC": ["L", "H"],
    "PR": ["N", "L", "H"],
    "UI": ["N", "R"],
    "S": ["U", "C"],
    "C": ["H", "L", "N"],
    "I": ["H", "L", "N"],
    "A": ["H", "L", "N"],
}

V40_METRICS = {
    "AV": ["N", "A", "L", "P"],
    "AC": ["L", "H"],
    "AT": ["N", "P"],
    "PR": ["N", "L", "H"],
    "UI": ["N", "P", "A"],
    "VC": ["H", "L", "N"],
    "VI": ["H", "L", "N"],
    "VA": ["H", "L", "N"],
    "SC": ["H", "L", "N"],
    "SI": ["H", "L", "N"],
    "SA": ["H", "L", "N"],
}

PREFIX = {"3.1": "CVSS:3.1/", "4.0": "CVSS:4.0/"}
METRICS = {"3.1": V31_METRICS, "4.0": V40_METRICS}


def parse_vector(vector, version):
    """把向量字符串解析成 {指标: 取值}。

    格式不对、缺少任一基础指标或取值非法时返回 None（调用方据此丢弃该条标签）。
    """
    if not isinstance(vector, str) or not vector.startswith(PREFIX[version]):
        return None
    allowed = METRICS[version]
    parsed = {}
    for part in vector[len(PREFIX[version]):].split("/"):
        key, sep, value = part.partition(":")
        if not sep:
            return None
        if key in allowed:
            if value not in allowed[key] or key in parsed:
                return None
            parsed[key] = value
    if set(parsed) != set(allowed):
        return None
    return parsed


def base_vector(parsed, version):
    """按规范顺序重新拼出只含基础指标的向量字符串（用于去重和比较）。"""
    return PREFIX[version] + "/".join(f"{k}:{parsed[k]}" for k in METRICS[version])
