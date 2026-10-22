# app.py — 大数据杀熟智能审计引擎（Streamlit 网页版）
from __future__ import annotations

import hashlib
import json
import statistics
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Optional

import pandas as pd
import streamlit as st

# ============ 配置 ============
MIN_DIFF_RATE = 0.03
REASONABLE_TAGS = {
    "new_user_promo",
    "region_cost",
    "limited_time_promo",
    "clearance",
}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ============ 数据模型 ============
@dataclass(frozen=True)
class Persona:
    pid: str
    label: str
    is_member: bool
    order_cnt_90d: int
    device_tier: str
    region: str

    @property
    def loyalty_weight(self) -> float:
        if self.order_cnt_90d >= 20:
            return 1.5
        if self.order_cnt_90d >= 5:
            return 1.2
        return 1.0


@dataclass
class Quote:
    sku_id: str
    persona_id: str
    list_price: float
    coupon_discount: float = 0.0
    member_discount: float = 0.0
    promo_tag: Optional[str] = None
    collected_at: str = field(default_factory=now_iso)

    @property
    def final_price(self) -> float:
        return round(self.list_price - self.coupon_discount - self.member_discount, 2)


@dataclass
class Finding:
    sku_id: str
    persona_id: str
    persona_label: str
    final_price: float
    base_price: float
    diff_rate: float
    risk_score: float
    reason: str
    evidence: dict = field(default_factory=dict)


# ============ 采集层 ============
class MockCollector:
    def __init__(self, dataset: dict[str, list[Quote]]):
        self._data = dataset

    def quotes_for(self, sku_id: str) -> list[Quote]:
        return self._data.get(sku_id, [])


# ============ 核心：公平性检测 ============
class FairnessDetector:
    def __init__(self, min_diff_rate: float = MIN_DIFF_RATE):
        self.min_diff_rate = min_diff_rate

    def detect(self, sku_id: str, quotes: list[Quote],
               personas: dict[str, Persona]) -> list[Finding]:
        if len(quotes) < 2:
            return []

        prices = [q.final_price for q in quotes]
        base = statistics.median(prices)
        if base <= 0:
            return []

        findings: list[Finding] = []
        for q in quotes:
            p = personas[q.persona_id]
            diff = (q.final_price - base) / base

            if diff < self.min_diff_rate:
                continue
            if q.promo_tag in REASONABLE_TAGS:
                continue

            score = diff * 100 * p.loyalty_weight * (1.3 if p.is_member else 1.0)
            score = min(round(score, 1), 100.0)

            reason = self._explain(p, q, diff)
            findings.append(Finding(
                sku_id=sku_id,
                persona_id=p.pid,
                persona_label=p.label,
                final_price=q.final_price,
                base_price=round(base, 2),
                diff_rate=round(diff, 4),
                risk_score=score,
                reason=reason,
            ))
        return findings

    @staticmethod
    def _explain(p: Persona, q: Quote, diff: float) -> str:
        parts = [f"实付价比同商品中位价高 {diff:.1%}"]
        if p.is_member:
            parts.append("付费会员未享受价格优势")
        if p.order_cnt_90d >= 20:
            parts.append(f"高频忠诚用户（90天{p.order_cnt_90d}单）")
        if q.coupon_discount == 0:
            parts.append("未获得任何优惠券（疑似差异化发券）")
        if not q.promo_tag:
            parts.append("无合理促销因素说明")
        return "；".join(parts)


# ============ 优惠券公平性专项检测 ============
class CouponFairnessChecker:
    def check(self, quotes: list[Quote], personas: dict[str, Persona]) -> Optional[dict]:
        if len(quotes) < 2:
            return None
        new_u = [q for q in quotes if personas[q.persona_id].order_cnt_90d <= 1]
        old_u = [q for q in quotes if personas[q.persona_id].order_cnt_90d >= 10]
        if not new_u or not old_u:
            return None
        avg_new = statistics.mean(q.coupon_discount for q in new_u)
        avg_old = statistics.mean(q.coupon_discount for q in old_u)
        if avg_new - avg_old <= 0:
            return None
        return {
            "type": "差异化发券",
            "new_user_avg_coupon": round(avg_new, 2),
            "old_user_avg_coupon": round(avg_old, 2),
            "gap": round(avg_new - avg_old, 2),
            "note": "老用户平均券额显著低于新用户，需核查定价规则",
        }


# ============ 存证层 ============
class EvidencePacker:
    @staticmethod
    def pack(payload: dict) -> dict:
        canonical = json.dumps(payload, sort_keys=True,
                               ensure_ascii=False, separators=(",", ":"))
        return {
            "sha256": hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
            "timestamp": now_iso(),
            "algorithm": "SHA-256",
            "note": "内容任何改动都会导致哈希变化，可用于公证/司法鉴定前置固定",
        }


# ============ 报告生成 ============
class ReportBuilder:
    @staticmethod
    def build(platform: str, sku_id: str, quotes: list[Quote],
              findings: list[Finding], coupon_issue: Optional[dict]) -> dict:
        max_score = max((f.risk_score for f in findings), default=0.0)
        level = ("高风险" if max_score >= 40 else
                 "中风险" if max_score >= 15 else
                 "低风险" if findings else "未发现异常")

        body = {
            "platform": platform,
            "sku_id": sku_id,
            "audit_time": now_iso(),
            "quote_count": len(quotes),
            "price_matrix": [
                {"persona": q.persona_id, "final_price": q.final_price,
                 "coupon": q.coupon_discount, "tag": q.promo_tag}
                for q in sorted(quotes, key=lambda x: x.final_price)
            ],
            "findings": [asdict(f) for f in findings],
            "coupon_issue": coupon_issue,
            "risk_level": level,
            "max_risk_score": max_score,
        }
        body["evidence"] = EvidencePacker.pack(body)
        return body


# ============ 演示数据 ============
def build_demo():
    personas = {
        "P1": Persona("P1", "新用户", False, 0, "中端机", "北京"),
        "P2": Persona("P2", "老用户", False, 30, "中端机", "北京"),
        "P3": Persona("P3", "付费会员", True, 45, "高端机", "北京"),
        "P4": Persona("P4", "低频用户", False, 2, "低端机", "北京"),
    }

    s1 = [
        Quote("SKU-WAIMAI", "P1", 30.0, 8.0, 0.0, "new_user_promo"),
        Quote("SKU-WAIMAI", "P2", 32.0, 0.0, 0.0),
        Quote("SKU-WAIMAI", "P3", 33.0, 0.0, 1.0),
        Quote("SKU-WAIMAI", "P4", 31.0, 1.0, 0.0),
    ]
    s2 = [
        Quote("SKU-HOTEL", "P1", 600.0, 50.0, 0.0, "new_user_promo"),
        Quote("SKU-HOTEL", "P2", 620.0, 0.0, 0.0),
        Quote("SKU-HOTEL", "P3", 660.0, 0.0, 20.0),
        Quote("SKU-HOTEL", "P4", 615.0, 0.0, 0.0),
    ]
    s3 = [
        Quote("SKU-MALL", "P1", 199.0, 20.0, 0.0, "new_user_promo"),
        Quote("SKU-MALL", "P2", 199.0, 0.0, 0.0),
        Quote("SKU-MALL", "P3", 209.0, 0.0, 0.0, "region_cost"),
        Quote("SKU-MALL", "P4", 199.0, 0.0, 0.0),
    ]
    return personas, {"SKU-WAIMAI": s1, "SKU-HOTEL": s2, "SKU-MALL": s3}


# ============ CSV 上传解析 ============
def load_uploaded_csv(uploaded) -> tuple[dict[str, Persona], dict[str, list[Quote]], dict[str, str]]:
    df = pd.read_csv(uploaded)
    required = [
        "sku_id", "persona_id", "persona_label", "is_member",
        "order_cnt_90d", "device_tier", "region",
        "list_price", "coupon_discount", "member_discount",
    ]
    missing = [c for c in required if c not in df.columns]
    if missing:
        raise ValueError(f"CSV 缺少必要列：{', '.join(missing)}")

    personas: dict[str, Persona] = {}
    dataset: dict[str, list[Quote]] = {}
    platform_map: dict[str, str] = {}

    for _, row in df.iterrows():
        pid = str(row["persona_id"]).strip()
        if pid not in personas:
            personas[pid] = Persona(
                pid=pid,
                label=str(row["persona_label"]).strip(),
                is_member=str(row["is_member"]).strip().lower() in ("true", "1", "yes", "y", "是"),
                order_cnt_90d=int(row["order_cnt_90d"]),
                device_tier=str(row["device_tier"]).strip(),
                region=str(row["region"]).strip(),
            )

        sku = str(row["sku_id"]).strip()
        promo_tag = row.get("promo_tag")
        if pd.isna(promo_tag) or str(promo_tag).strip() == "":
            promo_tag = None
        else:
            promo_tag = str(promo_tag).strip()

        coupon = row["coupon_discount"]
        member = row["member_discount"]
        quote = Quote(
            sku_id=sku,
            persona_id=pid,
            list_price=float(row["list_price"]),
            coupon_discount=float(coupon) if not pd.isna(coupon) else 0.0,
            member_discount=float(member) if not pd.isna(member) else 0.0,
            promo_tag=promo_tag,
        )
        dataset.setdefault(sku, []).append(quote)

        if "platform" in df.columns:
            val = row.get("platform")
            if not pd.isna(val):
                platform_map.setdefault(sku, str(val).strip())

    return personas, dataset, platform_map


# ============ 网页渲染 ============
def render_report(report: dict) -> None:
    st.subheader(f"审计报告：{report['platform']} / {report['sku_id']}")

    col1, col2, col3 = st.columns(3)
    col1.metric("风险等级", report["risk_level"])
    col2.metric("最高风险分", report["max_risk_score"])
    col3.metric("画像数", report["quote_count"])

    st.markdown("### 价格矩阵")
    matrix_df = pd.DataFrame(report["price_matrix"])
    matrix_df = matrix_df.rename(columns={
        "persona": "画像ID",
        "final_price": "实付价",
        "coupon": "优惠券",
        "tag": "促销标签",
    })
    st.dataframe(matrix_df, use_container_width=True)

    st.markdown("### 疑似问题")
    if report["findings"]:
        findings_df = pd.DataFrame(report["findings"])
        display_cols = ["persona_label", "final_price", "base_price", "diff_rate", "risk_score", "reason"]
        display_df = findings_df[[c for c in display_cols if c in findings_df.columns]]
        display_df = display_df.rename(columns={
            "persona_label": "画像",
            "final_price": "实付价",
            "base_price": "基准价",
            "diff_rate": "差异率",
            "risk_score": "风险分",
            "reason": "理由",
        })
        st.dataframe(display_df, use_container_width=True)

        for f in report["findings"]:
            st.warning(
                f"**{f['persona_label']}**：实付价 {f['final_price']}，"
                f"基准价 {f['base_price']}，高出 {f['diff_rate']:.1%}，"
                f"风险分 {f['risk_score']}。  \n理由：{f['reason']}"
            )
    else:
        st.success("未发现超过阈值的疑似杀熟差异。")

    st.markdown("### 优惠券公平性")
    if report["coupon_issue"]:
        c = report["coupon_issue"]
        st.error(
            f"**{c['type']}**：新客平均券 {c['new_user_avg_coupon']} 元，"
            f"老客平均券 {c['old_user_avg_coupon']} 元，"
            f"差额 {c['gap']} 元。{c['note']}"
        )
    else:
        st.info("未检测到显著的新老客差异化发券。")

    st.markdown("### 证据存证")
    st.code(
        f"SHA-256: {report['evidence']['sha256']}\n"
        f"时间戳: {report['evidence']['timestamp']}\n"
        f"算法: {report['evidence']['algorithm']}"
    )

    with st.expander("合规提示"):
        st.write("1. 本引擎仅输出价格差异的客观数据与技术分析，不认定违法。")
        st.write("2. 所有疑似线索须经人工复核，并排除合理商业因素后方可举报/披露。")
        st.write("3. 采集须使用真实注册账号、公开可见标价，不得侵入平台后台。")


# ============ Streamlit 页面 ============
st.set_page_config(
    page_title="大数据杀熟审计引擎",
    page_icon="🔍",
    layout="wide",
)

st.title("🔍 大数据杀熟智能审计引擎")
st.caption("上传报价数据或使用演示数据，检测疑似差异化定价")

mode = st.radio(
    "数据来源",
    ["使用演示数据", "上传 CSV"],
    horizontal=True,
)

if mode == "使用演示数据":
    personas, dataset = build_demo()
    platform_map = {
        "SKU-WAIMAI": "某外卖平台",
        "SKU-HOTEL": "某住宿平台",
        "SKU-MALL": "某电商平台",
    }
else:
    uploaded = st.file_uploader("上传报价数据（CSV）", type="csv")
    if not uploaded:
        st.info("请上传 CSV 文件。列名要求见下方说明。")
        with st.expander("CSV 列名说明"):
            st.code(
                "sku_id, persona_id, persona_label, is_member, order_cnt_90d, "
                "device_tier, region, list_price, coupon_discount, "
                "member_discount, promo_tag, platform"
            )
            st.write("其中 `promo_tag` 和 `platform` 可选。")
        st.stop()
    try:
        personas, dataset, platform_map = load_uploaded_csv(uploaded)
    except Exception as e:
        st.error(f"CSV 解析失败：{e}")
        st.stop()

if not dataset:
    st.warning("没有可用数据。")
    st.stop()

sku = st.selectbox("选择检测商品/场景", list(dataset.keys()))

if st.button("开始审计", type="primary"):
    quotes = dataset[sku]
    detector = FairnessDetector()
    coupon_chk = CouponFairnessChecker()

    findings = detector.detect(sku, quotes, personas)
    coupon_issue = coupon_chk.check(quotes, personas)
    platform = platform_map.get(sku, "用户上传数据")

    report = ReportBuilder.build(
        platform=platform,
        sku_id=sku,
        quotes=quotes,
        findings=findings,
        coupon_issue=coupon_issue,
    )
    render_report(report)