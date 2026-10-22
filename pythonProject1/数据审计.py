# price_audit_full.py
# 大数据杀熟智能审计引擎 —— 完整可运行版
# 运行: python price_audit_full.py
from __future__ import annotations

import csv
import hashlib
import json
import os
import statistics
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Optional

# ========================= 配置 =========================
MIN_DIFF_RATE = 0.03
REASONABLE_TAGS = {
    "new_user_promo",      # 新客首单补贴
    "region_cost",         # 区域运营成本差异
    "limited_time_promo",  # 限时促销
    "clearance",           # 清仓
}

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")

# ========================= 数据模型 =========================
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
    platform: str = ""
    product_name: str = ""
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

# ========================= 核心算法 =========================
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

            findings.append(Finding(
                sku_id=sku_id,
                persona_id=p.pid,
                persona_label=p.label,
                final_price=q.final_price,
                base_price=round(base, 2),
                diff_rate=round(diff, 4),
                risk_score=score,
                reason=self._explain(p, q, diff),
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

class CouponFairnessChecker:
    def check(self, quotes: list[Quote],
              personas: dict[str, Persona]) -> Optional[dict]:
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

# ========================= 存证 =========================
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

# ========================= 报告 =========================
class ReportBuilder:
    @staticmethod
    def build(sku_id: str, quotes: list[Quote],
              findings: list[Finding],
              coupon_issue: Optional[dict]) -> dict:
        platform = quotes[0].platform if quotes else ""
        product = quotes[0].product_name if quotes else ""
        max_score = max((f.risk_score for f in findings), default=0.0)
        level = ("高风险" if max_score >= 40 else
                 "中风险" if max_score >= 15 else
                 "低风险" if findings else "未发现异常")

        body = {
            "platform": platform,
            "sku_id": sku_id,
            "product_name": product,
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

def print_report(r: dict) -> None:
    print("=" * 68)
    print(f"平台: {r['platform']}   商品: {r['product_name']}（{r['sku_id']}）")
    print(f"风险等级: {r['risk_level']}   最高风险分: {r['max_risk_score']}")
    print("-" * 68)
    print(f"{'画像':<12}{'实付价':>10}{'优惠券':>10}   促销标签")
    for row in r["price_matrix"]:
        print(f"{row['persona']:<12}{row['final_price']:>10.2f}"
              f"{row['coupon']:>10.2f}   {row['tag'] or '-'}")
    if r["findings"]:
        print("-" * 68)
        for f in r["findings"]:
            print(f"[!] {f['persona_label']} 高出基准 {f['diff_rate']:.1%} "
                  f"| 风险分 {f['risk_score']}")
            print(f"    理由: {f['reason']}")
    if r["coupon_issue"]:
        c = r["coupon_issue"]
        print(f"[!] {c['type']}: 新客均券 {c['new_user_avg_coupon']} 元 vs "
              f"老客均券 {c['old_user_avg_coupon']} 元（差 {c['gap']} 元）")
    print(f"\n证据哈希: {r['evidence']['sha256'][:32]}...")
    print(f"存证时间: {r['evidence']['timestamp']}")
    print("=" * 68)

# ========================= 内嵌 CSV 数据 =========================
PERSONAS_CSV = """persona_id,persona_label,is_member,order_cnt_90d,device_tier,region,description
P1,新用户,false,0,中端机,北京,近90天0单，模拟新注册用户
P2,老用户,false,30,中端机,北京,近90天30单，高频忠诚用户
P3,付费会员,true,45,高端机,北京,付费会员+45单，高价值用户
P4,低频用户,false,2,低端机,北京,近90天2单，价格敏感型
"""

QUOTES_CSV = """audit_id,platform,category,sku_id,product_name,persona_id,persona_label,is_member,order_cnt_90d,device_tier,region,list_price,coupon_discount,member_discount,promo_tag,collected_at
A001,某外卖平台,外卖,SKU-WAIMAI-001,麻辣香锅套餐,P1,新用户,false,0,中端机,北京,30,10,0,new_user_promo,2026-10-22 10:00:00
A002,某外卖平台,外卖,SKU-WAIMAI-001,麻辣香锅套餐,P2,老用户,false,30,中端机,北京,34,0,0,,2026-10-22 10:00:01
A003,某外卖平台,外卖,SKU-WAIMAI-001,麻辣香锅套餐,P3,付费会员,true,45,高端机,北京,35,0,1,,2026-10-22 10:00:02
A004,某外卖平台,外卖,SKU-WAIMAI-001,麻辣香锅套餐,P4,低频用户,false,2,低端机,北京,32,2,0,,2026-10-22 10:00:03
A005,某住宿平台,酒店,SKU-HOTEL-001,某酒店大床房,P1,新用户,false,0,中端机,北京,600,60,0,new_user_promo,2026-10-22 10:05:00
A006,某住宿平台,酒店,SKU-HOTEL-001,某酒店大床房,P2,老用户,false,30,中端机,北京,640,0,0,,2026-10-22 10:05:01
A007,某住宿平台,酒店,SKU-HOTEL-001,某酒店大床房,P3,付费会员,true,45,高端机,北京,700,20,0,,2026-10-22 10:05:02
A008,某住宿平台,酒店,SKU-HOTEL-001,某酒店大床房,P4,低频用户,false,2,低端机,北京,620,0,0,,2026-10-22 10:05:03
A009,某电商平台,电商,SKU-MALL-001,空气炸锅,P1,新用户,false,0,中端机,北京,199,20,0,new_user_promo,2026-10-22 10:10:00
A010,某电商平台,电商,SKU-MALL-001,空气炸锅,P2,老用户,false,30,中端机,北京,199,20,0,,2026-10-22 10:10:01
A011,某电商平台,电商,SKU-MALL-001,空气炸锅,P3,付费会员,true,45,高端机,北京,209,20,0,region_cost,2026-10-22 10:10:02
A012,某电商平台,电商,SKU-MALL-001,空气炸锅,P4,低频用户,false,2,低端机,北京,199,10,0,,2026-10-22 10:10:03
A013,某出行平台,出行,SKU-RIDE-001,机场专线,P1,新用户,false,0,中端机,北京,50,10,0,new_user_promo,2026-10-22 10:15:00
A014,某出行平台,出行,SKU-RIDE-001,机场专线,P2,老用户,false,30,中端机,北京,58,10,0,,2026-10-22 10:15:01
A015,某出行平台,出行,SKU-RIDE-001,机场专线,P3,付费会员,true,45,高端机,北京,62,10,0,,2026-10-22 10:15:02
A016,某出行平台,出行,SKU-RIDE-001,机场专线,P4,低频用户,false,2,低端机,北京,52,10,0,,2026-10-22 10:15:03
A017,某直播平台,直播,SKU-LIVE-001,护肤品套装,P1,新用户,false,0,中端机,北京,299,50,0,new_user_promo,2026-10-22 10:20:00
A018,某直播平台,直播,SKU-LIVE-001,护肤品套装,P2,老用户,false,30,中端机,北京,299,0,0,,2026-10-22 10:20:01
A019,某直播平台,直播,SKU-LIVE-001,护肤品套装,P3,付费会员,true,45,高端机,北京,299,10,0,,2026-10-22 10:20:02
A020,某直播平台,直播,SKU-LIVE-001,护肤品套装,P4,低频用户,false,2,低端机,北京,299,30,0,,2026-10-22 10:20:03
A021,某电商平台,电商,SKU-MALL-002,胶囊咖啡机,P1,新用户,false,0,中端机,北京,899,100,0,new_user_promo,2026-10-22 10:25:00
A022,某电商平台,电商,SKU-MALL-002,胶囊咖啡机,P2,老用户,false,30,中端机,北京,899,0,0,,2026-10-22 10:25:01
A023,某电商平台,电商,SKU-MALL-002,胶囊咖啡机,P3,付费会员,true,45,高端机,北京,899,50,0,limited_time_promo,2026-10-22 10:25:02
A024,某电商平台,电商,SKU-MALL-002,胶囊咖啡机,P4,低频用户,false,2,低端机,北京,899,100,0,limited_time_promo,2026-10-22 10:25:03
A025,某电商平台,电商,SKU-MALL-003,夏季T恤,P1,新用户,false,0,中端机,北京,159,30,0,new_user_promo,2026-10-22 10:30:00
A026,某电商平台,电商,SKU-MALL-003,夏季T恤,P2,老用户,false,30,中端机,北京,159,20,0,clearance,2026-10-22 10:30:01
A027,某电商平台,电商,SKU-MALL-003,夏季T恤,P3,付费会员,true,45,高端机,北京,159,50,0,clearance,2026-10-22 10:30:02
A028,某电商平台,电商,SKU-MALL-003,夏季T恤,P4,低频用户,false,2,低端机,北京,159,20,0,clearance,2026-10-22 10:30:03
A029,某外卖平台,外卖,SKU-FOOD-002,珍珠奶茶,P1,新用户,false,0,中端机,北京,18,1,0,new_user_promo,2026-10-22 10:35:00
A030,某外卖平台,外卖,SKU-FOOD-002,珍珠奶茶,P2,老用户,false,30,中端机,北京,18,1,0,,2026-10-22 10:35:01
A031,某外卖平台,外卖,SKU-FOOD-002,珍珠奶茶,P3,付费会员,true,45,高端机,北京,18,1,0,,2026-10-22 10:35:02
A032,某外卖平台,外卖,SKU-FOOD-002,珍珠奶茶,P4,低频用户,false,2,低端机,北京,18,2,0,,2026-10-22 10:35:03
A033,某住宿平台,酒店,SKU-HOTEL-002,经济型酒店,P1,新用户,false,0,中端机,北京,300,20,0,new_user_promo,2026-10-22 10:40:00
A034,某住宿平台,酒店,SKU-HOTEL-002,经济型酒店,P2,老用户,false,30,中端机,北京,300,25,0,,2026-10-22 10:40:01
A035,某住宿平台,酒店,SKU-HOTEL-002,经济型酒店,P3,付费会员,true,45,高端机,北京,300,25,0,,2026-10-22 10:40:02
A036,某住宿平台,酒店,SKU-HOTEL-002,经济型酒店,P4,低频用户,false,2,低端机,北京,300,25,0,,2026-10-22 10:40:03
A037,某电商平台,电商,SKU-MALL-004,27寸显示器,P1,新用户,false,0,中端机,北京,1299,100,0,new_user_promo,2026-10-22 10:45:00
A038,某电商平台,电商,SKU-MALL-004,27寸显示器,P2,老用户,false,30,中端机,北京,1299,100,0,,2026-10-22 10:45:01
A039,某电商平台,电商,SKU-MALL-004,27寸显示器,P3,付费会员,true,45,高端机,北京,1399,100,0,,2026-10-22 10:45:02
A040,某电商平台,电商,SKU-MALL-004,27寸显示器,P4,低频用户,false,2,低端机,北京,1299,100,0,,2026-10-22 10:45:03
"""

# ========================= CSV 落盘与读取 =========================
def ensure_csv_files(personas_path: str = "personas.csv",
                     quotes_path: str = "quotes.csv") -> None:
    if not os.path.exists(personas_path):
        with open(personas_path, "w", newline="", encoding="utf-8-sig") as f:
            f.write(PERSONAS_CSV)
        print(f"[初始化] 已生成 {personas_path}")
    if not os.path.exists(quotes_path):
        with open(quotes_path, "w", newline="", encoding="utf-8-sig") as f:
            f.write(QUOTES_CSV)
        print(f"[初始化] 已生成 {quotes_path}")

def load_personas_csv(path: str = "personas.csv") -> dict[str, Persona]:
    out: dict[str, Persona] = {}
    with open(path, newline="", encoding="utf-8-sig") as f:
        for r in csv.DictReader(f):
            if not r["persona_id"]:
                continue
            out[r["persona_id"]] = Persona(
                pid=r["persona_id"],
                label=r["persona_label"],
                is_member=r["is_member"].strip().lower() == "true",
                order_cnt_90d=int(r["order_cnt_90d"] or 0),
                device_tier=r["device_tier"],
                region=r["region"],
            )
    return out

def load_quotes_csv(path: str = "quotes.csv") -> dict[str, list[Quote]]:
    ds: dict[str, list[Quote]] = {}
    with open(path, newline="", encoding="utf-8-sig") as f:
        for r in csv.DictReader(f):
            if not r["sku_id"]:
                continue
            q = Quote(
                sku_id=r["sku_id"],
                persona_id=r["persona_id"],
                list_price=float(r["list_price"]),
                coupon_discount=float(r["coupon_discount"] or 0),
                member_discount=float(r["member_discount"] or 0),
                promo_tag=r["promo_tag"] or None,
                platform=r["platform"],
                product_name=r["product_name"],
                collected_at=r["collected_at"] or now_iso(),
            )
            ds.setdefault(q.sku_id, []).append(q)
    return ds

def export_summary_csv(summary: list[dict], path: str = "audit_summary.csv") -> None:
    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow(["sku_id", "platform", "product_name", "risk_level",
                    "max_risk_score", "finding_count", "coupon_issue",
                    "findings_detail", "evidence_sha256"])
        for s in summary:
            w.writerow([
                s["sku_id"], s["platform"], s["product_name"],
                s["risk_level"], s["max_risk_score"],
                s["finding_count"], s["coupon_issue"],
                s["findings_detail"], s["evidence_sha256"],
            ])
    print(f"[导出] 审计汇总已写入 {path}")

# ========================= 主流程 =========================
def main() -> None:
    ensure_csv_files()

    personas = load_personas_csv()
    dataset = load_quotes_csv()

    # 外键校验：quotes 引用的画像必须在 personas 中存在
    all_pids = {q.persona_id for qs in dataset.values() for q in qs}
    missing = all_pids - set(personas)
    if missing:
        raise ValueError(f"quotes.csv 引用了不存在的画像: {missing}")

    detector = FairnessDetector()
    coupon_chk = CouponFairnessChecker()
    summary: list[dict] = []

    for sku, quotes in dataset.items():
        findings = detector.detect(sku, quotes, personas)
        coupon = coupon_chk.check(quotes, personas)
        report = ReportBuilder.build(sku, quotes, findings, coupon)
        print_report(report)

        detail = " | ".join(
            f"{f['persona_label']}(+{f['diff_rate']:.1%},分{f['risk_score']})"
            for f in findings
        ) or "-"

        summary.append({
            "sku_id": sku,
            "platform": report["platform"],
            "product_name": report["product_name"],
            "risk_level": report["risk_level"],
            "max_risk_score": report["max_risk_score"],
            "finding_count": len(findings),
            "coupon_issue": "是" if coupon else "否",
            "findings_detail": detail,
            "evidence_sha256": report["evidence"]["sha256"],
        })

    # 汇总表
    print("\n" + "=" * 68)
    print("审计汇总")
    print("=" * 68)
    print(f"{'SKU':<18}{'风险等级':<10}{'最高分':>8}{'检出数':>8}{'券差':>6}")
    for s in summary:
        print(f"{s['sku_id']:<18}{s['risk_level']:<10}"
              f"{s['max_risk_score']:>8}{s['finding_count']:>8}"
              f"{s['coupon_issue']:>6}")

    export_summary_csv(summary)

    print("\n【合规提示】")
    print("1. 本引擎仅输出价格差异的客观数据与技术分析，不认定违法。")
    print("2. 所有疑似线索须经人工复核，并排除合理商业因素后方可举报/披露。")
    print("3. 采集须使用真实注册账号、公开可见标价，不得侵入平台后台。")

if __name__ == "__main__":
    main()
