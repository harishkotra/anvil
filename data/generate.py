"""Generate the two datasets Anvil's agent computes over.

Deterministic (fixed seed) so verification runs are reproducible. Run:
    python data/generate.py
"""

from __future__ import annotations

import csv
import math
import random
from datetime import date, datetime, timedelta
from pathlib import Path

OUT = Path(__file__).resolve().parent

rng = random.Random(20260105)

REGIONS = ["North America", "EMEA", "APAC", "LATAM"]
CHANNELS = ["direct", "partner", "self-serve"]
CATEGORIES = ["Workstation", "Server", "Peripheral", "Support Plan"]
UNITS = {
    "Workstation": (1_200, 3_400),
    "Server": (6_500, 18_000),
    "Peripheral": (45, 240),
    "Support Plan": (300, 1_400),
}


def sales_rows(n: int = 500) -> list[dict]:
    rows = []
    day = date(2025, 1, 1)
    for i in range(1, n + 1):
        day += timedelta(days=rng.randint(0, 2))
        category = rng.choice(CATEGORIES)
        low, high = UNITS[category]
        unit_price = round(rng.uniform(low, high), 2)
        quantity = rng.randint(1, 40) if category != "Server" else rng.randint(1, 6)
        # Seasonality: Q4 lifts volume, LATAM grows across the year.
        seasonal = 1.0 + 0.22 * math.sin((day.month / 12.0) * 2 * math.pi)
        quantity = max(1, int(quantity * seasonal))
        discount = rng.choice([0.0, 0.0, 0.05, 0.08, 0.12, 0.15, 0.2])
        gross = round(unit_price * quantity, 2)
        net = round(gross * (1 - discount), 2)
        rows.append(
            {
                "order_id": f"SO-{2025}-{i:05d}",
                "order_date": day.isoformat(),
                "region": rng.choice(REGIONS),
                "channel": rng.choice(CHANNELS),
                "customer_segment": rng.choice(["Enterprise", "Mid-Market", "SMB"]),
                "category": category,
                "sku": f"{category[:2].upper()}-{rng.randint(1000, 9999)}",
                "unit_price": f"{unit_price:.2f}",
                "quantity": quantity,
                "discount_pct": f"{discount:.2f}",
                "gross_amount": f"{gross:.2f}",
                "net_amount": f"{net:.2f}",
                "unit_cost": f"{round(unit_price * rng.uniform(0.42, 0.68), 2):.2f}",
            }
        )
    for r in rows:
        r["gross_profit"] = round(float(r["net_amount"]) - float(r["unit_cost"]) * r["quantity"], 2)
    return rows


SENSOR_DEFS = [
    ("return_temp_c", 62.0, 2.4),
    ("vibration_mmss", 1.1, 0.18),
    ("pressure_bar", 4.8, 0.22),
    ("rpm", 1_750, 42),
    ("power_kw", 11.4, 1.05),
]


def sensor_rows(n: int = 300) -> list[dict]:
    rows = []
    ts = datetime(2025, 6, 1, 0, 0, 0)
    # A bearing degrades over the last third of the window: an anomaly the
    # agent can actually find.
    for i in range(1, n + 1):
        ts += timedelta(minutes=30)
        degrade = max(0.0, (i - 200) / 100.0)
        row = {
            "sample_id": f"S-{i:05d}",
            "captured_at": ts.isoformat(timespec="seconds"),
            "line_id": rng.choice(["line-1", "line-2", "line-3"]),
            "machine_id": f"CNC-{rng.randint(1, 8):02d}",
        }
        for name, base, sd in SENSOR_DEFS:
            value = base + rng.gauss(0, sd)
            if name == "return_temp_c":
                value += degrade * 9.5
            if name == "vibration_mmss":
                value += degrade * 2.6
            if rng.random() < 0.02:
                value += rng.uniform(3.5, 6.0) * sd
            row[name] = f"{value:.3f}"
        row["status"] = rng.choice(["running"] * 9 + ["idle"])
        row["operator"] = f"op-{rng.randint(10, 29)}"
        rows.append(row)
    return rows


def write(path: Path, rows: list[dict]) -> None:
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
    print(f"{path.name}: {len(rows)} rows, {path.stat().st_size} bytes")


if __name__ == "__main__":
    write(OUT / "sales_2025.csv", sales_rows())
    write(OUT / "sensor_log.csv", sensor_rows())
