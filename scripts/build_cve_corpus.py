#!/usr/bin/env python3
"""Build a pinned curated §12.67 JSONL corpus from downloaded NVD, KEV, EPSS, and CPE-map data."""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any


def _load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected a JSON object")
    return value


def _nvd_records(document: dict[str, Any]) -> dict[str, dict[str, Any]]:
    records: dict[str, dict[str, Any]] = {}
    for item in document.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id")
        if not cve_id:
            continue
        descriptions = cve.get("descriptions", [])
        summary = next(
            (entry.get("value", "") for entry in descriptions if entry.get("lang") == "en"),
            "",
        )
        weaknesses = cve.get("weaknesses", [])
        cwe = next(
            (
                description.get("value", "")
                for weakness in weaknesses
                for description in weakness.get("description", [])
                if description.get("lang") == "en"
            ),
            "",
        )
        metrics = cve.get("metrics", {})
        candidates = metrics.get("cvssMetricV31", []) or metrics.get("cvssMetricV30", [])
        cvss = float(candidates[0].get("cvssData", {}).get("baseScore", 0.0)) if candidates else 0.0
        records[str(cve_id)] = {"cvss": cvss, "cwe": cwe, "summary": summary}
    return records


def _kev_ids(document: dict[str, Any]) -> set[str]:
    return {str(item["cveID"]) for item in document.get("vulnerabilities", []) if item.get("cveID")}


def _epss_scores(path: Path) -> dict[str, float]:
    with path.open(encoding="utf-8", newline="") as handle:
        return {
            str(row["cve"]): float(row["epss"])
            for row in csv.DictReader(line for line in handle if not line.startswith("#"))
            if row.get("cve") and row.get("epss")
        }


def build_corpus(
    *,
    nvd_path: Path,
    kev_path: Path,
    epss_path: Path,
    cpe_map_path: Path,
    output_path: Path,
    corpus_version: str,
) -> int:
    nvd = _nvd_records(_load_json(nvd_path))
    kev = _kev_ids(_load_json(kev_path))
    epss = _epss_scores(epss_path)
    cpe_map = _load_json(cpe_map_path)
    records = []
    for cve_id, mapping in cpe_map.items():
        if cve_id not in nvd or not isinstance(mapping, dict):
            continue
        record = {
            "corpus_version": corpus_version,
            "product": mapping["product"],
            "version_range": mapping["version_range"],
            "cve_id": cve_id,
            "cvss": nvd[cve_id]["cvss"],
            "cwe": nvd[cve_id]["cwe"],
            "kev": cve_id in kev,
            "epss": epss.get(cve_id, 0.0),
            "summary": nvd[cve_id]["summary"],
            "confirm_probe": mapping.get("confirm_probe"),
        }
        records.append(record)
    records.sort(key=lambda record: (not record["kev"], -record["epss"], record["cve_id"]))
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        "".join(json.dumps(record, separators=(",", ":")) + "\n" for record in records),
        encoding="utf-8",
    )
    return len(records)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--nvd", type=Path, required=True)
    parser.add_argument("--kev", type=Path, required=True)
    parser.add_argument("--epss", type=Path, required=True)
    parser.add_argument("--cpe-map", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--version", required=True)
    args = parser.parse_args()
    count = build_corpus(
        nvd_path=args.nvd,
        kev_path=args.kev,
        epss_path=args.epss,
        cpe_map_path=args.cpe_map,
        output_path=args.output,
        corpus_version=args.version,
    )
    print(f"wrote {count} curated CVE records to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
