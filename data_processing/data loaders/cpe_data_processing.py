import pandas as pd
import os
from dotenv import load_dotenv
load_dotenv(".local.env")

CVE_PROCESSING_OUTPUT = os.getenv("CVE_PROCESSING_OUTPUT")
CPE_ALL_CSV = os.getenv("CPE_OUTPUT")
CPE_PROCESSING_OUTPUT = os.getenv("CPE_PROCESSING_OUTPUT")

cpe_all_df = pd.read_csv(CPE_ALL_CSV)

cpe_map = {}
for _, row in cpe_all_df.iterrows():
    cpe23 = row.get("cpe23-item", "")
    if cpe23:
        cpe_map[cpe23] = row

cve_df = pd.read_csv(CVE_PROCESSING_OUTPUT)

used_cpe_set = set()
for cpe_string in cve_df["MatchingCPE"].dropna():
    for cpe in str(cpe_string).split(";"):
        clean = cpe.strip()
        if clean:
            used_cpe_set.add(clean)

def parse_cpe(cpe_str):
    if pd.isna(cpe_str) or not cpe_str:
        return None
    
    parts = cpe_str.split(":")
    if len(parts) >= 12:
        return {
            "part": parts[2],
            "vendor": parts[3],
            "product": parts[4],
            "version": parts[5],
            "update": parts[6],
            "edition": parts[7],
            "language": parts[8],
            "sw_edition": parts[9],
            "target_sw": parts[10],
            "target_hw": parts[11],
            "other": parts[12] if len(parts) > 12 else "*",
            "cpe23-item": cpe_str,
            "title": "",
            "cpe-item": "",
            "lastModified": "",
            "created": ""
        }
    return None

cpe_list = []
for cpe_str in used_cpe_set:
    if cpe_str in cpe_map:
        row = cpe_map[cpe_str]
        cpe_list.append({
            "part": row.get("part", ""),
            "vendor": row.get("vendor", ""),
            "product": row.get("product", ""),
            "version": row.get("version", ""),
            "update": row.get("update", ""),
            "edition": row.get("edition", ""),
            "language": row.get("language", ""),
            "sw_edition": row.get("sw_edition", ""),
            "target_sw": row.get("target_sw", ""),
            "target_hw": row.get("target_hw", ""),
            "other": row.get("other", ""),
            "cpe23-item": row.get("cpe23-item", cpe_str),
            "title": row.get("title", ""),
            "cpe-item": row.get("cpe-item", ""),
            "lastModified": row.get("lastModified", ""),
            "created": row.get("created", "")
        })
    else:
        parsed = parse_cpe(cpe_str)
        if parsed:
            cpe_list.append(parsed)

cpe_df = pd.DataFrame(cpe_list)

columns_to_keep = [
    "part",
    "vendor", 
    "product",
    "version",
    "update",
    "edition",
    "language",
    "sw_edition",
    "target_sw",
    "target_hw",
    "other",
    "cpe23-item",
    "title",
    "cpe-item",
    "lastModified",
    "created"
]

cpe_df = cpe_df[columns_to_keep]

cpe_df = cpe_df.drop_duplicates(subset=["cpe23-item"], keep="first")

cpe_df.to_csv(CPE_PROCESSING_OUTPUT, index=False)