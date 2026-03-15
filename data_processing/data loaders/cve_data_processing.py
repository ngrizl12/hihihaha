import pandas as pd
import os
from dotenv import load_dotenv

load_dotenv(".local.env")

INPUT_CSV = os.getenv("CVE_OUTPUT")
OUTPUT_CSV = os.getenv("CVE_PROCESSING_OUTPUT")
CPE_ALL_CSV = os.getenv("CPE_OUTPUT")

cpe_df = pd.read_csv(CPE_ALL_CSV)

def normalize_cpe(cpe_str):
    if pd.isna(cpe_str) or not cpe_str:
        return None
    parts = cpe_str.split(":")
    if len(parts) >= 12:
        key = f"{parts[2]}:{parts[3]}:{parts[4]}:{parts[5]}:{parts[10]}:{parts[11]}"
        return key.lower()
    return None

cpe_mapping = {}
for _, row in cpe_df.iterrows():
    cpe23 = row.get("cpe23-item", "")
    if cpe23:
        norm_key = normalize_cpe(cpe23)
        if norm_key:
            cpe_mapping[norm_key] = cpe23


def match_cpe(cpe_str):
    if pd.isna(cpe_str) or not cpe_str:
        return ""
    
    result_cpes = []
    for cpe in cpe_str.split(";"):
        cpe = cpe.strip()
        if not cpe:
            continue
        
        norm_key = normalize_cpe(cpe)
        if norm_key and norm_key in cpe_mapping:
            result_cpes.append(cpe_mapping[norm_key])
        else:
            result_cpes.append(cpe)
    
    return ";".join(result_cpes)

df = pd.read_csv(INPUT_CSV, low_memory=False)

df["MatchingCPE"] = df["MatchingCPE"].apply(match_cpe)

df["published"] = pd.to_datetime(
    df["published"],
    errors="coerce",
    utc=True
)

cutoff_date = pd.Timestamp.now(tz="UTC") - pd.DateOffset(years=20)

df = df[df["published"] >= cutoff_date]


df["description"] = (
    df["description"]
        .fillna("")
        .str.replace(r"\s+", " ", regex=True)  # убираем переносы и лишние пробелы
        .str.strip()
)

df = df.drop_duplicates(subset=["ID"], keep="first")

columns_to_keep = [
    "ID",
    "MatchingCWE",
    "MatchingCPE",
    "baseSeverity",
    "baseScore",
    "impactScore",
    "exploitabilityScore",
    "cvssV3_Vector",
    "description"
]

df = df[columns_to_keep]

df.to_csv(
    OUTPUT_CSV,
    index=False,
    encoding="utf-8-sig"
)