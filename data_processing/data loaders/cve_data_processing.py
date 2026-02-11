import pandas as pd
import os
from dotenv import load_dotenv

load_dotenv(".local.env")

INPUT_CSV = os.getenv("CVE_OUTPUT")
OUTPUT_CSV = os.getenv("CVE_PROCESSING_OUTPUT")

df = pd.read_csv(INPUT_CSV, low_memory=False)

df["published"] = pd.to_datetime(
    df["published"],
    errors="coerce",
    utc=True
)

cutoff_date = pd.Timestamp.now(tz="UTC") - pd.DateOffset(years=10)

df = df[df["published"] >= cutoff_date]

print(f"После фильтрации (10 лет): {len(df)}")

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

print(f"CVE за последние 10 лет: {len(df)}")