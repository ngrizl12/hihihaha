import pandas as pd
import os
from dotenv import load_dotenv
load_dotenv(".local.env")

INPUT_CSV = os.getenv("CPE_OUTPUT")
CPE_PROCESSING_OUTPUT = os.getenv("CPE_PROCESSING_OUTPUT")

df = pd.read_csv(INPUT_CSV)

df["lastModified"] = pd.to_datetime(df["lastModified"])

cutoff_date = pd.Timestamp.now() - pd.DateOffset(years=5)
df = df[df["lastModified"] >= cutoff_date]

df = df.sort_values(by="lastModified", ascending=False)

df = df.drop_duplicates(
    subset=[
        "part",
        "vendor",
        "product",
        "version",
        "target_sw",
        "target_hw"
    ],
    keep="first"
)

df["name"] = (
    "cpe:" +
    df["part"] + ":" +
    df["vendor"] + ":" +
    df["product"] + ":" +
    df["version"] + ":" +
    df["target_sw"] + ":" +
    df["target_hw"]
)

df.to_csv(CPE_PROCESSING_OUTPUT, index=False)
