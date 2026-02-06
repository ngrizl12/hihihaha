import requests
import pandas as pd
import time
from datetime import datetime, timedelta, timezone
import os
from dotenv import load_dotenv
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
load_dotenv(".local.env")

API_KEY = os.getenv("API_KEY")
BASE_URL = "https://services.nvd.nist.gov/rest/json/cpes/2.0"

RESULTS_PER_PAGE = 500
SLEEP_SECONDS = 1.2

DATE_LIMIT = datetime.min.replace(tzinfo=timezone.utc)

OUTPUT_CSV = os.getenv("CPE_OUTPUT")

session = requests.Session()

retries = Retry(
    total=5,
    backoff_factor=2,
    status_forcelist=[429, 500, 502, 503, 504],
    allowed_methods=["GET"]
)
session.mount("https://", HTTPAdapter(max_retries=retries))

headers = {
    "apiKey": API_KEY,
    "User-Agent": "VKRDataloader/1.0"
}

params = {
    "resultsPerPage": RESULTS_PER_PAGE,
    "startIndex": 0
}

rows = []
total_results = None
stop_loading = False

while not stop_loading:
    try:
        response = session.get(
            BASE_URL,
            headers=headers,
            params=params,
            timeout=(10, 120)  
        )
        response.raise_for_status()
        data = response.json()

    except requests.exceptions.RequestException as e:
        print(f"HTTP ERROR: {e}")
        print("Повтор через 10 секунд...")
        time.sleep(10)
        continue

    if total_results is None:
        total_results = data.get("totalResults", 0)
        print(f"Всего CPE в базе: {total_results}")

    products = data.get("products", [])
    if not products:
        break

    for product in products:
        cpe = product.get("cpe", {})
        if cpe.get("deprecated"):
            continue

        last_modified_str = cpe.get("lastModified")
        if not last_modified_str:
            continue

        try:
            last_modified_dt = datetime.fromisoformat(last_modified_str.replace("Z", "+00:00"))
        except ValueError:
            continue

        if last_modified_dt.tzinfo is None:
            last_modified_dt = last_modified_dt.replace(tzinfo=timezone.utc)

        if last_modified_dt < DATE_LIMIT:
            stop_loading = True
            break

        cpe23 = cpe.get("cpeName")
        if not cpe23:
            continue

        cpe23_clean = (
            cpe23.replace("\\,", ".")
                 .replace("\\:", ";")
                 .replace('"', "'")
        )

        parts = cpe23_clean.split(":")
        if len(parts) < 13:
            continue

        rows.append({
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
            "other": parts[12],
            "cpe23-item": cpe23_clean,
            "title": cpe.get("titles")[0]["title"] if cpe.get("titles") else "",
            "cpe-item": cpe.get("cpeNameId"),
            "lastModified": last_modified_str,
            "created": cpe.get("created")
        })

    params["startIndex"] += RESULTS_PER_PAGE
    print(f"Загружено: {min(params['startIndex'], total_results)} / {total_results}")

    time.sleep(SLEEP_SECONDS)


df = pd.DataFrame(rows)
df.to_csv(OUTPUT_CSV, index=False)

print(f"Сохранено CPE: {len(df)}")