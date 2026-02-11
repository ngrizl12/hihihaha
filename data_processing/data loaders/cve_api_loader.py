import requests
import pandas as pd
import time
import os
from datetime import datetime, timezone
from dotenv import load_dotenv
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

load_dotenv(".local.env")

API_KEY = os.getenv("API_KEY")
OUTPUT_CSV = os.getenv("CVE_OUTPUT")

BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

RESULTS_PER_PAGE = 2000
SLEEP_SECONDS = 1.2

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

while True:
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
        print(f"Всего CVE в базе: {total_results}")

    vulns = data.get("vulnerabilities", [])
    if not vulns:
        break

    for item in vulns:
        cve = item.get("cve", {})
        cve_id = cve.get("id")

        description = ""
        desc_data = cve.get("descriptions", [])
        for d in desc_data:
            if d.get("lang") == "en":
                description = d.get("value", "")
                break

        cwe_list = []
        for weakness in cve.get("weaknesses", []):
            for desc in weakness.get("description", []):
                if desc.get("lang") == "en":
                    cwe_list.append(desc.get("value"))
        cwe_str = ";".join(set(cwe_list))

        cpe_list = []
        for config in cve.get("configurations", []):
            for node in config.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    if match.get("vulnerable"):
                        cpe_list.append(match.get("criteria"))
        cpe_str = ";".join(set(cpe_list))

        baseSeverity = ""
        baseScore = ""
        impactScore = ""
        exploitabilityScore = ""
        cvssVector = ""

        metrics = cve.get("metrics", {})
        if "cvssMetricV31" in metrics:
            m = metrics["cvssMetricV31"][0]
        elif "cvssMetricV30" in metrics:
            m = metrics["cvssMetricV30"][0]
        else:
            m = None

        if m:
            cvss = m.get("cvssData", {})
            baseSeverity = cvss.get("baseSeverity", "")
            baseScore = cvss.get("baseScore", "")
            cvssVector = cvss.get("vectorString", "")
            impactScore = m.get("impactScore", "")
            exploitabilityScore = m.get("exploitabilityScore", "")

        rows.append({
            "ID": cve_id,
            "MatchingCWE": cwe_str,
            "MatchingCPE": cpe_str,
            "baseSeverity": baseSeverity,
            "baseScore": baseScore,
            "impactScore": impactScore,
            "exploitabilityScore": exploitabilityScore,
            "cvssV3_Vector": cvssVector,
            "description": description,
            "published": cve.get("published"),
            "lastModified": cve.get("lastModified")
        })

    params["startIndex"] += RESULTS_PER_PAGE
    print(f"Загружено: {min(params['startIndex'], total_results)} / {total_results}")

    time.sleep(SLEEP_SECONDS)

df = pd.DataFrame(rows)
df.to_csv(OUTPUT_CSV, index=False, encoding="utf-8-sig")

print(f"Готово. Сохранено CVE: {len(df)}")