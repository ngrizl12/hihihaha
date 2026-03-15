#!/usr/bin/env python3

import os
import json
import pandas as pd
import ssl
import urllib.request
from tqdm import tqdm
from dotenv import load_dotenv

load_dotenv(".local.env")

CVE_CSV_PATH = os.getenv("CVE_PROCESSING_OUTPUT")
OUTPUT_JSON = os.getenv("RISK_REFERENCE_OUTPUT")

try:
    cve_df = pd.read_csv(CVE_CSV_PATH)
    
    cve_data = []
    for _, row in cve_df.iterrows():
        cve_id = str(row.get('ID', '')).replace('-', '_')
        cvss = row.get('baseScore')
        if pd.notna(cvss):
            cve_data.append((cve_id, float(cvss)))
    
except Exception as e:
    exit(1)

BATCH_SIZE = 50

epss_cache = {}
epss_errors = 0
epss_success = 0

def get_epss_batch(cve_ids):
    global epss_errors, epss_success
    
    cve_api_ids = [cve_id.replace("_", "-") for cve_id in cve_ids]
    cve_string = ",".join(cve_api_ids)
    
    try:
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        
        url = f"https://api.first.org/data/v1/epss?cve={cve_string}"
        req = urllib.request.Request(url)
        req.add_header('User-Agent', 'Mozilla/5.0')
        
        with urllib.request.urlopen(req, context=ssl_context, timeout=30) as response:
            data = json.loads(response.read().decode())
            
            if data and 'data' in data:
                for item in data['data']:
                    cve_id = item['cve'].replace("-", "_")
                    epss = float(item.get('epss', 0))
                    epss_cache[cve_id] = epss
                    epss_success += 1
                return True
    
    except Exception as e:
        epss_errors += len(cve_ids)
    
    for cve_id in cve_ids:
        epss_cache[cve_id] = None
    
    return False

risk_distribution = []

total_cves = len(cve_data)
total_batches = (total_cves + BATCH_SIZE - 1) // BATCH_SIZE

pbar = tqdm(range(0, total_cves, BATCH_SIZE), desc="Пакеты", unit="пакет", ncols=100)

for batch_start in pbar:
    batch_end = min(batch_start + BATCH_SIZE, total_cves)
    batch = cve_data[batch_start:batch_end]
    
    get_epss_batch([cve_id for cve_id, _ in batch])
    
    for cve_id, cvss in batch:
        epss = epss_cache.get(cve_id)
        if epss is not None and epss > 0:
            risk = cvss * epss
            risk_distribution.append(risk)
    
    processed = min(batch_end, total_cves)
    pbar.set_postfix({
        'прогресс': f'{processed}/{total_cves} ({processed/total_cves*100:.1f}%)',
        'найдено рисков': len(risk_distribution),
        'EPSS ок': epss_success,
        'ошибки': epss_errors
    })

risk_distribution.sort()


with open(OUTPUT_JSON, 'w', encoding='utf-8') as f:
    json.dump(risk_distribution, f)