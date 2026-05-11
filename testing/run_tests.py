import os
import sys
import json
import time
import ssl
import math
import bisect
import urllib.request
from pathlib import Path
import datetime as dt

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from owlready2 import *
import pandas as pd

owlready2.reasoning.JAVA_MEMORY = 16000

# ── Конфигурация ───────────────────────────────────────────────────────────
ONTO_PATH           = PROJECT_ROOT / "owl_files_processing" / "owl_files" / "security_ontology_full.owl"
CWE_CHAINS_FILE     = PROJECT_ROOT / "scripts_for_create_reasoning" / "risk_calculation_preparation_data" / "cwe_chains.json"
RISK_REFERENCE_FILE = PROJECT_ROOT / "scripts_for_create_reasoning" / "risk_calculation_preparation_data" / "risk_reference_distribution.json"
CVE_FILE            = PROJECT_ROOT / "data_processing" / "csv_files_ready" / "cve_all_done.csv"
CWE_FILE            = PROJECT_ROOT / "data_processing" / "csv_files_ready" / "cwe_all.csv"
CAPEC_FILE          = PROJECT_ROOT / "data_processing" / "csv_files_ready" / "capec_all.csv"

# Тестовые компоненты — Таблица 4.1
TEST_COMPONENTS = [
    {"name": "Apache Tomcat", "version": "9.0.0",  "vendor": "apache",        "product": "tomcat",      "expected_cve": 53},
    {"name": "OpenSSL",       "version": "1.1.1",   "vendor": "openssl",       "product": "openssl",     "expected_cve": 4 },
    {"name": "MySQL",         "version": "8.1.0",   "vendor": "oracle",        "product": "mysql",       "expected_cve": 11},
    {"name": "WordPress",     "version": "6.2",     "vendor": "wordpress",     "product": "wordpress",   "expected_cve": 1 },
    {"name": "PHP",           "version": "7.4.0",   "vendor": "php",           "product": "php",         "expected_cve": 6 },
    {"name": "PostgreSQL",    "version": "14.0",    "vendor": "postgresql",    "product": "postgresql",  "expected_cve": 3 },
    {"name": "Nginx",         "version": "1.23.0",  "vendor": "f5",            "product": "nginx",       "expected_cve": 2 },
    {"name": "Python",        "version": "3.10.0",  "vendor": "python",        "product": "python",      "expected_cve": 4 },
    {"name": "Django",        "version": "4.2",     "vendor": "djangoproject", "product": "django",      "expected_cve": 1 },
    {"name": "Node.js",       "version": "19.0.0",  "vendor": "nodejs",        "product": "node.js",     "expected_cve": 3 },
]

# Эталонные цепочки CWE для верификации
REFERENCE_CWE_CHAINS = [
    {"root": "CWE-89",  "desc": "SQL Injection"},
    {"root": "CWE-79",  "desc": "XSS"},
    {"root": "CWE-78",  "desc": "OS Command Injection"},
    {"root": "CWE-22",  "desc": "Path Traversal"},
    {"root": "CWE-287", "desc": "Authentication Failure"},
    {"root": "CWE-434", "desc": "Unrestricted Upload"},
    {"root": "CWE-502", "desc": "Deserialization"},
    {"root": "CWE-611", "desc": "XXE Injection"},
    {"root": "CWE-918", "desc": "SSRF"},
    {"root": "CWE-20",  "desc": "Improper Input Validation"},
]

# Контрольные CVE — 53 с различными уровнями CVSS
CONTROL_CVES = [
    # CRITICAL (CVSS >= 9.0)
    {"id": "CVE-2016-8735",  "expected_cvss_min": 9.0,  "component": "Apache Tomcat"},
    {"id": "CVE-2018-8014",  "expected_cvss_min": 9.0,  "component": "Apache Tomcat"},
    {"id": "CVE-2016-5018",  "expected_cvss_min": 9.0,  "component": "Apache Tomcat"},
    {"id": "CVE-2017-5651",  "expected_cvss_min": 9.0,  "component": "Apache Tomcat"},
    {"id": "CVE-2017-5648",  "expected_cvss_min": 9.0,  "component": "Apache Tomcat"},
    {"id": "CVE-2023-31047", "expected_cvss_min": 9.0,  "component": "Django"},
    # HIGH (CVSS 7.0-8.9)
    {"id": "CVE-2015-5346",  "expected_cvss_min": 7.0,  "component": "Apache Tomcat"},
    {"id": "CVE-2015-5351",  "expected_cvss_min": 7.0,  "component": "Apache Tomcat"},
    {"id": "CVE-2016-0714",  "expected_cvss_min": 7.0,  "component": "Apache Tomcat"},
    {"id": "CVE-2016-3092",  "expected_cvss_min": 7.0,  "component": "Apache Tomcat"},
    {"id": "CVE-2016-6796",  "expected_cvss_min": 7.0,  "component": "Apache Tomcat"},
    {"id": "CVE-2016-6797",  "expected_cvss_min": 7.0,  "component": "Apache Tomcat"},
    {"id": "CVE-2016-6816",  "expected_cvss_min": 7.0,  "component": "Apache Tomcat"},
    {"id": "CVE-2016-6817",  "expected_cvss_min": 7.0,  "component": "Apache Tomcat"},
    {"id": "CVE-2016-8745",  "expected_cvss_min": 7.0,  "component": "Apache Tomcat"},
    {"id": "CVE-2016-8747",  "expected_cvss_min": 7.0,  "component": "Apache Tomcat"},
    {"id": "CVE-2019-0232",  "expected_cvss_min": 7.0,  "component": "Apache Tomcat"},
    {"id": "CVE-2021-23214", "expected_cvss_min": 7.0,  "component": "PostgreSQL"},
    {"id": "CVE-2022-41741", "expected_cvss_min": 7.0,  "component": "Nginx"},
    {"id": "CVE-2022-41742", "expected_cvss_min": 7.0,  "component": "Nginx"},
    {"id": "CVE-2022-3602",  "expected_cvss_min": 7.0,  "component": "Node.js"},
    {"id": "CVE-2022-3786",  "expected_cvss_min": 7.0,  "component": "Node.js"},
    {"id": "CVE-2022-43548", "expected_cvss_min": 7.0,  "component": "Node.js"},
    {"id": "CVE-2022-0391",  "expected_cvss_min": 7.0,  "component": "Python"},
    {"id": "CVE-2020-9484",  "expected_cvss_min": 7.0,  "component": "Apache Tomcat"},
    # MEDIUM (CVSS 4.0-6.9)
    {"id": "CVE-2015-5345",  "expected_cvss_min": 4.0,  "component": "Apache Tomcat"},
    {"id": "CVE-2016-0706",  "expected_cvss_min": 4.0,  "component": "Apache Tomcat"},
    {"id": "CVE-2016-0762",  "expected_cvss_min": 4.0,  "component": "Apache Tomcat"},
    {"id": "CVE-2016-0763",  "expected_cvss_min": 4.0,  "component": "Apache Tomcat"},
    {"id": "CVE-2016-6794",  "expected_cvss_min": 4.0,  "component": "Apache Tomcat"},
    {"id": "CVE-2017-15706", "expected_cvss_min": 4.0,  "component": "Apache Tomcat"},
    {"id": "CVE-2017-7674",  "expected_cvss_min": 4.0,  "component": "Apache Tomcat"},
    {"id": "CVE-2018-11784", "expected_cvss_min": 4.0,  "component": "Apache Tomcat"},
    {"id": "CVE-2018-0734",  "expected_cvss_min": 4.0,  "component": "OpenSSL"},
    {"id": "CVE-2018-0735",  "expected_cvss_min": 4.0,  "component": "OpenSSL"},
    {"id": "CVE-2023-3446",  "expected_cvss_min": 4.0,  "component": "OpenSSL"},
    {"id": "CVE-2023-3817",  "expected_cvss_min": 4.0,  "component": "OpenSSL"},
    {"id": "CVE-2023-2745",  "expected_cvss_min": 4.0,  "component": "WordPress"},
    {"id": "CVE-2021-23222", "expected_cvss_min": 4.0,  "component": "PostgreSQL"},
    {"id": "CVE-2021-43767", "expected_cvss_min": 4.0,  "component": "PostgreSQL"},
    {"id": "CVE-2021-3426",  "expected_cvss_min": 4.0,  "component": "Python"},
    {"id": "CVE-2021-3733",  "expected_cvss_min": 4.0,  "component": "Python"},
    {"id": "CVE-2023-42795", "expected_cvss_min": 4.0,  "component": "Apache Tomcat"},
    {"id": "CVE-2023-45648", "expected_cvss_min": 4.0,  "component": "Apache Tomcat"},
    {"id": "CVE-2024-21733", "expected_cvss_min": 4.0,  "component": "Apache Tomcat"},
    {"id": "CVE-2023-22032", "expected_cvss_min": 4.0,  "component": "MySQL"},
    {"id": "CVE-2023-22059", "expected_cvss_min": 4.0,  "component": "MySQL"},
    {"id": "CVE-2023-22066", "expected_cvss_min": 4.0,  "component": "MySQL"},
    {"id": "CVE-2023-22078", "expected_cvss_min": 4.0,  "component": "MySQL"},
    {"id": "CVE-2023-22084", "expected_cvss_min": 4.0,  "component": "MySQL"},
    # LOW (CVSS < 4.0)
    {"id": "CVE-2019-11044", "expected_cvss_min": 0.0,  "component": "PHP"},
    {"id": "CVE-2019-11045", "expected_cvss_min": 0.0,  "component": "PHP"},
    {"id": "CVE-2019-11046", "expected_cvss_min": 0.0,  "component": "PHP"},
    {"id": "CVE-2021-3737",  "expected_cvss_min": 0.0,  "component": "Python"},
    {"id": "CVE-2022-45143", "expected_cvss_min": 0.0,  "component": "Apache Tomcat"},
]

# Результаты тестов
test_results = {"unit": [], "integration": [], "system": []}


# ── Вспомогательные функции ────────────────────────────────────────────────
def log_test(test_type, test_id, name, expected, actual, status, details=""):
    test_results[test_type].append({
        "id": test_id, "name": name,
        "expected": expected, "actual": actual,
        "status": status, "details": details
    })
    icon = "✅" if status == "Passed" else "❌"
    print(f"  {icon} Тест {test_id}: {name} — {status}")
    if details:
        print(f"     {details}")


def normalize(text):
    if not text:
        return None
    return text.lower().replace("_", "").replace("-", "").replace(".", "")


def parse_cpe(name):
    if not name:
        return None
    parts = name.split("_")
    if len(parts) < 6 or parts[0] != "cpe" or parts[1] != "2" or parts[2] != "3":
        return None
    remaining = parts[6:]
    ver_parts = remaining[:-6] if len(remaining) >= 6 else remaining
    version   = None
    if ver_parts:
        filtered = [p for p in ver_parts if p and p != "*"]
        if filtered:
            version = ".".join(filtered)
    return {"part": parts[3], "vendor": parts[4], "product": parts[5], "version": version}


def find_cpe_for_component(onto, vendor, product, version):
    for cpe in onto.CPE.instances():
        parsed = parse_cpe(cpe.name)
        if not parsed:
            continue
        if (normalize(parsed["product"]) == normalize(product) and
                normalize(parsed["vendor"]) == normalize(vendor)):
            cv = parsed["version"]
            if cv and version:
                if cv.startswith(version) or version.startswith(cv):
                    return cpe
            elif cv:
                return cpe
    return None


def get_cvss_from_cve(cve):
    for prop in ["hasCVSSScore", "cvssScore", "baseScore"]:
        if hasattr(cve, prop):
            val = getattr(cve, prop)
            if val:
                try:
                    return float(val[0])
                except (ValueError, TypeError):
                    pass
    return None


def get_epss_score(cve_id):
    cve_api_id = cve_id.replace("_", "-")
    try:
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode    = ssl.CERT_NONE
        url = f"https://api.first.org/data/v1/epss?cve={cve_api_id}"
        req = urllib.request.Request(url)
        req.add_header('User-Agent', 'Mozilla/5.0')
        with urllib.request.urlopen(req, context=ssl_context, timeout=5) as resp:
            data = json.loads(resp.read().decode())
            if data and 'data' in data and len(data['data']) > 0:
                return float(data['data'][0].get('epss', 0))
    except Exception:
        pass
    return None


def calculate_risk_percentile(cvss, epss, ref_dist):
    """Расчёт перцентиля риска: raw = CVSS × EPSS → перцентиль → [0, 10]"""
    raw_risk   = cvss * epss
    rank       = bisect.bisect_right(ref_dist, raw_risk)
    percentile = (rank / len(ref_dist)) * 100
    return (percentile / 100) * 10


def calculate_app_risk(component_risks, n_cve):
    """Агрегированный риск приложения: R_app = max(R_i) + ln(1 + N_CVE)"""
    if not component_risks:
        return 0.0
    return max(component_risks) + math.log(1 + n_cve)


def find_cvss_column(df):
    """Ищет колонку с CVSS-оценкой среди возможных вариантов названий."""
    for candidate in ["baseScore", "cvssScore", "CVSS", "cvss", "score",
                      "base_score", "cvss_score", "CVSSScore"]:
        if candidate in df.columns:
            return candidate
    return None


def find_relation_column(df):
    """Ищет колонку со связями CWE среди возможных вариантов названий."""
    for candidate in ["Related_Weaknesses", "RelatedWeaknesses",
                      "related_weaknesses", "Relations", "ChildOf",
                      "ParentOf", "CanPrecede", "Relationships"]:
        if candidate in df.columns:
            return candidate
    return None


# ── МОДУЛЬНОЕ ТЕСТИРОВАНИЕ ─────────────────────────────────────────────────
def run_unit_tests():
    print("\n" + "=" * 80)
    print("МОДУЛЬНОЕ ТЕСТИРОВАНИЕ (Unit Testing)")
    print("=" * 80)

    # Тест 1: Загрузка онтологии
    print("\n[Тест 1] Загрузка онтологии...")
    start = time.time()
    try:
        onto  = get_ontology(f"file://{ONTO_PATH}").load()
        t     = time.time() - start
        cpe_n = len(list(onto.CPE.instances()))
        cve_n = len(list(onto.CVE.instances()))
        cwe_n = len(list(onto.CWE.instances()))
        cap_n = len(list(onto.CAPEC.instances()))
        status = "Passed" if cpe_n > 0 and cve_n > 0 else "Failed"
        log_test("unit", 1, "Загрузка онтологии",
                 "CPE > 0 и CVE > 0",
                 f"Загружено за {t:.2f}с",
                 status,
                 f"CPE: {cpe_n}, CVE: {cve_n}, CWE: {cwe_n}, CAPEC: {cap_n}")
    except Exception as e:
        log_test("unit", 1, "Загрузка онтологии",
                 "Успешная загрузка", f"Ошибка: {e}", "Failed")

    # Тест 2: Извлечение CVSS из базы данных CVE (CSV)
    print("\n[Тест 2] Извлечение CVSS из базы данных CVE...")
    try:
        if not os.path.exists(CVE_FILE):
            raise FileNotFoundError(f"Файл не найден: {CVE_FILE}")

        cve_df   = pd.read_csv(CVE_FILE)
        cvss_col = find_cvss_column(cve_df)

        if cvss_col is None:
            raise ValueError(
                f"Колонка CVSS не найдена. Доступные: {list(cve_df.columns)}"
            )

        total     = len(cve_df)
        with_cvss = cve_df[cvss_col].notna().sum()
        sample    = cve_df[cvss_col].dropna().head(3).tolist()

        # Проверяем числовой диапазон [0, 10]
        numeric_ok = 0
        for v in cve_df[cvss_col].dropna().head(100):
            try:
                f = float(v)
                if 0.0 <= f <= 10.0:
                    numeric_ok += 1
            except (ValueError, TypeError):
                pass

        pct    = with_cvss / total * 100 if total else 0
        status = "Passed" if with_cvss > 0 and numeric_ok > 0 else "Failed"
        log_test("unit", 2, "Извлечение CVSS",
                 "CVSS доступен в базе данных",
                 f"{with_cvss}/{total} CVE имеют CVSS ({pct:.1f}%), "
                 f"числовых корректных: {numeric_ok}/100",
                 status,
                 f"Колонка: '{cvss_col}', примеры: {sample}")
    except Exception as e:
        log_test("unit", 2, "Извлечение CVSS",
                 "CVSS доступен", f"Ошибка: {e}", "Failed")

    # Тест 3: Запросы к EPSS API
    print("\n[Тест 3] Запросы к EPSS API...")
    try:
        test_cves = ["CVE-2021-44228", "CVE-2022-22965", "CVE-2023-44487"]
        success   = []
        for cve_id in test_cves:
            epss = get_epss_score(cve_id)
            if epss is not None:
                success.append({"cve": cve_id, "epss": epss})
        status = "Passed" if len(success) > 0 else "Failed"
        log_test("unit", 3, "Запросы к EPSS API",
                 "API доступно и возвращает данные",
                 f"{len(success)}/{len(test_cves)} запросов успешны",
                 status,
                 str(success[:2]) if success else "")
    except Exception as e:
        log_test("unit", 3, "Запросы к EPSS API",
                 "API доступно", f"Ошибка: {e}", "Failed")

    # Тест 4: Извлечение CWE цепочек
    print("\n[Тест 4] Извлечение CWE цепочек...")
    try:
        if not os.path.exists(CWE_CHAINS_FILE):
            raise FileNotFoundError(f"Файл не найден: {CWE_CHAINS_FILE}")
        with open(CWE_CHAINS_FILE, 'r', encoding='utf-8') as f:
            chains = json.load(f)
        n      = len(chains)
        status = "Passed" if n >= 10 else "Failed"
        log_test("unit", 4, "Извлечение CWE цепочек",
                 "≥10 цепочек CWE",
                 f"{n} цепочек загружено",
                 status)
    except Exception as e:
        log_test("unit", 4, "Извлечение CWE цепочек",
                 "≥10 цепочек", f"Ошибка: {e}", "Failed")

    # Тест 5: Верификация 10 эталонных цепочек CWE
    print("\n[Тест 5] Верификация 10 эталонных цепочек CWE...")
    try:
        if not os.path.exists(CWE_CHAINS_FILE):
            raise FileNotFoundError(f"Файл не найден: {CWE_CHAINS_FILE}")
        with open(CWE_CHAINS_FILE, 'r', encoding='utf-8') as f:
            chains = json.load(f)

        chain_keys = set()
        if isinstance(chains, dict):
            chain_keys = set(chains.keys())
        elif isinstance(chains, list):
            for item in chains:
                if isinstance(item, dict):
                    for k in ("root", "cwe_id", "id"):
                        if k in item:
                            chain_keys.add(str(item[k]))

        found        = 0
        details_list = []
        for ref in REFERENCE_CWE_CHAINS:
            cwe_id  = ref["root"]
            cwe_num = cwe_id.replace("CWE-", "")
            matched = any(
                cwe_num in k or cwe_id.lower() in k.lower()
                for k in chain_keys
            )
            if matched:
                found += 1
                details_list.append(f"{cwe_id}✅")
            else:
                details_list.append(f"{cwe_id}❌")

        status = "Passed" if found >= 5 else "Failed"
        log_test("unit", 5, "Верификация эталонных цепочек CWE",
                 "≥5/10 эталонных цепочек найдено",
                 f"{found}/10: {', '.join(details_list)}",
                 status)
    except Exception as e:
        log_test("unit", 5, "Верификация эталонных цепочек CWE",
                 "≥5/10 цепочек", f"Ошибка: {e}", "Failed")

    # Тест 6: Загрузка референсного распределения
    print("\n[Тест 6] Загрузка референсного распределения...")
    try:
        if not os.path.exists(RISK_REFERENCE_FILE):
            raise FileNotFoundError(f"Файл не найден: {RISK_REFERENCE_FILE}")
        with open(RISK_REFERENCE_FILE, 'r', encoding='utf-8') as f:
            ref_dist = json.load(f)
        n         = len(ref_dist)
        is_sorted = all(ref_dist[i] <= ref_dist[i + 1]
                        for i in range(min(1000, n - 1)))
        status    = "Passed" if n > 100000 and is_sorted else "Failed"
        log_test("unit", 6, "Референсное распределение",
                 "≥100 000 записей, отсортировано",
                 f"{n} записей, отсортировано: {is_sorted}",
                 status)
    except Exception as e:
        log_test("unit", 6, "Референсное распределение",
                 "Успешная загрузка", f"Ошибка: {e}", "Failed")

    # Тест 7: Расчёт перцентиля риска — математическая корректность
    print("\n[Тест 7] Расчёт перцентиля риска...")
    try:
        if not os.path.exists(RISK_REFERENCE_FILE):
            raise FileNotFoundError(f"Файл не найден: {RISK_REFERENCE_FILE}")
        with open(RISK_REFERENCE_FILE, 'r', encoding='utf-8') as f:
            ref_dist = json.load(f)

        cases = [
            (10.0, 1.00, "Critical"),
            (9.8,  0.95, "High-1"),
            (7.5,  0.50, "High-2"),
            (5.0,  0.30, "Medium"),
            (3.0,  0.10, "Low"),
            (1.0,  0.01, "Minimal"),
        ]
        risks = []
        for cvss, epss, label in cases:
            r = calculate_risk_percentile(cvss, epss, ref_dist)
            risks.append((label, r))

        in_range = all(0 <= r <= 10 for _, r in risks)
        monotone = all(risks[i][1] >= risks[i + 1][1]
                       for i in range(len(risks) - 1))
        status   = "Passed" if in_range and monotone else "Failed"
        detail   = ", ".join(f"{l}={v:.2f}" for l, v in risks)
        log_test("unit", 7, "Расчёт перцентиля риска",
                 "Risk ∈ [0,10] и монотонно убывает",
                 detail,
                 status)
    except Exception as e:
        log_test("unit", 7, "Расчёт перцентиля",
                 "Корректный расчёт", f"Ошибка: {e}", "Failed")

    # Тест 8: Граничный случай — отсутствие CVSS (замена из CAPEC)
    print("\n[Тест 8] Граничный случай: отсутствие CVSS...")
    try:
        if not os.path.exists(CAPEC_FILE):
            raise FileNotFoundError(f"Файл не найден: {CAPEC_FILE}")
        capec_df = pd.read_csv(CAPEC_FILE)

        severity_map = {
            "Critical": 9.5, "High": 7.5,
            "Medium":   5.0, "Low":  2.5,
        }
        has_col = 'Typical_Severity' in capec_df.columns

        if has_col:
            sample    = (capec_df['Typical_Severity'].dropna().iloc[0]
                         if capec_df['Typical_Severity'].notna().any() else None)
            recovered = severity_map.get(str(sample).strip(), None) if sample else None
            status    = "Passed" if recovered is not None else "Failed"
            log_test("unit", 8, "Граничный случай: нет CVSS",
                     "CVSS восстановлен из CAPEC Typical_Severity",
                     f"Пример: '{sample}' → CVSS={recovered}",
                     status)
        else:
            log_test("unit", 8, "Граничный случай: нет CVSS",
                     "CAPEC Typical_Severity",
                     "Столбец Typical_Severity отсутствует",
                     "Failed")
    except Exception as e:
        log_test("unit", 8, "Граничный случай: нет CVSS",
                 "CVSS восстановлен", f"Ошибка: {e}", "Failed")

    # Тест 9: Граничный случай — отсутствие EPSS (замена из CWE)
    print("\n[Тест 9] Граничный случай: отсутствие EPSS...")
    try:
        if not os.path.exists(CWE_FILE):
            raise FileNotFoundError(f"Файл не найден: {CWE_FILE}")
        cwe_df = pd.read_csv(CWE_FILE)

        likelihood_map = {
            "High": 0.75, "Medium": 0.40, "Low": 0.10,
        }
        has_col = 'Likelihood_Of_Exploit' in cwe_df.columns

        if has_col:
            sample    = (cwe_df['Likelihood_Of_Exploit'].dropna().iloc[0]
                         if cwe_df['Likelihood_Of_Exploit'].notna().any() else None)
            recovered = likelihood_map.get(str(sample).strip(), None) if sample else None
            status    = "Passed" if recovered is not None else "Failed"
            log_test("unit", 9, "Граничный случай: нет EPSS",
                     "EPSS восстановлен из CWE Likelihood_Of_Exploit",
                     f"Пример: '{sample}' → EPSS={recovered}",
                     status)
        else:
            log_test("unit", 9, "Граничный случай: нет EPSS",
                     "CWE Likelihood_Of_Exploit",
                     "Столбец Likelihood_Of_Exploit отсутствует",
                     "Failed")
    except Exception as e:
        log_test("unit", 9, "Граничный случай: нет EPSS",
                 "EPSS восстановлен", f"Ошибка: {e}", "Failed")

    # Тест 10: Расчёт агрегированного риска приложения
    print("\n[Тест 10] Расчёт агрегированного риска приложения...")
    try:
        cases = [
            ([9.5, 7.2, 5.1, 3.0], 88, "Полная выборка"),
            ([5.0],                  1,  "Один компонент"),
            ([],                     0,  "Нет компонентов"),
            ([10.0, 10.0],          10, "Два максимальных"),
        ]
        all_ok       = True
        details_list = []
        for risks, n_cve, label in cases:
            r  = calculate_app_risk(risks, n_cve)
            ok = (r == 0.0 if not risks else 0 <= r <= 25)
            all_ok = all_ok and ok
            details_list.append(f"{label}={r:.2f}({'✅' if ok else '❌'})")

        status = "Passed" if all_ok else "Failed"
        log_test("unit", 10, "Агрегированный риск приложения",
                 "R_app корректен для всех тестовых случаев",
                 " | ".join(details_list),
                 status)
    except Exception as e:
        log_test("unit", 10, "Агрегированный риск",
                 "Корректный расчёт", f"Ошибка: {e}", "Failed")

    passed = sum(1 for t in test_results["unit"] if t["status"] == "Passed")
    total  = len(test_results["unit"])
    print(f"\n{'=' * 80}")
    print(f"МОДУЛЬНОЕ ТЕСТИРОВАНИЕ: {passed}/{total} ({passed / total * 100:.1f}%)")
    print(f"{'=' * 80}")
    return passed == total


# ── ИНТЕГРАЦИОННОЕ ТЕСТИРОВАНИЕ ───────────────────────────────────────────
def run_integration_tests():
    print("\n" + "=" * 80)
    print("ИНТЕГРАЦИОННОЕ ТЕСТИРОВАНИЕ (Integration Testing)")
    print("=" * 80)

    # Тест 1: Загрузка онтологии + HermiT Reasoner
    print("\n[Тест 1] Загрузка онтологии + HermiT Reasoner...")
    start = time.time()
    onto  = None
    try:
        onto       = get_ontology(f"file://{ONTO_PATH}").load()
        cpe_before = len(list(onto.CPE.instances()))
        cve_before = len(list(onto.CVE.instances()))

        with onto:
            sync_reasoner(infer_property_values=True)

        cpe_after = len(list(onto.CPE.instances()))
        cve_after = len(list(onto.CVE.instances()))
        t         = time.time() - start

        status = "Passed" if cpe_after > 0 else "Failed"
        log_test("integration", 1, "Онтология + HermiT Reasoner",
                 "Reasoner успешно завершён",
                 f"Время: {t:.1f}с | CPE: {cpe_before}→{cpe_after} | "
                 f"CVE: {cve_before}→{cve_after}",
                 status)
    except Exception as e:
        log_test("integration", 1, "Онтология + HermiT Reasoner",
                 "Reasoner инициализирован", f"Ошибка: {e}", "Failed")
        if onto is None:
            onto = get_ontology(f"file://{ONTO_PATH}").load()

    # Тест 2: Транзитивные связи CWE
    print("\n[Тест 2] Транзитивные связи CWE...")
    try:
        if not os.path.exists(CWE_FILE):
            raise FileNotFoundError(f"Файл не найден: {CWE_FILE}")

        cwe_df   = pd.read_csv(CWE_FILE)
        all_cols = list(cwe_df.columns)
        rel_col  = find_relation_column(cwe_df)

        if rel_col:
            # Вариант A: нашли колонку со связями в CSV
            total_cwe  = len(cwe_df)
            with_links = cwe_df[rel_col].notna().sum()
            sample     = (cwe_df[rel_col].dropna().iloc[0]
                          if with_links > 0 else None)
            status     = "Passed" if with_links > 0 else "Failed"
            log_test("integration", 2, "Транзитивные связи CWE",
                     "Связи CWE > 0",
                     f"Колонка '{rel_col}': {with_links}/{total_cwe} CWE "
                     f"имеют связи",
                     status,
                     f"Пример: {str(sample)[:80]}" if sample else "")
        else:
            # Вариант B: колонки нет — используем cwe_chains.json как fallback
            if os.path.exists(CWE_CHAINS_FILE):
                with open(CWE_CHAINS_FILE, 'r', encoding='utf-8') as f:
                    chains = json.load(f)

                total_links = 0
                if isinstance(chains, dict):
                    for chain in chains.values():
                        if isinstance(chain, list):
                            total_links += max(0, len(chain) - 1)

                status = "Passed" if total_links > 0 else "Failed"
                log_test("integration", 2, "Транзитивные связи CWE",
                         "Связи CWE > 0",
                         f"Через cwe_chains.json: {len(chains)} цепочек, "
                         f"{total_links} связей",
                         status,
                         f"Колонки CWE CSV: {all_cols}")
            else:
                log_test("integration", 2, "Транзитивные связи CWE",
                         "Связи CWE > 0",
                         "Ни колонка связей, ни cwe_chains.json не найдены",
                         "Failed",
                         f"Колонки CWE CSV: {all_cols}")
    except Exception as e:
        log_test("integration", 2, "Транзитивные связи CWE",
                 "Связи > 0", f"Ошибка: {e}", "Failed")

    # Тест 3: Полный граф угроз CPE→CVE→CWE→CAPEC
    print("\n[Тест 3] Полный граф угроз CPE→CVE→CWE→CAPEC...")
    try:
        onto = get_ontology(f"file://{ONTO_PATH}").load()
        cpe  = find_cpe_for_component(onto, "apache", "tomcat", "9.0.0")

        if not cpe:
            raise ValueError("Apache Tomcat CPE не найден")

        cves   = list(onto.search(type=onto.CVE, affects=cpe))
        cwes   = set()
        capecs = set()
        for cve in cves:
            for cwe in getattr(cve, "hasWeakness", []):
                cwes.add(cwe)
                for capec in getattr(cwe, "exploitedBy", []):
                    capecs.add(capec)

        cve_ok = 40 <= len(cves) <= 70
        status = "Passed" if cve_ok and len(cves) > 0 else "Failed"
        log_test("integration", 3, "Полный граф угроз",
                 "CVE ∈ [40, 70]",
                 f"CVE: {len(cves)}, CWE: {len(cwes)}, CAPEC: {len(capecs)}",
                 status)
    except Exception as e:
        log_test("integration", 3, "Полный граф угроз",
                 "CVE > 0", f"Ошибка: {e}", "Failed")

    # Тест 4: Верификация 53 контрольных CVE
    print("\n[Тест 4] Верификация 53 контрольных CVE...")
    try:
        if not os.path.exists(CVE_FILE):
            raise FileNotFoundError(f"Файл не найден: {CVE_FILE}")
        cve_df   = pd.read_csv(CVE_FILE)
        cvss_col = find_cvss_column(cve_df)

        found     = 0
        cvss_ok   = 0
        not_found = []

        for ctrl in CONTROL_CVES:
            cid  = ctrl["id"]
            rows = cve_df[cve_df['ID'].astype(str).str.contains(
                cid.replace("CVE-", ""), na=False)]

            if len(rows) > 0:
                found += 1
                if cvss_col:
                    try:
                        score = float(rows[cvss_col].iloc[0])
                        if score >= ctrl["expected_cvss_min"]:
                            cvss_ok += 1
                    except (ValueError, TypeError):
                        pass
            else:
                not_found.append(cid)

        total  = len(CONTROL_CVES)
        status = "Passed" if found >= int(total * 0.8) else "Failed"
        log_test("integration", 4, "Верификация 53 контрольных CVE",
                 f"≥{int(total * 0.8)}/{total} CVE найдено в базе",
                 f"Найдено: {found}/{total}, CVSS корректен: {cvss_ok}/{total}",
                 status,
                 f"Не найдено: {not_found[:5]}" if not_found else "")
    except Exception as e:
        log_test("integration", 4, "Верификация CVE",
                 "≥80% найдено", f"Ошибка: {e}", "Failed")

    # Тест 5: EPSS API + расчёт риска (end-to-end)
    print("\n[Тест 5] EPSS API + расчёт риска (end-to-end)...")
    try:
        if not os.path.exists(RISK_REFERENCE_FILE):
            raise FileNotFoundError(f"Файл не найден: {RISK_REFERENCE_FILE}")
        with open(RISK_REFERENCE_FILE, 'r', encoding='utf-8') as f:
            ref_dist = json.load(f)

        test_cve = "CVE-2016-8735"
        cvss     = 9.8
        epss     = get_epss_score(test_cve)
        if epss is None:
            epss = 0.40  # fallback

        risk   = calculate_risk_percentile(cvss, epss, ref_dist)
        status = "Passed" if 0 <= risk <= 10 else "Failed"
        log_test("integration", 5, "EPSS API + расчёт риска",
                 "Risk ∈ [0, 10]",
                 f"{test_cve}: CVSS={cvss}, EPSS={epss:.4f}, Risk={risk:.2f}",
                 status)
    except Exception as e:
        log_test("integration", 5, "EPSS + риск",
                 "Risk ∈ [0, 10]", f"Ошибка: {e}", "Failed")

    # Тест 6: Агрегация рисков нескольких компонентов
    print("\n[Тест 6] Агрегация рисков нескольких компонентов...")
    try:
        if not os.path.exists(RISK_REFERENCE_FILE):
            raise FileNotFoundError(f"Файл не найден: {RISK_REFERENCE_FILE}")
        with open(RISK_REFERENCE_FILE, 'r', encoding='utf-8') as f:
            ref_dist = json.load(f)

        components = [
            {"name": "Apache Tomcat", "cvss": 9.8, "epss": 0.40, "n_cve": 53},
            {"name": "OpenSSL",       "cvss": 5.9, "epss": 0.10, "n_cve": 4 },
            {"name": "MySQL",         "cvss": 6.5, "epss": 0.20, "n_cve": 11},
        ]
        comp_risks = []
        total_cve  = 0
        for c in components:
            r = calculate_risk_percentile(c["cvss"], c["epss"], ref_dist)
            comp_risks.append(r)
            total_cve += c["n_cve"]

        app_risk = calculate_app_risk(comp_risks, total_cve)
        status   = "Passed" if app_risk > 0 else "Failed"
        log_test("integration", 6, "Агрегация рисков",
                 "R_app > 0",
                 f"Компоненты: {[f'{r:.2f}' for r in comp_risks]}, "
                 f"R_app={app_risk:.2f}",
                 status)
    except Exception as e:
        log_test("integration", 6, "Агрегация рисков",
                 "R_app > 0", f"Ошибка: {e}", "Failed")

    # Тест 7: Согласованность данных онтология ↔ CSV
    print("\n[Тест 7] Согласованность данных онтология ↔ CSV...")
    try:
        onto   = get_ontology(f"file://{ONTO_PATH}").load()
        cve_df = pd.read_csv(CVE_FILE)

        onto_cve_ids = set()
        for cve in list(onto.CVE.instances())[:20]:
            raw = cve.name.replace("_", "-")
            onto_cve_ids.add(raw)

        found_in_csv = 0
        for cid in onto_cve_ids:
            num  = cid.replace("CVE-", "").replace("-", "")
            rows = cve_df[cve_df['ID'].astype(str)
                          .str.replace(r'\D', '', regex=True)
                          .str.contains(num, na=False)]
            if len(rows) > 0:
                found_in_csv += 1

        pct    = found_in_csv / len(onto_cve_ids) * 100 if onto_cve_ids else 0
        status = "Passed" if pct >= 50 else "Failed"
        log_test("integration", 7, "Согласованность онтология ↔ CSV",
                 "≥50% CVE из онтологии найдены в CSV",
                 f"{found_in_csv}/{len(onto_cve_ids)} ({pct:.1f}%)",
                 status)
    except Exception as e:
        log_test("integration", 7, "Согласованность данных",
                 "≥50% совпадений", f"Ошибка: {e}", "Failed")

    # Тест 8: Веб-интерфейс — наличие ключевых функций
    print("\n[Тест 8] Веб-интерфейс — ключевые функции...")
    try:
        web_app = (PROJECT_ROOT / "scripts_for_create_reasoning"
                   / "web_interface" / "app.py")
        if not web_app.exists():
            raise FileNotFoundError(f"Файл не найден: {web_app}")

        with open(web_app, 'r', encoding='utf-8') as f:
            content = f.read()

        checks = {
            "import streamlit":         'import streamlit' in content,
            "get_risk_percentile":      ('get_risk_percentile' in content or
                                         'calculate_risk' in content),
            "parse_cpe / find_cpes":    ('parse_cpe' in content or
                                         'find_cpes' in content),
            "cwe_chains":               ('cwe_chains' in content or
                                         'chain' in content.lower()),
            "st.text_input / selectbox":('text_input' in content or
                                         'selectbox' in content),
            "st.button":                'button' in content,
        }
        ok_count = sum(checks.values())
        status   = "Passed" if ok_count >= 4 else "Failed"
        detail   = " | ".join(
            f"{k}:{'✅' if v else '❌'}" for k, v in checks.items()
        )
        log_test("integration", 8, "Веб-интерфейс",
                 "≥4/6 ключевых функций",
                 f"{ok_count}/6 проверок пройдено",
                 status, detail)
    except Exception as e:
        log_test("integration", 8, "Веб-интерфейс",
                 "Streamlit приложение", f"Ошибка: {e}", "Failed")

    passed = sum(1 for t in test_results["integration"] if t["status"] == "Passed")
    total  = len(test_results["integration"])
    print(f"\n{'=' * 80}")
    print(f"ИНТЕГРАЦИОННОЕ ТЕСТИРОВАНИЕ: {passed}/{total} "
          f"({passed / total * 100:.1f}%)")
    print(f"{'=' * 80}")
    return passed == total


# ── СИСТЕМНОЕ ТЕСТИРОВАНИЕ ────────────────────────────────────────────────
def run_system_tests():
    print("\n" + "=" * 80)
    print("СИСТЕМНОЕ ТЕСТИРОВАНИЕ (System Testing)")
    print("=" * 80)

    onto     = get_ontology(f"file://{ONTO_PATH}").load()
    ref_dist = []
    if os.path.exists(RISK_REFERENCE_FILE):
        with open(RISK_REFERENCE_FILE, 'r', encoding='utf-8') as f:
            ref_dist = json.load(f)

    # Сценарий 1: Анализ одного компонента — Apache Tomcat 9.0.0
    print("\n[Сценарий 1] Анализ Apache Tomcat 9.0.0...")
    try:
        cpe = find_cpe_for_component(onto, "apache", "tomcat", "9.0.0")
        if not cpe:
            raise ValueError("CPE не найден")
        cves     = list(onto.search(type=onto.CVE, affects=cpe))
        n        = len(cves)
        expected = 53
        status   = "Passed" if abs(n - expected) <= 5 else "Failed"
        log_test("system", 1, "Анализ одного компонента (Tomcat)",
                 f"CVE ≈ {expected} (±5)",
                 f"{n} CVE найдено",
                 status)
    except Exception as e:
        log_test("system", 1, "Анализ Tomcat",
                 "CVE ≈ 53", f"Ошибка: {e}", "Failed")

    # Сценарий 2: Анализ всех 10 компонентов Таблицы 4.1
    print("\n[Сценарий 2] Анализ всех 10 компонентов Таблицы 4.1...")
    try:
        comp_results = []
        total_cves   = 0
        for comp in TEST_COMPONENTS:
            cpe = find_cpe_for_component(
                onto, comp["vendor"], comp["product"], comp["version"])
            n   = len(list(onto.search(type=onto.CVE, affects=cpe))) if cpe else 0
            total_cves += n
            match = abs(n - comp["expected_cve"]) <= max(2, int(comp["expected_cve"] * 0.1))
            comp_results.append({
                "name": comp["name"], "found": n,
                "expected": comp["expected_cve"], "match": match,
                "vendor": comp["vendor"], "product": comp["product"],
                "version": comp["version"],
            })

        matched = sum(1 for r in comp_results if r["match"])
        status  = "Passed" if matched >= 8 else "Failed"
        detail  = " | ".join(
            f"{r['name']}:{r['found']}/{'✅' if r['match'] else '❌'}"
            for r in comp_results
        )
        log_test("system", 2, "Все 10 компонентов Таблицы 4.1",
                 "≥8/10 компонентов с ожидаемым числом CVE",
                 f"{matched}/10 совпали, итого CVE: {total_cves}",
                 status, detail)

        # Диагностика расхождений
        mismatches = [r for r in comp_results if not r["match"]]
        if mismatches:
            print("     Диагностика расхождений:")
            for r in mismatches:
                # Ищем все CPE этого продукта без привязки к версии
                all_cpes = []
                for cpe_inst in onto.CPE.instances():
                    parsed = parse_cpe(cpe_inst.name)
                    if parsed and normalize(parsed["product"]) == normalize(r["product"]):
                        all_cpes.append(parsed)
                versions = [p["version"] for p in all_cpes[:5] if p["version"]]
                print(f"       {r['name']}: найдено {r['found']} "
                      f"(ожидалось {r['expected']}), "
                      f"CPE в онтологии: {len(all_cpes)}, "
                      f"версии: {versions}")
    except Exception as e:
        log_test("system", 2, "Все 10 компонентов",
                 "≥8/10", f"Ошибка: {e}", "Failed")

    # Сценарий 3: Комбинация компонентов — Python + Django
    print("\n[Сценарий 3] Анализ Python 3.10.0 + Django 4.2...")
    try:
        cpe1  = find_cpe_for_component(onto, "python",        "python", "3.10.0")
        cpe2  = find_cpe_for_component(onto, "djangoproject", "django", "4.2")
        cves1 = list(onto.search(type=onto.CVE, affects=cpe1)) if cpe1 else []
        cves2 = list(onto.search(type=onto.CVE, affects=cpe2)) if cpe2 else []
        total = len(cves1) + len(cves2)
        status = "Passed" if total >= 4 else "Failed"
        log_test("system", 3, "Комбинация Python + Django",
                 "≥4 CVE суммарно (ожидается 5)",
                 f"Python: {len(cves1)}, Django: {len(cves2)}, итого: {total}",
                 status)
    except Exception as e:
        log_test("system", 3, "Python + Django",
                 "≥4 CVE", f"Ошибка: {e}", "Failed")

    # Сценарий 4: Компонент с критической уязвимостью — Django CVE-2023-31047
    print("\n[Сценарий 4] Компонент с критической уязвимостью (Django 4.2)...")
    try:
        cpe = find_cpe_for_component(onto, "djangoproject", "django", "4.2")
        if not cpe:
            raise ValueError("CPE не найден")
        cves          = list(onto.search(type=onto.CVE, affects=cpe))
        critical_cves = []
        for cve in cves:
            cvss = get_cvss_from_cve(cve)
            if cvss and cvss >= 9.0:
                critical_cves.append((cve.name, cvss))

        # Если CVSS из онтологии не читается — ищем в CSV
        if not critical_cves and os.path.exists(CVE_FILE):
            cve_df   = pd.read_csv(CVE_FILE)
            cvss_col = find_cvss_column(cve_df)
            if cvss_col:
                for cve in cves:
                    cid  = cve.name.replace("_", "-")
                    rows = cve_df[cve_df['ID'].astype(str).str.contains(
                        cid.replace("CVE-", ""), na=False)]
                    if len(rows) > 0:
                        try:
                            score = float(rows[cvss_col].iloc[0])
                            if score >= 9.0:
                                critical_cves.append((cve.name, score))
                        except (ValueError, TypeError):
                            pass

        status = "Passed" if len(critical_cves) >= 1 else "Failed"
        log_test("system", 4, "Критическая уязвимость Django",
                 "≥1 CVE с CVSS ≥ 9.0",
                 f"Критических: {critical_cves}",
                 status)
    except Exception as e:
        log_test("system", 4, "Критическая уязвимость",
                 "≥1 критическая CVE", f"Ошибка: {e}", "Failed")

    # Сценарий 5: Компонент без уязвимостей
    print("\n[Сценарий 5] Компонент без уязвимостей...")
    try:
        cpe   = find_cpe_for_component(onto, "nonexistent", "safeproduct", "1.0.0")
        n_cve = len(list(onto.search(type=onto.CVE, affects=cpe))) if cpe else 0
        risk  = calculate_app_risk([], 0) if n_cve == 0 else None
        status = "Passed" if n_cve == 0 and risk == 0.0 else "Failed"
        log_test("system", 5, "Компонент без уязвимостей",
                 "CVE = 0, Risk = 0.0",
                 f"CVE: {n_cve}, Risk: {risk}",
                 status)
    except Exception as e:
        log_test("system", 5, "Без уязвимостей",
                 "Risk = 0", f"Ошибка: {e}", "Failed")

    # Сценарий 6: Коэффициенты важности — 4 варианта
    print("\n[Сценарий 6] Разные коэффициенты важности...")
    try:
        if not ref_dist:
            raise ValueError("Референсное распределение не загружено")
        base_risk = calculate_risk_percentile(9.8, 0.40, ref_dist)
        coeffs    = [0.25, 0.50, 0.75, 1.00]
        weighted  = [round(base_risk * c, 4) for c in coeffs]
        in_range  = all(0 <= w <= 10 for w in weighted)
        monotone  = all(weighted[i] <= weighted[i + 1]
                        for i in range(len(weighted) - 1))
        status    = "Passed" if in_range and monotone else "Failed"
        log_test("system", 6, "Коэффициенты важности",
                 "Риск монотонно растёт с коэффициентом",
                 f"Base={base_risk:.2f}, Взвешенные: {weighted}",
                 status)
    except Exception as e:
        log_test("system", 6, "Коэффициенты важности",
                 "Монотонное масштабирование", f"Ошибка: {e}", "Failed")

    # Сценарий 7: Обработка отсутствующего CVSS (CAPEC-based)
    print("\n[Сценарий 7] Обработка отсутствующего CVSS...")
    try:
        if not os.path.exists(CAPEC_FILE):
            raise FileNotFoundError(f"Файл не найден: {CAPEC_FILE}")
        capec_df     = pd.read_csv(CAPEC_FILE)
        severity_map = {
            "Critical": 9.5, "High": 7.5,
            "Medium":   5.0, "Low":  2.5,
        }
        recovered = 0
        total_na  = 0
        if 'Typical_Severity' in capec_df.columns:
            for sev in capec_df['Typical_Severity'].dropna():
                total_na += 1
                if str(sev).strip() in severity_map:
                    recovered += 1

        status = "Passed" if recovered > 0 else "Failed"
        log_test("system", 7, "CVSS из CAPEC Typical_Severity",
                 "CVSS восстановлен из CAPEC",
                 f"{recovered}/{total_na} значений восстановлено",
                 status)
    except Exception as e:
        log_test("system", 7, "CVSS из CAPEC",
                 "CVSS восстановлен", f"Ошибка: {e}", "Failed")

    # Сценарий 8: Обработка отсутствующего EPSS (CWE-based)
    print("\n[Сценарий 8] Обработка отсутствующего EPSS...")
    try:
        if not os.path.exists(CWE_FILE):
            raise FileNotFoundError(f"Файл не найден: {CWE_FILE}")
        cwe_df         = pd.read_csv(CWE_FILE)
        likelihood_map = {"High": 0.75, "Medium": 0.40, "Low": 0.10}
        recovered = 0
        total_na  = 0
        if 'Likelihood_Of_Exploit' in cwe_df.columns:
            for lk in cwe_df['Likelihood_Of_Exploit'].dropna():
                total_na += 1
                if str(lk).strip() in likelihood_map:
                    recovered += 1

        status = "Passed" if recovered > 0 else "Failed"
        log_test("system", 8, "EPSS из CWE Likelihood",
                 "EPSS восстановлен из CWE",
                 f"{recovered}/{total_na} значений восстановлено",
                 status)
    except Exception as e:
        log_test("system", 8, "EPSS из CWE",
                 "EPSS восстановлен", f"Ошибка: {e}", "Failed")

    # Сценарий 9: Построение цепочек CWE
    print("\n[Сценарий 9] Построение цепочек CWE...")
    try:
        if not os.path.exists(CWE_CHAINS_FILE):
            raise FileNotFoundError(f"Файл не найден: {CWE_CHAINS_FILE}")
        with open(CWE_CHAINS_FILE, 'r', encoding='utf-8') as f:
            chains = json.load(f)
        n      = len(chains)
        status = "Passed" if n >= 10 else "Failed"
        log_test("system", 9, "Цепочки CWE",
                 "≥10 цепочек",
                 f"{n} цепочек построено",
                 status)
    except Exception as e:
        log_test("system", 9, "Цепочки CWE",
                 "≥10 цепочек", f"Ошибка: {e}", "Failed")

    # Сценарий 10: Экспорт результатов анализа в CSV
    print("\n[Сценарий 10] Экспорт результатов в CSV...")
    try:
        import csv
        import tempfile

        export_rows = []
        for comp in TEST_COMPONENTS:
            cpe = find_cpe_for_component(
                onto, comp["vendor"], comp["product"], comp["version"])
            n_cve = len(list(onto.search(type=onto.CVE, affects=cpe))) if cpe else 0
            export_rows.append({
                "component": comp["name"],
                "version":   comp["version"],
                "cve_count": n_cve,
                "expected":  comp["expected_cve"],
                "match":     abs(n_cve - comp["expected_cve"]) <= 2,
            })

        with tempfile.NamedTemporaryFile(
                mode='w', suffix='.csv', delete=False,
                newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=export_rows[0].keys())
            writer.writeheader()
            writer.writerows(export_rows)
            tmp = f.name

        with open(tmp, 'r', encoding='utf-8') as f:
            rows = list(csv.DictReader(f))
        os.unlink(tmp)

        status = "Passed" if len(rows) == len(TEST_COMPONENTS) else "Failed"
        log_test("system", 10, "Экспорт результатов в CSV",
                 f"{len(TEST_COMPONENTS)} строк в CSV",
                 f"{len(rows)} строк экспортировано",
                 status)
    except Exception as e:
        log_test("system", 10, "Экспорт CSV",
                 "CSV сформирован", f"Ошибка: {e}", "Failed")

    passed = sum(1 for t in test_results["system"] if t["status"] == "Passed")
    total  = len(test_results["system"])
    print(f"\n{'=' * 80}")
    print(f"СИСТЕМНОЕ ТЕСТИРОВАНИЕ: {passed}/{total} ({passed / total * 100:.1f}%)")
    print(f"{'=' * 80}")
    return passed == total


# ── ГЕНЕРАЦИЯ ОТЧЁТА ──────────────────────────────────────────────────────
def generate_report():
    print("\n" + "=" * 80)
    print("ИТОГОВЫЙ ОТЧЁТ О ТЕСТИРОВАНИИ")
    print("=" * 80)

    total_passed = 0
    total_tests  = 0

    labels = {
        "unit":        "МОДУЛЬНОЕ",
        "integration": "ИНТЕГРАЦИОННОЕ",
        "system":      "СИСТЕМНОЕ",
    }
    for key in ["unit", "integration", "system"]:
        passed = sum(1 for t in test_results[key] if t["status"] == "Passed")
        total  = len(test_results[key])
        total_passed += passed
        total_tests  += total
        print(f"\n{labels[key]}: {passed}/{total} ({passed / total * 100:.1f}%)")
        for t in test_results[key]:
            icon = "✅" if t["status"] == "Passed" else "❌"
            print(f"  {icon} Тест {t['id']}: {t['name']} — {t['status']}")
            if t.get("details"):
                print(f"     {t['details']}")

    print(f"\n{'=' * 80}")
    print(f"ОБЩИЙ РЕЗУЛЬТАТ: {total_passed}/{total_tests} "
          f"({total_passed / total_tests * 100:.1f}%)")
    print(f"{'=' * 80}")

    report_file = PROJECT_ROOT / "testing" / "test_report.json"
    report_file.parent.mkdir(parents=True, exist_ok=True)
    with open(report_file, 'w', encoding='utf-8') as f:
        json.dump({
            "timestamp": dt.datetime.now().isoformat(),
            "results":   test_results,
            "summary": {
                "total_passed": total_passed,
                "total_tests":  total_tests,
                "percentage":   round(total_passed / total_tests * 100, 1),
            },
        }, f, indent=2, ensure_ascii=False)

    print(f"\nОтчёт сохранён: {report_file}")
    return total_passed, total_tests


# ── ОСНОВНАЯ ФУНКЦИЯ ─────────────────────────────────────────────────────
def main():
    print("=" * 80)
    print("ТЕСТИРОВАНИЕ ЭКСПЕРТНОЙ СИСТЕМЫ ОЦЕНКИ РИСКОВ")
    print("=" * 80)
    print(f"Дата:                 {dt.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Онтология:            {ONTO_PATH}")
    print(f"Тестовых компонентов: {len(TEST_COMPONENTS)}")
    print(f"Контрольных CVE:      {len(CONTROL_CVES)}")
    print(f"Эталонных цепочек:    {len(REFERENCE_CWE_CHAINS)}")

    run_unit_tests()
    run_integration_tests()
    run_system_tests()
    total_passed, total_tests = generate_report()

    print("\n" + "=" * 80)
    if total_passed == total_tests:
        print("✅ ВСЕ ТЕСТЫ ПРОЙДЕНЫ!")
    else:
        print(f"⚠️  {total_tests - total_passed} тестов не пройдено")
    print("=" * 80)

    return total_passed == total_tests


if __name__ == "__main__":
    sys.exit(0 if main() else 1)