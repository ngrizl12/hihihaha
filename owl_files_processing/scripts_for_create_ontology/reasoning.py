from owlready2 import *
import os
import re
import math
import pandas as pd
from dotenv import load_dotenv
from deep_translator import GoogleTranslator

load_dotenv(".local.env")

ONTO_PATH = os.getenv("ONTO_PATH")
CWE_CSV_PATH = os.getenv("CWE_OUTPUT_CSV")
CAPEC_CSV_PATH = os.getenv("CAPEC_OUTPUT")

try:
    translator = GoogleTranslator(source='en', target='ru')
    print("Переводчик инициализирован")
except Exception as e:
    print(f"Ошибка инициализации переводчика: {e}")
    translator = None

translation_cache = {}

def translate_text(text, max_length=500):
    if not text or not translator:
        return text
    
    if text in translation_cache:
        return translation_cache[text]
    
    try:
        if len(text) > max_length:
            text_short = text[:max_length] + "..."
            translated = translator.translate(text_short)
        else:
            translated = translator.translate(text)
        
        translation_cache[text] = translated
        return translated
    except Exception as e:
        print(f"  Ошибка перевода: {e}")
        return text

print("Загрузка данных CWE...")
cwe_df = pd.read_csv(CWE_CSV_PATH)
cwe_dict = {}
for _, row in cwe_df.iterrows():
    cwe_id = str(row['ID']).strip()
    cwe_dict[cwe_id] = {
        'name': row['Name'] if pd.notna(row['Name']) else cwe_id,
        'likelihood': row['Likelihood_Of_Exploit'] if pd.notna(row['Likelihood_Of_Exploit']) else None
    }
print(f"Загружено {len(cwe_dict)} записей CWE")

print("Загрузка данных CAPEC...")
capec_df = pd.read_csv(CAPEC_CSV_PATH)
capec_dict = {}
for _, row in capec_df.iterrows():
    capec_id = str(row['ID']).strip()
    capec_dict[capec_id] = {
        'name': row['Name'] if pd.notna(row['Name']) else capec_id,
        'description': row['Description'] if pd.notna(row['Description']) else "Описание отсутствует",
        'likelihood': row['Likelihood_Of_Attack'] if pd.notna(row['Likelihood_Of_Attack']) else None
    }
print(f"Загружено {len(capec_dict)} записей CAPEC")

def normalize(text):
    if not text or text in ["*", "-", "na", ""]:
        return None
    return str(text).lower().replace(":", "").replace(".", "").replace("-", "").replace("_", "").strip()

def parse_cpe(cpe_name):
    if not cpe_name or not isinstance(cpe_name, str) or not cpe_name.startswith("cpe_2_3_"):
        return None
    
    parts = cpe_name.split("_")
    
    if len(parts) < 14:
        return None
        
    return {
        "part": parts[3],
        "vendor": parts[4],
        "product": parts[5],
        "version": parts[6] if parts[6] not in ["", "*"] else None,
        "update": parts[7] if parts[7] not in ["", "*"] else None,
        "edition": parts[8] if parts[8] not in ["", "*"] else None,
        "language": parts[9] if parts[9] not in ["", "*"] else None,
        "sw_edition": parts[10] if len(parts) > 10 and parts[10] not in ["", "*"] else None,
        "target_sw": parts[11] if len(parts) > 11 and parts[11] not in ["", "*"] else None,
        "target_hw": parts[12] if len(parts) > 12 and parts[12] not in ["", "*"] else None,
        "other": parts[13] if len(parts) > 13 and parts[13] not in ["", "*"] else None
    }

def extract_version(parsed):
    version_parts = []
    
    if parsed.get("version") and parsed["version"] not in ["*", "-", ""]:
        version_parts.append(parsed["version"])
    
    if parsed.get("update") and parsed["update"] not in ["*", "-", ""]:
        version_parts.append(parsed["update"])
    
    if parsed.get("edition") and parsed["edition"] not in ["*", "-", ""]:
        if re.search(r'^\d+$', parsed["edition"]) or re.search(r'\.', parsed["edition"]):
            version_parts.append(parsed["edition"])
    
    if parsed.get("sw_edition") and parsed["sw_edition"] not in ["*", "-", ""]:
        if re.search(r'\d', parsed["sw_edition"]):
            version_parts.append(parsed["sw_edition"])
    
    if version_parts:
        full_version = ".".join(version_parts)
        if re.search(r'\d', full_version):
            return full_version
    
    return None

def find_cpes_for_component(product_name, version_name=None):
    all_cpe = list(onto.CPE.instances())
    product_matches = []
    target_sw_matches = []
    
    for cpe in all_cpe:
        parsed = parse_cpe(cpe.name)
        if not parsed:
            continue
        
        product = normalize(parsed.get("product"))
        version = extract_version(parsed)
        target_sw = normalize(parsed.get("target_sw"))
        
        if product and product == product_name:
            product_matches.append({"cpe": cpe, "parsed": parsed, "version": version})
        
        if target_sw and target_sw == product_name:
            target_sw_matches.append({"cpe": cpe, "parsed": parsed, "version": version})
    
    if version_name:
        exact_matches = [m["cpe"] for m in product_matches if m["version"] and version_name in m["version"]]
        if exact_matches:
            print(f"  Найдено точное совпадение: {len(exact_matches)} CPE")
            return exact_matches
        else:
            print(f"  Версия '{version_name}' не найдена")
            return []
    
    elif product_matches:
        versions_dict = {}
        for match in product_matches:
            ver = match["version"]
            if ver not in versions_dict:
                versions_dict[ver] = []
            versions_dict[ver].append(match["cpe"])
        
        versions = sorted([v for v in versions_dict.keys() if v is not None])
        
        if not versions:
            print("  Нет версий с цифрами, беру все CPE")
            return [m["cpe"] for m in product_matches]
        elif len(versions) == 1:
            print(f"  Найдена единственная версия: {versions[0]}")
            return versions_dict[versions[0]]
        else:
            print("\n  Доступные версии:")
            for i, ver in enumerate(versions[:20]):
                count = len(versions_dict[ver])
                print(f"    {i}: {ver} ({count} CPE)")
            
            choice = int(input("  Выберите номер версии: "))
            chosen_version = versions[choice]
            print(f"  Выбрана версия: {chosen_version}")
            return versions_dict[chosen_version]
    
    elif target_sw_matches:
        print(f"  Найдено совпадение по target_sw: {len(target_sw_matches)} CPE")
        return [m["cpe"] for m in target_sw_matches]
    
    return []

def classify_cvss(score):
    if score >= 9.0:
        return "Критический"
    elif score >= 7.0:
        return "Высокий"
    elif score >= 4.0:
        return "Средний"
    else:
        return "Низкий"

def classify_risk(score):
    if score >= 8.0:
        return "Критический"
    elif score >= 6.0:
        return "Высокий"
    elif score >= 4.0:
        return "Средний"
    else:
        return "Низкий"

def extract_cwe_id(cwe_obj):
    cwe_str = str(cwe_obj)
    match = re.search(r'CWE[_-]?(\d+)', cwe_str, re.IGNORECASE)
    if match:
        return f"CWE-{match.group(1)}"
    return cwe_str

def extract_capec_id(capec_obj):
    capec_str = str(capec_obj)
    match = re.search(r'CAPEC[_-]?(\d+)', capec_str, re.IGNORECASE)
    if match:
        return f"CAPEC-{match.group(1)}"
    return capec_str

def get_cwe_info(cwe_obj):
    cwe_id = extract_cwe_id(cwe_obj)
    
    if cwe_id in cwe_dict:
        return {
            'id': cwe_id,
            'name': cwe_dict[cwe_id]['name'],
            'likelihood': cwe_dict[cwe_id]['likelihood']
        }
    else:
        return {
            'id': cwe_id,
            'name': cwe_id,
            'likelihood': None
        }

def get_capec_info(capec_obj):
    capec_id = extract_capec_id(capec_obj)
    
    if capec_id in capec_dict:
        return {
            'id': capec_id,
            'name': capec_dict[capec_id]['name'],
            'description': capec_dict[capec_id]['description'],
            'likelihood': capec_dict[capec_id]['likelihood']
        }
    else:
        return {
            'id': capec_id,
            'name': capec_id,
            'description': "Описание отсутствует",
            'likelihood': None
        }

def translate_likelihood(likelihood):
    if not likelihood:
        return None
    
    likelihood_map = {
        'very high': 'Очень высокая',
        'high': 'Высокая',
        'medium': 'Средняя',
        'low': 'Низкая',
        'very low': 'Очень низкая',
        'not specified': None
    }
    
    likelihood_lower = likelihood.lower()
    return likelihood_map.get(likelihood_lower, likelihood)

def display_capecs(capec_list, start_idx=0, page_size=10):
    total = len(capec_list)
    end_idx = min(start_idx + page_size, total)
    
    for i in range(start_idx, end_idx):
        capec = capec_list[i]
        
        name_ru = translate_text(capec['name'])
        print(f"\n    {i+1}. {name_ru} ({capec['id']})")
        
        if capec['likelihood'] and capec['likelihood'].lower() != "not specified":
            likelihood_ru = translate_likelihood(capec['likelihood']) or capec['likelihood']
            print(f"       Вероятность атаки: {likelihood_ru}")
        
        if capec['description'] and capec['description'] != "Описание отсутствует":
            desc_ru = translate_text(capec['description'])
            desc_short = desc_ru[:200] + "..." if len(desc_ru) > 200 else desc_ru
            print(f"       Описание: {desc_short}")
    
    return end_idx

onto = get_ontology(f"file://{os.path.abspath(ONTO_PATH)}").load()

print("Количество CVE:", len(list(onto.CVE.instances())))
print("Количество CPE:", len(list(onto.CPE.instances())))

user_input = input("\nВведите компоненты через запятую (например 'python 3.9, java 8, node.js'): ")
components = [c.strip() for c in user_input.split(",")]

all_components_data = []
all_app_risk_scores = []

for component in components:
    print("\n" + "="*60)
    print(f"АНАЛИЗ КОМПОНЕНТА: {component}")
    print("="*60)
    
    tokens = component.strip().split()
    product_input = normalize(tokens[0])
    version_input = tokens[1] if len(tokens) > 1 else None
    
    print(f"Поиск CPE для продукта='{product_input}'...")
    
    selected_cpes = find_cpes_for_component(product_input, version_input)
    
    if not selected_cpes:
        print("  CPE не найдено, пропускаем компонент")
        continue
    
    all_cves = []
    for cpe in selected_cpes:
        cves = list(onto.search(type=onto.CVE, affects=cpe))
        all_cves.extend(cves)
    
    unique_cves = list(set(all_cves))
    
    if not unique_cves:
        print("  Уязвимости не найдены")
        all_components_data.append({
            "name": component,
            "cves_count": 0,
            "cvss_scores": [],
            "risk_score": 0,
            "cwe_list": [],
            "capec_list": []
        })
        continue
    
    print(f"\n  Найдено уязвимостей: {len(unique_cves)}")
    
    cvss_scores = []
    cwe_set = set()
    capec_set = set()
    
    for cve in unique_cves:
        if hasattr(cve, "hasCVSSScore") and cve.hasCVSSScore:
            try:
                score = float(cve.hasCVSSScore[0])
                cvss_scores.append(score)
                print(f"    CVE: {cve.name} | CVSS: {score}")
            except:
                print(f"    CVE: {cve.name} | CVSS: N/A")
        else:
            print(f"    CVE: {cve.name} | CVSS: N/A")
        
        if hasattr(cve, "hasWeakness"):
            for cwe in cve.hasWeakness:
                cwe_set.add(cwe)
                if hasattr(cwe, "exploitedBy"):
                    for capec in cwe.exploitedBy:
                        capec_set.add(capec)
    
    risk_score = 0
    if cvss_scores:
        max_cvss = max(cvss_scores)
        avg_cvss = sum(cvss_scores) / len(cvss_scores)
        cve_count = len(unique_cves)
        
        risk_score = (
            max_cvss * 0.6 +
            avg_cvss * 0.3 +
            math.log10(cve_count + 1) * 0.1
        )
        
        all_app_risk_scores.append(risk_score)
    
    cwe_list = []
    for cwe in cwe_set:
        cwe_info = get_cwe_info(cwe)
        if cwe_info['likelihood'] and cwe_info['likelihood'].lower() != "not specified":
            cwe_info['name_ru'] = translate_text(cwe_info['name'])
            cwe_info['likelihood_ru'] = translate_likelihood(cwe_info['likelihood']) or cwe_info['likelihood']
            cwe_list.append(cwe_info)
    
    capec_list = []
    for capec in capec_set:
        capec_list.append(get_capec_info(capec))
    
    capec_list.sort(key=lambda x: 
        0 if not x['likelihood'] or x['likelihood'].lower() == "not specified"
        else (1 if x['likelihood'].lower() == "low" 
        else (2 if x['likelihood'].lower() == "medium"
        else (3 if x['likelihood'].lower() == "high"
        else (4 if x['likelihood'].lower() == "very high" else 0)))), 
        reverse=True)
    
    all_components_data.append({
        "name": component,
        "cves_count": len(unique_cves),
        "cvss_scores": cvss_scores,
        "risk_score": risk_score,
        "max_cvss": max(cvss_scores) if cvss_scores else 0,
        "avg_cvss": sum(cvss_scores)/len(cvss_scores) if cvss_scores else 0,
        "cwe_list": cwe_list,
        "capec_list": capec_list
    })

print("\n" + "="*70)
print("ИТОГОВЫЙ ОТЧЁТ ПО БЕЗОПАСНОСТИ ПРИЛОЖЕНИЯ")
print("="*70)

if not all_components_data:
    print("Нет данных для анализа")
    exit()

all_risk_scores = [d["risk_score"] for d in all_components_data if d["cvss_scores"]]
all_cves_total = sum(d["cves_count"] for d in all_components_data)
all_cwe_items = []
all_capec_items = []

for d in all_components_data:
    all_cwe_items.extend(d["cwe_list"])
    all_capec_items.extend(d["capec_list"])

unique_cwe_ids = set()
unique_capec_ids = set()
for cwe in all_cwe_items:
    unique_cwe_ids.add(cwe["id"])
for capec in all_capec_items:
    unique_capec_ids.add(capec["id"])

if all_risk_scores:
    max_risk = max(all_risk_scores)
    avg_risk = sum(all_risk_scores) / len(all_risk_scores)
    app_risk_score = max_risk * 0.5 + avg_risk * 0.5
    
    print(f"\nКомпонентов проанализировано: {len(all_components_data)}")
    print(f"Всего найдено уязвимостей: {all_cves_total}")
    print(f"Уникальных CWE (с вероятностью): {len(unique_cwe_ids)}")
    print(f"Уникальных CAPEC: {len(unique_capec_ids)}")
    
    print(f"\nОЦЕНКА РИСКА ПРИЛОЖЕНИЯ: {app_risk_score:.2f}")
    print(f"УРОВЕНЬ РИСКА: {classify_risk(app_risk_score)}")
    
    if app_risk_score >= 8:
        print("\nКРИТИЧЕСКИЙ РИСК: Требуется немедленное внимание!")
    elif app_risk_score >= 6:
        print("\nВЫСОКИЙ РИСК: Рекомендуется приоритетное исправление")
    elif app_risk_score >= 4:
        print("\nСРЕДНИЙ РИСК: Плановое исправление")
    else:
        print("\nНИЗКИЙ РИСК: Приложение в безопасности")
else:
    print("Нет оценок CVSS для расчета риска")

print("\n" + "="*70)
print("ОБЩИЙ РИСК ПО ВСЕМ ПРОАНАЛИЗИРОВАННЫМ ПРИЛОЖЕНИЯМ")
print("="*70)

if all_app_risk_scores:
    overall_max_risk = max(all_app_risk_scores)
    overall_avg_risk = sum(all_app_risk_scores) / len(all_app_risk_scores)
    overall_risk_score = overall_max_risk * 0.5 + overall_avg_risk * 0.5
    
    print(f"\nВсего проанализировано компонентов/приложений: {len(all_app_risk_scores)}")
    print(f"Максимальный риск: {overall_max_risk:.2f}")
    print(f"Средний риск: {overall_avg_risk:.2f}")
    print(f"\nОБЩАЯ ОЦЕНКА РИСКА: {overall_risk_score:.2f}")
    print(f"ОБЩИЙ УРОВЕНЬ РИСКА: {classify_risk(overall_risk_score)}")
    
    if overall_risk_score >= 8:
        print("\nОБЩИЙ КРИТИЧЕСКИЙ РИСК: Требуются немедленные действия по всем приложениям!")
    elif overall_risk_score >= 6:
        print("\nОБЩИЙ ВЫСОКИЙ РИСК: Приоритетное исправление необходимо для всех приложений")
    elif overall_risk_score >= 4:
        print("\nОБЩИЙ СРЕДНИЙ РИСК: Плановое исправление для всех приложений")
    else:
        print("\nОБЩИЙ НИЗКИЙ РИСК: Приложения в целом безопасны")
else:
    print("Нет данных о рисках приложений")

print("\n" + "="*70)
print("ДЕТАЛЬНЫЙ ОТЧЁТ ПО КОМПОНЕНТАМ")
print("="*70)

for i, comp in enumerate(all_components_data):
    print(f"\n--- Компонент {i+1}: {comp['name']} ---")
    print(f"  Уязвимостей: {comp['cves_count']}")
    
    if comp['cvss_scores']:
        print(f"  Max CVSS: {comp['max_cvss']:.1f} ({classify_cvss(comp['max_cvss'])})")
        print(f"  Avg CVSS: {comp['avg_cvss']:.1f}")
        print(f"  Риск компонента: {comp['risk_score']:.2f} ({classify_risk(comp['risk_score'])})")
    
    if comp['cwe_list']:
        print(f"\n  CWE ({len(comp['cwe_list'])}):")
        for cwe in comp['cwe_list'][:5]:
            print(f"    • {cwe['name_ru']}")
            print(f"      Вероятность эксплуатации: {cwe['likelihood_ru']}")
    
    if comp['capec_list']:
        print(f"\n  CAPEC ({len(comp['capec_list'])}):")
        displayed = display_capecs(comp['capec_list'], 0, min(10, len(comp['capec_list'])))
        
        while displayed < len(comp['capec_list']):
            show_more = input(f"\n  Показать следующие 10 CAPEC? (д/н): ").lower()
            if show_more in ['д', 'y', 'yes', 'да']:
                displayed = display_capecs(comp['capec_list'], displayed, 10)
            else:
                break

print("\n" + "="*70)
print("АНАЛИЗ ЗАВЕРШЕН")
print("="*70)
