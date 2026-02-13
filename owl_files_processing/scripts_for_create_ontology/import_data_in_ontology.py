import pandas as pd
from owlready2 import *
from tqdm import tqdm

ONTO_IRII = os.getenv("ONTO_IRII")
ONTO_OUTPUT = os.getenv("ONTO_OUTPUT")
CVE_PROCESSING_OUTPUT = os.getenv("CVE_PROCESSING_OUTPUT")
CWE_OUTPUT_CSV = os.getenv("CWE_OUTPUT_CSV")
CAPEC_OUTPUT = os.getenv("CAPEC_OUTPUT")

onto = get_ontology(ONTO_OUTPUT).load()

entity_cache = {}

def normalize(name):
    return name.replace(":", "_").replace(".", "_").replace("-", "_")

def get_or_create(cls, name):
    name = normalize(name)

    if name in entity_cache:
        return entity_cache[name]

    instance = cls(name)
    entity_cache[name] = instance
    return instance

with onto:
    cve_df = pd.read_csv(CVE_PROCESSING_OUTPUT)

    used_cpe = set()

    for cpe_string in cve_df["MatchingCPE"].dropna():
        for cpe in str(cpe_string).split(";"):
            clean = cpe.strip()
            if clean:
                used_cpe.add(clean)

    print(f"Найдено уникальных CPE: {len(used_cpe)}")

    for cpe in tqdm(used_cpe):
        get_or_create(onto.CPE, cpe)

    cwe_df = pd.read_csv(CWE_OUTPUT_CSV)

    for _, row in tqdm(cwe_df.iterrows(), total=len(cwe_df)):
        get_or_create(onto.CWE, str(row["ID"]))

    capec_df = pd.read_csv(CAPEC_OUTPUT)

    for _, row in tqdm(capec_df.iterrows(), total=len(capec_df)):
        get_or_create(onto.CAPEC, str(row["ID"]))

    for _, row in tqdm(cve_df.iterrows(), total=len(cve_df)):

        cve_id = str(row["ID"])
        cve = get_or_create(onto.CVE, cve_id)

        if not pd.isna(row["baseScore"]):
            cve.hasCVSSScore = [float(row["baseScore"])] 

        if not pd.isna(row["baseSeverity"]):
            cve.hasSeverity = [str(row["baseSeverity"])]  

        if not pd.isna(row["description"]):
            cve.hasDescription = [str(row["description"])] 

        # CVE → CPE
        for cpe_id in str(row["MatchingCPE"]).split(";"):
            clean = cpe_id.strip()
            if clean:
                cve.affects.append(get_or_create(onto.CPE, clean))  

        # CVE → CWE
        for cwe_id in str(row["MatchingCWE"]).split(";"):
            clean = cwe_id.strip()
            if clean:
                cve.hasWeakness.append(get_or_create(onto.CWE, clean))  

    for _, row in tqdm(capec_df.iterrows(), total=len(capec_df)):

        capec_instance = get_or_create(onto.CAPEC, str(row["ID"]))

        related = str(row.get("Related_CWE", "")).split(";")

        for cwe_id in related:
            clean = cwe_id.strip()
            if clean:
                cwe_instance = get_or_create(onto.CWE, clean)
                cwe_instance.exploitedBy.append(capec_instance)  

onto.save(file=ONTO_IRII, format="rdfxml")