import xml.etree.ElementTree as ET
from xml.etree.ElementTree import tostring
import pandas as pd
import re
import os
from dotenv import load_dotenv

load_dotenv(".local.env")

CAPEC_XML = os.getenv("CAPEC_XML")
CAPEC_OUTPUT = os.getenv("CAPEC_OUTPUT")

tree = ET.parse(CAPEC_XML)
root = tree.getroot()

ns = {"capec": "http://capec.mitre.org/capec-3"}

cols = [
    "ID",
    "Name",
    "Description",
    "Abstraction",
    "Likelihood_Of_Attack",
    "Typical_Severity",
    "Related_CWE"
]

rows = []

for attack in root.findall(".//capec:Attack_Pattern", ns):

    if attack.attrib.get("Status") == "Deprecated":
        continue

    capec_id = "CAPEC-" + attack.attrib.get("ID")
    name = attack.attrib.get("Name")
    abstraction = attack.attrib.get("Abstraction")

    description = ""
    desc_elem = attack.find("capec:Description", ns)
    if desc_elem is not None:
        description = tostring(desc_elem, method="text").decode("utf-8")
        description = description.replace("\n", " ").replace("\t", " ")
        description = re.sub(" +", " ", description)

    likelihood = ""
    likelihood_elem = attack.find("capec:Likelihood_Of_Attack", ns)
    if likelihood_elem is not None:
        likelihood = likelihood_elem.text

    severity = ""
    severity_elem = attack.find("capec:Typical_Severity", ns)
    if severity_elem is not None:
        severity = severity_elem.text

    related_cwe = []
    for rel in attack.findall(".//capec:Related_Weakness", ns):
        cwe_id = rel.attrib.get("CWE_ID")
        if cwe_id:
            related_cwe.append("CWE-" + cwe_id)

    related_cwe_str = ";".join(related_cwe)

    rows.append({
        "ID": capec_id,
        "Name": name,
        "Description": description,
        "Abstraction": abstraction,
        "Likelihood_Of_Attack": likelihood,
        "Typical_Severity": severity,
        "Related_CWE": related_cwe_str
    })

df = pd.DataFrame(rows, columns=cols)
df.to_csv(CAPEC_OUTPUT, index=False, encoding="utf-8-sig")

print(f"CAPEC rows: {len(df)}")