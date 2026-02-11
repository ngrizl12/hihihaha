import xml.etree.ElementTree as ET
from xml.etree.ElementTree import tostring
import pandas as pd
import re
import os
from dotenv import load_dotenv

load_dotenv(".local.env")

INPUT_XML = os.getenv("CWE_XML_INPUT")
OUTPUT_CSV = os.getenv("CWE_OUTPUT_CSV")

tree = ET.parse(INPUT_XML)
root = tree.getroot()

namespace = root.tag.split("}")[0].strip("{")
NS = f"{{{namespace}}}"

cols = [
    "ID","Name","Description","Extended_Description",
    "Related_Weakness","Language","Technology",
    "Likelihood_Of_Exploit","Consequence","CVE_Example"
]

rows = []

for item in root.iter(NS + "Weakness"):

    if 'DEPRECATED' in item.attrib.get('Name', ''):
        continue

    cweid = "CWE-" + item.attrib.get("ID", "")
    name = item.attrib.get("Name", "")

    description = ""
    desc_elem = item.find(NS + "Description")
    if desc_elem is not None and desc_elem.text:
        description = re.sub(r"\s+", " ", desc_elem.text.strip())

    extended = ""
    ext_elem = item.find(NS + "Extended_Description")
    if ext_elem is not None:
        extended = tostring(ext_elem, method="text").decode("utf-8")
        extended = re.sub(r"\s+", " ", extended.strip())

    related = []
    for i in item.iter(NS + "Related_Weakness"):
        related.append(
            f"{i.attrib.get('Nature','')}:{i.attrib.get('CWE_ID','')}"
        )

    language = []
    for i in item.iter(NS + "Language"):
        if "Class" in i.attrib:
            language.append(i.attrib["Class"])
        elif "Name" in i.attrib:
            language.append(i.attrib["Name"])

    technology = []
    for i in item.iter(NS + "Technology"):
        if "Class" in i.attrib:
            technology.append(i.attrib["Class"])
        elif "Name" in i.attrib:
            technology.append(i.attrib["Name"])

    likelihood = ""
    like_elem = item.find(NS + "Likelihood_Of_Exploit")
    if like_elem is not None:
        likelihood = like_elem.text or ""

    consequence = []
    for i in item.iter(NS + "Scope"):
        if i.text:
            consequence.append(i.text)

    examples = []
    for i in item.iter(NS + "Reference"):
        if i.text:
            examples.append(i.text)

    rows.append({
        "ID": cweid,
        "Name": name,
        "Description": description,
        "Extended_Description": extended,
        "Related_Weakness": ";".join(related),
        "Language": ";".join(language),
        "Technology": ";".join(technology),
        "Likelihood_Of_Exploit": likelihood,
        "Consequence": ";".join(set(consequence)),
        "CVE_Example": ";".join(set(examples))
    })

df = pd.DataFrame(rows, columns=cols)
df.to_csv(OUTPUT_CSV, index=False, encoding="utf-8-sig")

print(f"CWE записей: {len(df)}")