from owlready2 import *
import pandas as pd
import json
import os
from dotenv import load_dotenv

owlready2.reasoning.JAVA_MEMORY = 16000

load_dotenv(".local.env")

ONTO_PATH = os.getenv("ONTO_PATH")
ONTO_OUTPUT = os.getenv("ONTO_OUTPUT")
CWE_CSV_PATH = os.getenv("CWE_OUTPUT_CSV")
CWE_CHAINS_OUTPUT = os.getenv("CWE_CHAINS_OUTPUT")

onto = get_ontology(f"file://{os.path.abspath(ONTO_PATH)}").load()

cwe_df = pd.read_csv(CWE_CSV_PATH)

with onto:
    class CanPrecede(ObjectProperty):
        domain = [onto.CWE]
        range = [onto.CWE]
        transitive = True

cwe_instances = {}

for _, row in cwe_df.iterrows():
    cwe_id = str(row['ID']).strip()
    
    with onto:
        cwe = onto.CWE(cwe_id)
        cwe_instances[cwe_id] = cwe


connections_count = 0
for _, row in cwe_df.iterrows():
    cwe_id = str(row['ID']).strip()
    related_weakness = row.get('Related_Weakness', '')
    
    if pd.isna(related_weakness) or not related_weakness:
        continue
    
    cwe = cwe_instances.get(cwe_id)
    if not cwe:
        continue
    
    relations = str(related_weakness).split(';')
    
    for relation in relations:
        relation = relation.strip()
        if not relation:
            continue
        
        if ':' in relation:
            rel_type, target_id = relation.split(':', 1)
            rel_type = rel_type.strip()
            target_id = target_id.strip()
            
            if rel_type == 'CanPrecede':
                target_cwe = cwe_instances.get(f"CWE-{target_id}")
                if target_cwe:
                    cwe.CanPrecede.append(target_cwe)
                    connections_count += 1


with onto:
    sync_reasoner_hermit(infer_property_values=True)


cwe_chains = {}

for cwe_id, cwe in cwe_instances.items():
    chain = []
    
    try:
        for next_cwe in cwe.CanPrecede:
            chain.append(next_cwe.name)
    except Exception as e:
        pass
    
    cwe_chains[cwe_id] = chain

chains_with_relations = sum(1 for c in cwe_chains.values() if len(c) > 0)

output_dir = os.path.dirname(CWE_CHAINS_OUTPUT)
os.makedirs(output_dir, exist_ok=True)

with open(CWE_CHAINS_OUTPUT, "w", encoding="utf-8") as f:
    json.dump(cwe_chains, f, indent=2, ensure_ascii=False)