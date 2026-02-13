from owlready2 import *
import os
from dotenv import load_dotenv

load_dotenv(".local.env")

ONTO_IRI = os.getenv("ONTO_IRI")
ONTO_OUTPUT = os.getenv("ONTO_OUTPUT")

onto = get_ontology(ONTO_IRI)

with onto:

    class WebApplication(Thing): pass
    class Component(Thing): pass
    class CPE(Thing): pass
    class CVE(Thing): pass
    class CWE(Thing): pass
    class CAPEC(Thing): pass

    class usesComponent(ObjectProperty):
        domain = [WebApplication]
        range = [Component]

    class mappedToCPE(ObjectProperty):
        domain = [Component]
        range = [CPE]

    class affects(ObjectProperty):
        domain = [CVE]
        range = [CPE]

    class hasWeakness(ObjectProperty):
        domain = [CVE]
        range = [CWE]

    class exploitedBy(ObjectProperty):
        domain = [CWE]
        range = [CAPEC]

    class hasCVSSScore(DataProperty):
        domain = [CVE]
        range = [float]

    class hasSeverity(DataProperty):
        domain = [CVE]
        range = [str]

    class hasDescription(DataProperty):
        domain = [CVE]
        range = [str]

    class hasName(DataProperty):
        range = [str]

onto.save(file=ONTO_OUTPUT, format="rdfxml")

print("Структура онтологии создана")