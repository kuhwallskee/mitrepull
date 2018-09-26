from stix2 import TAXIICollectionSource, Filter
from taxii2client import Server, Collection

# Instantiate server and get API Root
server = Server("https://cti-taxii.mitre.org/taxii/")
api_root = server.api_roots[0]

def get_enterprise():
    for collection in api_root.collections:
        if collection.title == "Enterprise ATT&CK":
            return collection.id

# Print name and ID of all ATT&CK technology-domains available as collections

attack = {}
collection = Collection("https://cti-taxii.mitre.org/stix/collections/95ecc380-afe9-11e4-9b6c-751b66dd541e/")

# Supply the collection to TAXIICollection
tc_source = TAXIICollectionSource(collection)

# Create filters to retrieve content from Enterprise ATT&CK based on type
filter_objs = {"techniques": Filter("type", "=", "attack-pattern")}
# Retrieve all Enterprise ATT&CK content
for key in filter_objs:
          attack[key] = tc_source.query(filter_objs[key])


print attack["techniques"][0]

#All the T Numbes
list_of_t_numbers = [[y["external_id"] for y in x["external_references"] if y["source_name"] == "mitre-attack"] for x in attack["techniques"]]
print list_of_t_numbers

#All the Mac Tehniques, prefixed with the kill chain phase
mac_techs = [[x["name"] + x["kill_chain_phases"]) for y in x["x_mitre_platforms"] if y == "macOS"] for x in attack["techniques"]]

print mac_techs
