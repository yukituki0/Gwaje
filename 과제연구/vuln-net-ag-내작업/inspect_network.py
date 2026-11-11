import json

with open("networks_unzipped/networks/5_5_lan25_uniform_0.25.json", "r", encoding="utf-8") as f:
    data = json.load(f)

print("=== devices ===")
print("타입:", type(data["devices"]))
if isinstance(data["devices"], list):
    print("개수:", len(data["devices"]))
    print(json.dumps(data["devices"][0], indent=2, ensure_ascii=False))
elif isinstance(data["devices"], dict):
    first_key = list(data["devices"].keys())[0]
    print("개수:", len(data["devices"]))
    print("첫 키:", first_key)
    print(json.dumps(data["devices"][first_key], indent=2, ensure_ascii=False))

print("\n=== vulnerabilities ===")
print("타입:", type(data["vulnerabilities"]))
if isinstance(data["vulnerabilities"], list):
    print("개수:", len(data["vulnerabilities"]))
    print(json.dumps(data["vulnerabilities"][0], indent=2, ensure_ascii=False))
elif isinstance(data["vulnerabilities"], dict):
    first_key = list(data["vulnerabilities"].keys())[0]
    print("개수:", len(data["vulnerabilities"]))
    print("첫 키:", first_key)
    print(json.dumps(data["vulnerabilities"][first_key], indent=2, ensure_ascii=False))

print("\n=== edges ===")
print("타입:", type(data["edges"]))
if isinstance(data["edges"], list):
    print("개수:", len(data["edges"]))
    print(json.dumps(data["edges"][0], indent=2, ensure_ascii=False))
elif isinstance(data["edges"], dict):
    first_key = list(data["edges"].keys())[0]
    print("개수:", len(data["edges"]))
    print("첫 키:", first_key)
    print(json.dumps(data["edges"][first_key], indent=2, ensure_ascii=False))