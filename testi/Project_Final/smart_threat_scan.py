import json
from ti_engine.classifier import classify_value, detect_type

INPUT_FILE = "inputs.txt"
OUTPUT_FILE = "results.json"

# Separate output files
FILES = {
    "ip": "ips.json",
    "url": "urls.json",
    "domain": "domains.json",
    "hash": "hashes.json",
    "ja3": "ja3.json",
    "ja3s": "ja3s.json",
    "unknown": "unknown.json"
}

# -------------------------------------
# Load input values
# -------------------------------------
def load_inputs():
    with open(INPUT_FILE, "r") as f:
        return [line.strip() for line in f.readlines() if line.strip()]

# -------------------------------------
# Save results into a JSON file
# -------------------------------------
def save_json(path, data):
    with open(path, "w") as f:
        json.dump(data, f, indent=4)

# -------------------------------------
# MAIN SCAN LOGIC
# -------------------------------------
def run_scan():
    values = load_inputs()
    final_output = []

    # Prepare empty category buckets
    categorized = {key: [] for key in FILES.keys()}

    for v in values:
        v_type = detect_type(v)

        # Call TI engine
        result = classify_value(v)
        # Include type in result
        result["type"] = v_type

        final_output.append(result)

        # Add to correct category
        if v_type in categorized:
            categorized[v_type].append(result)
        else:
            categorized["unknown"].append(result)

    # Save full combined result
    save_json(OUTPUT_FILE, final_output)

    # Save each category in separate files
    for t, path in FILES.items():
        save_json(path, categorized[t])

    print("\nScan Completed Successfully!")
    print("Generated files:")
    print(f"- {OUTPUT_FILE}")
    for t, path in FILES.items():
        print(f"- {path}")

# -------------------------------------
# RUN
# -------------------------------------
if __name__ == "__main__":
    run_scan()
