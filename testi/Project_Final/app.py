from flask import Flask, request, jsonify
from ti_engine import classify_value  # your TI logic

app = Flask(__name__)

# -----------------------------
# ROOT ROUTE
# -----------------------------
@app.route("/")
def home():
    return jsonify({"message": "Welcome to the Threat Intelligence API"})

# -----------------------------
# HEALTH CHECK
# -----------------------------
@app.get("/health")
def health():
    return jsonify({"status": "ok"})

# -----------------------------
# IP CHECK
# -----------------------------
@app.post("/ip")
def score_ip():
    data = request.json
    if not data or "ip" not in data:
        return jsonify({"error": "missing 'ip'"}), 400

    result = classify_value(data["ip"])
    return jsonify({
        "value": data["ip"],
        "type": "ip",
        "final_score": result["final_score"],
        "classification": result["classification"],
        "confidence": result["confidence"]
    })

# -----------------------------
# URL CHECK
# -----------------------------
@app.post("/url")
def score_url():
    data = request.json
    if not data or "url" not in data:
        return jsonify({"error": "missing 'url'"}), 400

    result = classify_value(data["url"])
    return jsonify({
        "value": data["url"],
        "type": "url",
        "final_score": result["final_score"],
        "classification": result["classification"],
        "confidence": result["confidence"]
    })

# -----------------------------
# DOMAIN CHECK
# -----------------------------
@app.post("/domain")
def score_domain():
    data = request.json
    if not data or "domain" not in data:
        return jsonify({"error": "missing 'domain'"}), 400

    result = classify_value(data["domain"])
    return jsonify({
        "value": data["domain"],
        "type": "domain",
        "final_score": result["final_score"],
        "classification": result["classification"],
        "confidence": result["confidence"]
    })

# -----------------------------
# FILE HASH CHECK
# -----------------------------
@app.post("/file")
def score_file():
    data = request.json
    if not data or "hash" not in data:
        return jsonify({"error": "missing 'hash'"}), 400

    result = classify_value(data["hash"])
    return jsonify({
        "value": data["hash"],
        "type": "file",
        "final_score": result["final_score"],
        "classification": result["classification"],
        "confidence": result["confidence"]
    })

# -----------------------------
# BULK CHECK
# -----------------------------
@app.post("/bulk")
def bulk():
    data = request.json
    if not data or "values" not in data:
        return jsonify({"error": "missing 'values'"}), 400

    output = []
    for v in data["values"]:
        result = classify_value(v)
        output.append({
            "value": v,
            "type": result.get("type", "unknown"),
            "final_score": result["final_score"],
            "classification": result["classification"],
            "confidence": result["confidence"]
        })
    return jsonify(output)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5002
)
