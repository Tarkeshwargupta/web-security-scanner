from flask import Flask, render_template, request, jsonify
from scanner import run_full_scan

app = Flask(__name__)

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/scan", methods=["POST"])
def scan():
    payload = request.get_json(silent=True) or {}
    domain = payload.get("domain", "").strip()

    if not domain:
        return jsonify({"error": "Please enter a domain"}), 400

    result = run_full_scan(domain)
    status_code = 400 if result.get("error") else 200
    return jsonify(result), status_code

if __name__ == "__main__":
    app.run(debug=True)