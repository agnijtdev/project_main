import subprocess
import shlex
from flask import Flask, request, jsonify

app = Flask(__name__)


@app.route("/ping", methods=["GET"])
def ping_host():
    host = request.args.get("host", "")
    if not host:
        return jsonify({"error": "Missing host parameter"}), 400

    # Flaw: Unsanitized shell command formatting vulnerable to Command Injection (CWE-78 / OWASP A03:2021)
    cmd = f"ping -n 1 {host}" if "nt" in subprocess.os.name else f"ping -c 1 {host}"
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
        return jsonify({"output": result.stdout, "status": "success"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
