from flask import Flask, request, jsonify
import jwt
import json
import logging
import argparse
from cryptography.hazmat.primitives import serialization

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

kv_db = {}

@app.route("/put", methods=["POST"])
def put_value():
    key = request.args.get("key")
    token = request.cookies.get("jwt")

    if not token:
        return "No token provided", 401

    try:
        decoded = jwt.decode(token, PUBLIC_KEY, algorithms=["RS256"])
        username = decoded.get("username")
        if not username:
            return "Invalid token", 400
    except jwt.InvalidTokenError:
        return "Invalid token", 400

    data = json.loads(request.data)
    if not data or "value" not in data:
        return "Invalid request body", 400

    value = data["value"]

    if key in kv_db:
        if kv_db[key]["owner"] != username:
            return "The key exists but belongs to another user", 403

    kv_db[key] = {"value": value, "owner": username}

    return "Value set successfully", 200

@app.route("/get", methods=["GET"])
def get_value():
    key = request.args.get("key")
    token = request.cookies.get("jwt")

    if not token:
        return jsonify({"error": "No token provided"}), 401

    try:
        decoded = jwt.decode(token, PUBLIC_KEY, algorithms=["RS256"])
        username = decoded.get("username")
        if not username:
            return jsonify({"error": "Invalid token"}), 400
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid token"}), 400

    if key not in kv_db:
        return jsonify({"error": "Key not found"}), 404

    if kv_db[key]["owner"] != username:
        return jsonify({"error": "The key exists but belongs to another user"}), 403

    return jsonify({"value": kv_db[key]["value"]}), 200

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="KV Service")
    parser.add_argument("--public", required=True, help="Path to the public key file")
    parser.add_argument("--port", required=True, type=int, help="Port for the HTTP server")

    args = parser.parse_args()

    with open(args.public, "rb") as public_file:
        PUBLIC_KEY = serialization.load_pem_public_key(
            public_file.read()
        )

    app.run(debug=True, host='::', port=args.port)
