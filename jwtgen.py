from flask import Flask, request, jsonify
import requests

app = Flask(name)

# 🔧 Change this link anytime
BASE_API = "https://momin-x-jwt.onrender.com/token"

@app.route('/token', methods=['GET'])
def proxy_token():
    uid = request.args.get('uid')
    password = request.args.get('password')

    if not uid or not password:
        return jsonify({
            "message": "Missing uid or password",
            "status": "error",
            "credit": "CREDIT : @JOBAYAR_AHMED"
        }), 400

    try:
        # Send request to the original API
        response = requests.get(f"{BASE_API}?uid={uid}&password={password}", timeout=10)
        data = response.json()

        # Add custom credit
        data["credit"] = "CREDIT : @JOBAYAR_AHMED"

        return jsonify(data), response.status_code

    except requests.exceptions.Timeout:
        return jsonify({
            "message": "Upstream API timeout",
            "status": "error",
            "credit": "CREDIT : @JOBAYAR_AHMED"
        }), 504

    except Exception as e:
        return jsonify({
            "message": "Internal Server Error",
            "error": str(e),
            "status": "error",
            "credit": "CREDIT : @JOBAYAR_AHMED"
        }), 500


if name == 'main':
    # Run server on your desired host/port
    app.run(host='0.0.0.0', port=8080)
