from flask import Flask, jsonify, request
from flask_caching import Cache
import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import binascii
import my_pb2
import output_pb2
import json
from colorama import init
import warnings
from urllib3.exceptions import InsecureRequestWarning

warnings.filterwarnings("ignore", category=InsecureRequestWarning)
AES_KEY = b'Yg&tc%DEuh6%Zc^8'
AES_IV = b'6oyZDr22E3ychjM%'

init(autoreset=True)

app = Flask(__name__)
cache = Cache(app, config={'CACHE_TYPE': 'SimpleCache', 'CACHE_DEFAULT_TIMEOUT': 25200})

def get_token(password, uid):
    try:
        url = "https://100067.connect.garena.com/oauth/guest/token/grant"
        headers = {
            "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept-Encoding": "gzip",
            "Connection": "close"
        }
        data = {
            "uid": uid,
            "password": password,
            "response_type": "token",
            "client_type": "2",
            "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
            "client_id": "100067"
        }
        res = requests.post(url, headers=headers, data=data, timeout=10, verify=False)
        if res.status_code != 200:
            return None
        token_json = res.json()
        if "access_token" in token_json and "open_id" in token_json:
            return token_json
        else:
            return None
    except Exception:
        return None

def encrypt_message(key, iv, plaintext):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_message = pad(plaintext, AES.block_size)
    return cipher.encrypt(padded_message)

def parse_response(content):
    response_dict = {}
    lines = content.split("\n")
    for line in lines:
        if ":" in line:
            key, value = line.split(":", 1)
            response_dict[key.strip()] = value.strip().strip('"')
    return response_dict

@app.route('/tokens', methods=['POST'])
@cache.cached(timeout=25200)
def get_multiple_tokens():
    try:
        accounts = request.get_json()
        if not isinstance(accounts, list):
            return jsonify({"error": "Invalid JSON format. Expected a list of accounts."}), 400

        result = []
        for acc in accounts:
            uid = acc.get("uid")
            password = acc.get("password")

            if not uid or not password:
                result.append({
                    "uid": uid or "unknown",
                    "status": "error",
                    "message": "UID or Password missing"
                })
                continue

            token_data = get_token(password, uid)
            if not token_data:
                result.append({
                    "uid": uid,
                    "status": "invalid",
                    "message": "Wrong UID or Password",
                    "credit": "@GHOST_XMOD"
                })
                continue

            # -- Game Data (OB50 or any version logic can go here) --
            game_data = my_pb2.GameData()
            game_data.timestamp = "2024-12-05 18:15:32"
            game_data.game_name = "free fire"

            result.append({
                "uid": uid,
                "status": "success",
                "access_token": token_data.get("access_token"),
                "open_id": token_data.get("open_id"),
                "game_data": {
                    "timestamp": game_data.timestamp,
                    "game": game_data.game_name
                }
            })

        return jsonify(result)

    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
