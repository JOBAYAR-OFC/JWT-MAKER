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

@app.route('/token', methods=['GET'])
@cache.cached(timeout=25200, query_string=True)
def get_single_response():
    uid = request.args.get('uid')
    password = request.args.get('password')

    if not uid or not password:
        return jsonify({"error": "Both uid and password parameters are required"}), 400

    token_data = get_token(password, uid)
    if not token_data:
        return jsonify({
            "uid": uid,
            "status": "invalid",
            "message": "Wrong UID or Password. Please check and try again.",
            "credit": "@GHOST_XMOD"
        }), 400

    # --- Dynamic Game Data Handling (New Section) ---
    # Here, we're keeping it as is because it's not explicitly stated
    # that 'timestamp' or 'game_name' depend on 'obi' versions 49-50.
    # If they do, you would implement logic here to set them based on
    # an 'obi_version' parameter (e.g., from request.args.get('obi_version'))
    # or by inferring it from the UID if possible.

    game_data = my_pb2.GameData()
    game_data.timestamp = "2024-12-05 18:15:32"  # This value might need to be dynamic
    game_data.game_name = "free fire"           # This value might need to be dynamic

    # Example of how you *would* make it dynamic if 'obi' version mattered:
    # obi_version = request.args.get('obi_version')
    # if obi_version == '49':
    #     game_data.timestamp = "TIMESTAMP_FOR_OBI_49"
    #     game_data.game_name = "free fire"
    # elif obi_version == '50':
    #     game_data.timestamp = "TIMESTAMP_FOR_OBI_50"
    #     game_data.game_name = "free fire"
    # else:
    #     # Default or error handling
    #     game_data.timestamp = "2024-12-05 18:15:32"
    #     game_data.game_name = "free fire"
    # --- End Dynamic Game Data Handling ---

    # Your existing code continues from here:
    # Convert Protobuf message to bytes
    serialized_game_data = game_data.SerializeToString()

    # Encrypt the serialized data
    encrypted_data = encrypt_message(AES_KEY, AES_IV, serialized_game_data)
    hex_encrypted_data = binascii.hexlify(encrypted_data).decode('utf-8')

    # Prepare the payload for the second request
    payload = {
        "m": "user",
        "a": "get_user_info",
        "data": hex_encrypted_data,
        "ts": "1701777270",
        "token": token_data["access_token"]
    }
    encoded_payload = json.dumps(payload)

    try:
        url = "https://account.garena.com/api/user"
        headers = {
            "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept-Encoding": "gzip",
            "Connection": "close"
        }
        res_user_info = requests.post(url, headers=headers, data=f"req={encoded_payload}", timeout=10, verify=False)

        if res_user_info.status_code != 200:
            return jsonify({
                "uid": uid,
                "status": "error",
                "message": f"Error getting user info: Status code {res_user_info.status_code}",
                "credit": "@GHOST_XMOD"
            }), 500

        user_info_raw = res_user_info.text
        user_info_dict = parse_response(user_info_raw)

        return jsonify({
            "uid": uid,
            "status": "success",
            "message": "Login successful",
            "access_token": token_data["access_token"],
            "open_id": token_data["open_id"],
            "user_info": user_info_dict,
            "credit": "@GHOST_XMOD"
        })

    except requests.exceptions.Timeout:
        return jsonify({
            "uid": uid,
            "status": "error",
            "message": "Request to Garena API timed out.",
            "credit": "@GHOST_XMOD"
        }), 500
    except requests.exceptions.RequestException as e:
        return jsonify({
            "uid": uid,
            "status": "error",
            "message": f"An error occurred during the Garena API request: {str(e)}",
            "credit": "@GHOST_XMOD"
        }), 500
    except Exception as e:
        return jsonify({
            "uid": uid,
            "status": "error",
            "message": f"An unexpected error occurred: {str(e)}",
            "credit": "@GHOST_XMOD"
        }), 500

if __name__ == '__main__':
    app.run(debug=True)
