from flask import Flask, request, jsonify
import json
import base64
import asyncio
import httpx
import os
import time
from Crypto.Cipher import AES
from google.protobuf import json_format, message
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# === Settings ===
MAIN_KEY = base64.b64decode('WWcmdGMlREV1aDYlWmNeOA==')
MAIN_IV = base64.b64decode('Nm95WkRyMjJFM3ljaGpNJQ==')
USERAGENT = "Dalvik/2.1.0 (Linux; U; Android 13; CPH2095 Build/RKQ1.211119.001)"
RELEASEVERSION = "OB50"
MAX_WORKERS = 10

# === Import Protobuf ===
try:
    from proto import FreeFire_pb2, main_pb2, AccountPersonalShow_pb2
except ImportError:
    logger.error("Protobuf modules not found. Please ensure FreeFire_pb2.py, main_pb2.py, and AccountPersonalShow_pb2.py are in the proto/ directory.")
    exit(1)

# === Helper Functions ===
def pad(text: bytes) -> bytes:
    padding_length = AES.block_size - (len(text) % AES.block_size)
    return text + bytes([padding_length] * padding_length)

def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    aes = AES.new(key, AES.MODE_CBC, iv)
    return aes.encrypt(pad(plaintext))

async def json_to_proto(json_data: str, proto_message: message.Message) -> bytes:
    json_format.ParseDict(json.loads(json_data), proto_message)
    return proto_message.SerializeToString()

async def get_access_token(account: str):
    url = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
    payload = f"{account}&response_type=token&client_type=2&client_secret=2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3&client_id=100067"
    headers = {
        'User-Agent': USERAGENT,
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Content-Type': "application/x-www-form-urlencoded"
    }
    async with httpx.AsyncClient(timeout=20.0) as client:
        resp = await client.post(url, data=payload, headers=headers)
        resp.raise_for_status()
        data = resp.json()
        access_token = data.get("access_token", "0")
        open_id = data.get("open_id", "0")
        return access_token, open_id

async def create_jwt(uid: str, password: str):
    try:
        account = f"uid={uid}&password={password}"
        token_val, open_id = await get_access_token(account)
        body = json.dumps({
            "open_id": open_id,
            "open_id_type": "4",
            "login_token": token_val,
            "orign_platform_type": "4"
        })
        proto_bytes = await json_to_proto(body, FreeFire_pb2.LoginReq())
        payload = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, proto_bytes)
        url = "https://loginbp.ggblueshark.com/MajorLogin"
        headers = {
            'User-Agent': USERAGENT,
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Content-Type': "application/octet-stream",
            'Expect': "100-continue",
            'X-Unity-Version': "2022.3.47f1",
            'X-GA': "v1 1",
            'ReleaseVersion': RELEASEVERSION
        }
        async with httpx.AsyncClient(timeout=20.0) as client:
            resp = await client.post(url, data=payload, headers=headers)
            resp.raise_for_status()
            msg = json.loads(json_format.MessageToJson(FreeFire_pb2.LoginRes.FromString(resp.content)))
            token = msg.get('token', '0')
            region = msg.get('lockRegion', '0')
            server_url = msg.get('serverUrl', 'https://loginbp.ggblueshark.com')
            return {
                'uid': uid,
                'token': f"{token}",
                'region': region,
                'server_url': server_url,
            }
    except Exception as e:
        logger.error(f"Error creating JWT for UID {uid}: {str(e)}")
        return {'error': str(e), 'uid': uid}

@app.route('/token', methods=['GET'])
async def generate_token():
    """
    Generate JWT token for FreeFire account
    Example: https://momin-x-jwt.onrender.com/token?uid=4211291069&password=BY_PARAHEX-ZMEFPC2NK-REDZED
    """
    try:
        uid = request.args.get('uid', '').strip()
        password = request.args.get('password', '').strip()
        
        if not uid or not password:
            return jsonify({
                'success': False,
                'error': 'Missing uid or password parameter',
                'message': 'Please provide both uid and password parameters'
            }), 400
        
        logger.info(f"Generating token for UID: {uid}")
        
        result = await create_jwt(uid, password)
        
        if 'error' in result:
            return jsonify({
                'success': False,
                'error': result['error'],
                'uid': uid,
                'message': 'Failed to generate token'
            }), 400
        
        # Success response format
        response_data = [{
            'uid': result['uid'],
            'token': result['token'],
            'region': result['region']
        }]
        
        logger.info(f"Successfully generated token for UID: {uid}")
        return jsonify(response_data), 200
        
    except Exception as e:
        logger.error(f"Unexpected error in generate_token: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Internal server error',
            'message': 'An unexpected error occurred'
        }), 500

@app.route('/bulk-token', methods=['POST'])
async def bulk_generate_tokens():
    """
    Generate JWT tokens for multiple accounts
    Expects JSON: {"accounts": [{"uid": "123", "password": "pass"}, ...]}
    """
    try:
        data = request.get_json()
        if not data or 'accounts' not in data:
            return jsonify({
                'success': False,
                'error': 'Missing accounts array in request body',
                'message': 'Please provide accounts array with uid and password'
            }), 400
        
        accounts = data['accounts']
        if not isinstance(accounts, list):
            return jsonify({
                'success': False,
                'error': 'Invalid format: accounts should be an array',
                'message': 'Accounts should be an array of objects with uid and password'
            }), 400
        
        results = []
        errors = []
        
        # Process accounts concurrently
        sem = asyncio.Semaphore(MAX_WORKERS)
        
        async def process_single_account(account):
            async with sem:
                uid = str(account.get('uid', '')).strip()
                password = str(account.get('password', '')).strip()
                
                if not uid or not password:
                    errors.append({'uid': 'Unknown', 'error': 'Missing uid or password'})
                    return
                
                result = await create_jwt(uid, password)
                if 'error' in result:
                    errors.append({'uid': uid, 'error': result['error']})
                else:
                    results.append({
                        'uid': result['uid'],
                        'token': result['token'],
                        'region': result['region']
                    })
        
        # Create and run all tasks
        tasks = [process_single_account(account) for account in accounts]
        await asyncio.gather(*tasks, return_exceptions=True)
        
        response_data = {
            'success': True,
            'tokens': results,
            'total_processed': len(accounts),
            'successful': len(results),
            'failed': len(errors)
        }
        
        if errors:
            response_data['errors'] = errors
        
        return jsonify(response_data), 200
        
    except Exception as e:
        logger.error(f"Unexpected error in bulk_generate_tokens: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Internal server error',
            'message': 'An unexpected error occurred during bulk token generation'
        }), 500

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'success': True,
        'message': 'JWT API is running',
        'status': 'healthy',
        'timestamp': time.time()
    }), 200

@app.route('/')
def home():
    """Home endpoint with API information"""
    return jsonify({
        'success': True,
        'message': 'FreeFire JWT Token Generator API',
        'endpoints': {
            '/token': 'GET - Generate single token (parameters: uid, password)',
            '/bulk-token': 'POST - Generate multiple tokens (JSON body with accounts array)',
            '/health': 'GET - Health check'
        },
        'example': 'https://momin-x-jwt.onrender.com/token?uid=4211291069&password=BY_PARAHEX-ZMEFPC2NK-REDZED'
    }), 200

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    logger.info(f"Starting JWT API server on port {port}")
    app.run(host='0.0.0.0', port=port, debug=False)
