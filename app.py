#!/usr/bin/env python3
"""
RIZER GUEST ACCOUNT GENERATOR API - PURE FIXED VERSION v12.0
ALL ISSUES FIXED:
- Account Activation FIXED
- Account ID Showing FIXED  
- JWT Token Extraction FIXED
- Account Creation FIXED
"""

from flask import Flask, request, jsonify, render_template_string, send_file
import os
import sys
import json
import time
import random
import string
import hmac
import hashlib
import base64
import codecs
import threading
import re
import warnings
import urllib3
import io
import zipfile
from datetime import datetime

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore")

try:
    import requests
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad
except ImportError:
    import subprocess
    subprocess.check_call([sys.executable, '-m', 'pip', 'install', 'requests', 'pycryptodome', '-q'])
    import requests
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad

try:
    import MajorLoginRes_pb2
    PROTOBUF_AVAILABLE = True
except ImportError:
    PROTOBUF_AVAILABLE = False

app = Flask(__name__)

# Configuration
EXIT_FLAG = False
SUCCESS_COUNTER = 0
RARE_COUNTER = 0
COUPLES_COUNTER = 0
ACTIVATED_COUNTER = 0
FAILED_ACTIVATION_COUNTER = 0
RARITY_SCORE_THRESHOLD = 2
MAX_ACCOUNTS_PER_REQUEST = 10000
MAX_WORKERS = 100
LOCK = threading.Lock()

REGION_LANG = {
    "ME": "ar", "IND": "hi", "ID": "id", "VN": "vi", 
    "TH": "th", "BD": "bn", "PK": "ur", "TW": "zh", 
    "CIS": "ru", "SAC": "es", "BR": "pt", "NA": "en",
    "LK": "en"
}

ACTIVATION_REGIONS = {
    'IND': {
        'guest_url': 'https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant',
        'major_login_url': 'https://loginbp.common.ggbluefox.com/MajorLogin',
        'get_login_data_url': 'https://client.ind.freefiremobile.com/GetLoginData',
        'client_host': 'client.ind.freefiremobile.com'
    },
    'BD': {
        'guest_url': 'https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant',
        'major_login_url': 'https://loginbp.ggblueshark.com/MajorLogin',
        'get_login_data_url': 'https://clientbp.ggblueshark.com/GetLoginData',
        'client_host': 'clientbp.ggblueshark.com'
    },
    'PK': {
        'guest_url': 'https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant',
        'major_login_url': 'https://loginbp.ggblueshark.com/MajorLogin',
        'get_login_data_url': 'https://clientbp.ggblueshark.com/GetLoginData',
        'client_host': 'clientbp.ggblueshark.com'
    },
    'NA': {
        'guest_url': 'https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant',
        'major_login_url': 'https://loginbp.ggblueshark.com/MajorLogin',
        'get_login_data_url': 'https://clientbp.ggblueshark.com/GetLoginData',
        'client_host': 'clientbp.ggblueshark.com'
    },
    'LK': {
        'guest_url': 'https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant',
        'major_login_url': 'https://loginbp.ggblueshark.com/MajorLogin',
        'get_login_data_url': 'https://clientbp.ggblueshark.com/GetLoginData',
        'client_host': 'clientbp.ggblueshark.com'
    },
    'ID': {
        'guest_url': 'https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant',
        'major_login_url': 'https://loginbp.ggblueshark.com/MajorLogin',
        'get_login_data_url': 'https://clientbp.ggblueshark.com/GetLoginData',
        'client_host': 'clientbp.ggblueshark.com'
    },
    'TH': {
        'guest_url': 'https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant',
        'major_login_url': 'https://loginbp.ggblueshark.com/MajorLogin',
        'get_login_data_url': 'https://clientbp.common.ggbluefox.com/GetLoginData',
        'client_host': 'clientbp.common.ggbluefox.com'
    },
    'VN': {
        'guest_url': 'https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant',
        'major_login_url': 'https://loginbp.ggblueshark.com/MajorLogin',
        'get_login_data_url': 'https://clientbp.ggblueshark.com/GetLoginData',
        'client_host': 'clientbp.ggblueshark.com'
    },
    'ME': {
        'guest_url': 'https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant',
        'major_login_url': 'https://loginbp.common.ggbluefox.com/MajorLogin',
        'get_login_data_url': 'https://clientbp.ggblueshark.com/GetLoginData',
        'client_host': 'clientbp.ggblueshark.com'
    },
    'BR': {
        'guest_url': 'https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant',
        'major_login_url': 'https://loginbp.ggblueshark.com/MajorLogin',
        'get_login_data_url': 'https://clientbp.ggblueshark.com/GetLoginData',
        'client_host': 'clientbp.ggblueshark.com'
    }
}

MAIN_HEX_KEY = "32656534343831396539623435393838343531343130363762323831363231383734643064356437616639643866376530306331653534373135623764316533"
API_POOL = [{"id": "100067", "key": bytes.fromhex(MAIN_HEX_KEY), "label": f"API {i:02d}"} for i in range(1, 8)]

thread_local = threading.local()
POTENTIAL_COUPLES = {}
COUPLES_LOCK = threading.Lock()

ACCOUNTS_STORAGE = {}
RARE_ACCOUNTS_STORAGE = {}
COUPLES_ACCOUNTS_STORAGE = {}
ACTIVATED_ACCOUNTS_STORAGE = {}
FAILED_ACTIVATION_STORAGE = {}
STORAGE_LOCK = threading.Lock()

ACTIVATION_STATS = {
    'total_processed': 0,
    'successful_activations': 0,
    'failed_activations': 0,
    'rare_accounts': 0,
    'couples_found': 0
}

# Crypto Functions
def EnC_Vr(N):
    if N < 0:
        return b''
    H = []
    while True:
        BesTo = N & 0x7F
        N >>= 7
        if N:
            BesTo |= 0x80
        H.append(BesTo)
        if not N:
            break
    return bytes(H)

def CrEaTe_VarianT(field_number, value):
    field_header = (field_number << 3) | 0
    return EnC_Vr(field_header) + EnC_Vr(value)

def CrEaTe_LenGTh(field_number, value):
    field_header = (field_number << 3) | 2
    encoded_value = value.encode() if isinstance(value, str) else value
    return EnC_Vr(field_header) + EnC_Vr(len(encoded_value)) + encoded_value

def CrEaTe_ProTo(fields):
    packet = bytearray()
    for field, value in fields.items():
        if isinstance(value, dict):
            nested_packet = CrEaTe_ProTo(value)
            packet.extend(CrEaTe_LenGTh(field, nested_packet))
        elif isinstance(value, int):
            packet.extend(CrEaTe_VarianT(field, value))
        elif isinstance(value, (str, bytes)):
            packet.extend(CrEaTe_LenGTh(field, value))
    return bytes(packet)

def E_AEs(Pc):
    Z = bytes.fromhex(Pc)
    key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
    iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
    K = AES.new(key, AES.MODE_CBC, iv)
    R = K.encrypt(pad(Z, AES.block_size))
    return R

def encrypt_api(plain_text):
    try:
        plain_text = bytes.fromhex(plain_text)
        key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
        iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
        cipher = AES.new(key, AES.MODE_CBC, iv)
        cipher_text = cipher.encrypt(pad(plain_text, AES.block_size))
        return cipher_text.hex()
    except Exception as e:
        return None

def decode_jwt_token(jwt_token):
    try:
        if not jwt_token or '.' not in jwt_token:
            return "N/A"
        parts = jwt_token.split('.')
        if len(parts) >= 2:
            payload_part = parts[1]
            padding = 4 - len(payload_part) % 4
            if padding != 4:
                payload_part += '=' * padding
            decoded = base64.urlsafe_b64decode(payload_part)
            data = json.loads(decoded)
            account_id = data.get('account_id') or data.get('external_id') or data.get('sub')
            if account_id:
                return str(account_id)
    except:
        pass
    return "N/A"

# Rarity Detection
ACCOUNT_RARITY_PATTERNS = {
    "REPEATED_DIGITS_4": [r"(\d)\1{3,}", 3],
    "REPEATED_DIGITS_3": [r"(\d)\1\1(\d)\2\2", 2],
    "SEQUENTIAL_5": [r"(12345|23456|34567|45678|56789)", 4],
    "SEQUENTIAL_4": [r"(0123|1234|2345|3456|4567|5678|6789|9876|8765|7654|6543|5432|4321|3210)", 3],
    "PALINDROME_6": [r"^(\d)(\d)(\d)\3\2\1$", 5],
    "PALINDROME_4": [r"^(\d)(\d)\2\1$", 3],
    "SPECIAL_COMBINATIONS_HIGH": [r"(69|420|1337|007)", 4],
    "SPECIAL_COMBINATIONS_MED": [r"(100|200|300|400|500|666|777|888|999)", 2],
    "QUADRUPLE_DIGITS": [r"(1111|2222|3333|4444|5555|6666|7777|8888|9999|0000)", 4],
    "MIRROR_PATTERN_HIGH": [r"^(\d{2,3})\1$", 3],
    "MIRROR_PATTERN_MED": [r"(\d{2})0\1", 2],
    "GOLDEN_RATIO": [r"1618|0618", 3]
}

def check_account_rarity(account_data):
    account_id = account_data.get("account_id", "")
    if account_id == "N/A" or not account_id:
        return False, None, None, 0

    rarity_score = 0
    detected_patterns = []

    for rarity_type, pattern_data in ACCOUNT_RARITY_PATTERNS.items():
        pattern = pattern_data[0]
        score = pattern_data[1]
        if re.search(pattern, account_id):
            rarity_score += score
            detected_patterns.append(rarity_type)

    account_id_digits = [int(d) for d in account_id if d.isdigit()]

    if len(set(account_id_digits)) == 1 and len(account_id_digits) >= 4:
        rarity_score += 5
        detected_patterns.append("UNIFORM_DIGITS")

    if len(account_id_digits) >= 4:
        differences = [account_id_digits[i+1] - account_id_digits[i] for i in range(len(account_id_digits)-1)]
        if len(set(differences)) == 1:
            rarity_score += 4
            detected_patterns.append("ARITHMETIC_SEQUENCE")

    if len(account_id) <= 8 and account_id.isdigit() and int(account_id) < 1000000:
        rarity_score += 3
        detected_patterns.append("LOW_ACCOUNT_ID")

    if rarity_score >= RARITY_SCORE_THRESHOLD:
        reason = f"Account ID {account_id} - Score: {rarity_score} - Patterns: {', '.join(detected_patterns)}"
        return True, "RARE_ACCOUNT", reason, rarity_score

    return False, None, None, rarity_score

def check_account_couples(account_data, thread_id):
    account_id = account_data.get("account_id", "")
    if account_id == "N/A" or not account_id:
        return False, None, None

    with COUPLES_LOCK:
        for stored_id, stored_data in list(POTENTIAL_COUPLES.items()):
            stored_account_id = stored_data.get('account_id', '')
            if stored_account_id:
                try:
                    if abs(int(account_id) - int(stored_account_id)) == 1:
                        partner_data = stored_data
                        del POTENTIAL_COUPLES[stored_id]
                        return True, f"Sequential: {account_id} & {stored_account_id}", partner_data
                except:
                    pass

                if account_id == stored_account_id[::-1]:
                    partner_data = stored_data
                    del POTENTIAL_COUPLES[stored_id]
                    return True, f"Mirror: {account_id} & {stored_account_id}", partner_data

        POTENTIAL_COUPLES[account_id] = {
            'uid': account_data.get('uid', ''),
            'account_id': account_id,
            'name': account_data.get('name', ''),
            'password': account_data.get('password', ''),
            'region': account_data.get('region', ''),
            'thread_id': thread_id,
            'timestamp': datetime.now().isoformat()
        }

    return False, None, None

# Helpers
def generate_exponent_number():
    exponent_digits = {'0': '⁰', '1': '¹', '2': '²', '3': '³', '4': '⁴', '5': '⁵', '6': '⁶', '7': '⁷', '8': '⁸', '9': '⁹'}
    number = random.randint(1, 99999)
    number_str = f"{number:05d}"
    return ''.join(exponent_digits[digit] for digit in number_str)

def generate_random_name(base_name):
    return f"{base_name[:7]}{generate_exponent_number()}"

def generate_custom_password(prefix):
    characters = string.ascii_uppercase + string.digits
    random_part = ''.join(random.choice(characters) for _ in range(5))
    return f"{prefix}_RIZER_{random_part}"

def encode_string(original):
    keystream = [0x30, 0x30, 0x30, 0x32, 0x30, 0x31, 0x37, 0x30, 0x30, 0x30, 0x30, 0x30, 0x32, 0x30, 0x31, 0x37,
                 0x30, 0x30, 0x30, 0x30, 0x30, 0x32, 0x30, 0x31, 0x37, 0x30, 0x30, 0x30, 0x30, 0x30, 0x32, 0x30]
    encoded = ""
    for i in range(len(original)):
        orig_byte = ord(original[i])
        key_byte = keystream[i % len(keystream)]
        result_byte = orig_byte ^ key_byte
        encoded += chr(result_byte)
    return {"open_id": original, "field_14": encoded}

def to_unicode_escaped(s):
    return ''.join(c if 32 <= ord(c) <= 126 else '\\u{:04x}'.format(ord(c)) for c in s)

def smart_delay():
    time.sleep(random.uniform(0.1, 0.3))

# FIXED AutoActivator
class FixedAutoActivator:
    def __init__(self, max_workers=5, turbo_mode=True):
        self.key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
        self.iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
        self.max_workers = max_workers
        self.turbo_mode = turbo_mode
        self.session = requests.Session()
        self.successful = 0
        self.failed = 0
        self.stats_lock = threading.Lock()
        self.stop_execution = False
        self.unauthorized_count = 0
        self.max_unauthorized_before_stop = 10

        self.adapters = [
            requests.adapters.HTTPAdapter(pool_connections=100, pool_maxsize=100, max_retries=1),
            requests.adapters.HTTPAdapter(pool_connections=50, pool_maxsize=50, max_retries=0),
            requests.adapters.HTTPAdapter(pool_connections=75, pool_maxsize=75, max_retries=2)
        ]
        self.rotate_adapter()

    def rotate_adapter(self):
        adapter = random.choice(self.adapters)
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)

    def generate_fingerprint(self):
        user_agents = [
            'Mozilla/5.0 (Linux; Android 10; SM-G973F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Mobile Safari/537.36',
            'Mozilla/5.0 (Linux; Android 11; Pixel 5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.115 Mobile Safari/537.36',
            'Mozilla/5.0 (Linux; Android 12; SM-G998B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Mobile Safari/537.36'
        ]

        headers = {
            'User-Agent': random.choice(user_agents),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
        }

        self.session.headers.update(headers)
        self.rotate_adapter()

    def smart_delay(self):
        delay = random.uniform(0.05, 0.15) if self.turbo_mode else random.uniform(0.1, 0.3)
        time.sleep(delay)
        self.generate_fingerprint()

    def retry_delay(self, attempt):
        base = 1.5 if self.turbo_mode else 2
        delay = (base ** attempt) * random.uniform(0.8, 1.5)
        time.sleep(delay)

    def encrypt_api(self, plain_text):
        try:
            plain_text = bytes.fromhex(plain_text)
            cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
            cipher_text = cipher.encrypt(pad(plain_text, AES.block_size))
            return cipher_text.hex()
        except:
            return None

    def parse_major_login_response(self, serialized_data):
        try:
            if PROTOBUF_AVAILABLE:
                try:
                    MajorLogRes = MajorLoginRes_pb2.MajorLoginRes()
                    MajorLogRes.ParseFromString(serialized_data)
                    if MajorLogRes.token and MajorLogRes.token.startswith("eyJ"):
                        return MajorLogRes.token
                except:
                    pass

            text = serialized_data.decode('utf-8', errors='ignore')
            jwt_start = text.find("eyJ")
            if jwt_start != -1:
                jwt_token = text[jwt_start:]
                parts = jwt_token.split('.')
                if len(parts) >= 3:
                    jwt_token = parts[0] + '.' + parts[1] + '.' + parts[2][:43]
                    return jwt_token
            return None
        except:
            return None

    def guest_token(self, uid, password, region='IND'):
        if self.stop_execution:
            return None, None

        region_config = ACTIVATION_REGIONS.get(region, ACTIVATION_REGIONS['IND'])
        url = region_config['guest_url']
        data = {
            "uid": f"{uid}",
            "password": f"{password}",
            "response_type": "token",
            "client_type": "2",
            "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
            "client_id": "100067",
        }
        max_attempts = 4 if self.turbo_mode else 3
        for attempt in range(max_attempts):
            try:
                if self.stop_execution:
                    return None, None

                self.smart_delay()
                timeout = 8 if self.turbo_mode else 15
                response = self.session.post(url, data=data, timeout=timeout, verify=False)

                if response.status_code == 200:
                    data_json = response.json()
                    return data_json.get('access_token'), data_json.get('open_id')
                elif response.status_code == 429:
                    self.retry_delay(attempt)
                    continue
                elif response.status_code == 401:
                    with self.stats_lock:
                        self.unauthorized_count += 1
                        if self.unauthorized_count >= self.max_unauthorized_before_stop:
                            self.stop_execution = True
                    return None, None
            except:
                pass
            if attempt < max_attempts - 1:
                self.retry_delay(attempt)
        return None, None

    def major_login(self, access_token, open_id, region='IND'):
        if self.stop_execution:
            return None

        region_config = ACTIVATION_REGIONS.get(region, ACTIVATION_REGIONS['IND'])
        url = region_config['major_login_url']

        headers = {
            'X-Unity-Version': '2018.4.11f1',
            'ReleaseVersion': 'OB52',
            'Content-Type': 'application/x-www-form-urlencoded',
            'X-GA': 'v1 1',
            'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 7.1.2; ASUS_Z01QD Build/QKQ1.190825.002)',
            'Host': 'loginbp.ggblueshark.com',
            'Connection': 'Keep-Alive',
        }

        payload_template = bytes.fromhex(
            '1a13323032352d30372d33302031313a30323a3531220966726565206669726528013a07312e3131342e32422c416e64726f6964204f5320372e312e32202f204150492d323320284e32473438482f373030323530323234294a0848616e6468656c645207416e64726f69645a045749464960c00c68840772033332307a1f41524d7637205646507633204e454f4e20564d48207c2032343635207c203480019a1b8a010f416472656e6f2028544d292036343092010d4f70656e474c20455320332e319a012b476f6f676c657c31663361643662372d636562342d343934622d383730622d623164616364373230393131a2010c3139372e312e31322e313335aa0102656eb201203939366136323964626364623339363462653662363937386635643831346462ba010134c2010848616e6468656c64ca011073616d73756e6720534d2d473935354eea014066663930633037656239383135616633306134336234613966363031393531366530653463373033623434303932353136643064656661346365663531663261f00101ca0207416e64726f6964d2020457494649ca03203734323862323533646566633136343031386336303461316562626665626466e003daa907e803899b07f003bf0ff803ae088004999b078804daa9079004999b079804daa907c80403d204262f646174612f6170702f636f6d2e6474732e667265656669726574682d312f6c69622f61726de00401ea044832303837663631633139663537663261663465376665666630623234643964397c2f646174612f6170702f636f6d2e6474732e667265656669726574682d312f626173652e61706bf00403f804018a050233329a050a32303139313138363933a80503b205094f70656e474c455332b805ff7fc00504e005dac901ea0507616e64726f6964f2055c4b71734854394748625876574c6668437950416c52526873626d43676542557562555551317375746d525536634e30524f3751453141486e496474385963784d614c575437636d4851322b7374745279377830663935542b6456593d8806019006019a060134a2060134b2061e40001147550d0c074f530b4d5c584d57416657545a065f2a091d6a0d5033'
        )

        OLD_OPEN_ID = b"996a629dbcdb3964be6b6978f5d814db"
        OLD_ACCESS_TOKEN = b"ff90c07eb9815af30a43b4a9f6019516e0e4c703b44092516d0defa4cef51f2a"

        payload = payload_template.replace(OLD_OPEN_ID, open_id.encode())
        payload = payload.replace(OLD_ACCESS_TOKEN, access_token.encode())

        encrypted_payload = self.encrypt_api(payload.hex())
        if not encrypted_payload:
            return None

        final_payload = bytes.fromhex(encrypted_payload)

        max_attempts = 3
        for attempt in range(max_attempts):
            try:
                if self.stop_execution:
                    return None

                self.smart_delay()
                timeout = 12 if self.turbo_mode else 18
                response = self.session.post(url, headers=headers, data=final_payload, verify=False, timeout=timeout)

                if response.status_code == 200 and len(response.content) > 0:
                    return response.content
                elif response.status_code == 429:
                    self.retry_delay(attempt)
                    continue
            except:
                pass
            if attempt < max_attempts - 1:
                self.retry_delay(attempt)
        return None

    def create_login_data_payload(self, jwt_token, access_token):
        try:
            parts = jwt_token.split('.')
            if len(parts) < 2:
                return None

            payload_part = parts[1]
            padding = 4 - len(payload_part) % 4
            if padding != 4:
                payload_part += '=' * padding

            decoded = base64.urlsafe_b64decode(payload_part)
            token_data = json.loads(decoded)

            external_id = token_data.get('external_id', '')
            signature_md5 = token_data.get('signature_md5', '')

            if not external_id or not signature_md5:
                return None

            now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

            payload = bytes.fromhex(
                "1a13323032352d30372d33302031313a30323a3531220966726565206669726528013a07312e3131342e32422c416e64726f6964204f5320372e312e32202f204150492d323320284e32473438482f373030323530323234294a0848616e6468656c645207416e64726f69645a045749464960c00c68840772033332307a1f41524d7637205646507633204e454f4e20564d48207c2032343635207c203480019a1b8a010f416472656e6f2028544d292036343092010d4f70656e474c20455320332e319a012b476f6f676c657c31663361643662372d636562342d343934622d383730622d623164616364373230393131a2010c3139372e312e31322e313335aa0102656eb201203939366136323964626364623339363462653662363937386635643831346462ba010134c2010848616e6468656c64ca011073616d73756e6720534d2d473935354eea014066663930633037656239383135616633306134336234613966363031393531366530653463373033623434303932353136643064656661346365663531663261f00101ca0207416e64726f6964d2020457494649ca03203734323862323533646566633136343031386336303461316562626665626466e003daa907e803899b07f003bf0ff803ae088004999b078804daa9079004999b079804daa907c80403d204262f646174612f6170702f636f6d2e6474732e667265656669726574682d312f6c69622f61726de00401ea044832303837663631633139663537663261663465376665666630623234643964397c2f646174612f6170702f636f6d2e6474732e667265656669726574682d312f626173652e61706bf00403f804018a050233329a050a32303139313138363933a80503b205094f70656e474c455332b805ff7fc00504e005dac901ea0507616e64726f6964f2055c4b71734854394748625876574c6668437950416c52526873626d43676542557562555551317375746d525536634e30524f3751453141486e496474385963784d614c575437636d4851322b7374745279377830663935542b6456593d8806019006019a060134a2060134b2061e40001147550d0c074f530b4d5c584d57416657545a065f2a091d6a0d5033"
            )

            payload = payload.replace(b"2025-07-30 11:02:51", now.encode())
            payload = payload.replace(b"ff90c07eb9815af30a43b4a9f6019516e0e4c703b44092516d0defa4cef51f2a", access_token.encode("UTF-8"))
            payload = payload.replace(b"996a629dbcdb3964be6b6978f5d814db", external_id.encode("UTF-8"))
            payload = payload.replace(b"7428b253defc164018c604a1ebbfebdf", signature_md5.encode("UTF-8"))

            encrypted = self.encrypt_api(payload.hex())
            if encrypted:
                return bytes.fromhex(encrypted)
        except:
            pass
        return None

    def get_login_data(self, jwt_token, payload, region='IND'):
        if self.stop_execution or not payload:
            return False

        region_config = ACTIVATION_REGIONS.get(region, ACTIVATION_REGIONS['IND'])
        url = region_config['get_login_data_url']
        client_host = region_config['client_host']

        headers = {
            'Expect': '100-continue',
            'Authorization': f'Bearer {jwt_token}',
            'X-Unity-Version': '2018.4.11f1',
            'X-GA': 'v1 1',
            'ReleaseVersion': 'OB52',
            'Content-Type': 'application/x-www-form-urlencoded',
            'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 9; G011A Build/PI)',
            'Host': client_host,
            'Connection': 'close',
            'Accept-Encoding': 'gzip, deflate, br',
        }

        max_attempts = 2
        for attempt in range(max_attempts):
            try:
                if self.stop_execution:
                    return False

                self.smart_delay()
                timeout = 8 if self.turbo_mode else 12
                response = self.session.post(url, headers=headers, data=payload, verify=False, timeout=timeout)

                if response.status_code == 200:
                    return True
                elif response.status_code == 401:
                    with self.stats_lock:
                        self.unauthorized_count += 1
                        if self.unauthorized_count >= self.max_unauthorized_before_stop:
                            self.stop_execution = True
                    return False
                elif response.status_code == 404:
                    return False
            except:
                pass
            if attempt < max_attempts - 1:
                self.retry_delay(attempt)
        return False

    def activate_account(self, account_data):
        uid = account_data.get('uid')
        password = account_data.get('password')
        region = account_data.get('region', 'IND')

        if not uid or not password:
            return False

        if region not in ACTIVATION_REGIONS:
            region = 'IND'

        access_token, open_id = self.guest_token(uid, password, region)
        if not access_token or not open_id:
            return False

        major_login_response = self.major_login(access_token, open_id, region)
        if not major_login_response:
            return False

        jwt_token = self.parse_major_login_response(major_login_response)
        if not jwt_token:
            return False

        payload = self.create_login_data_payload(jwt_token, access_token)
        if not payload:
            return False

        return self.get_login_data(jwt_token, payload, region)

# Global activator
auto_activator = FixedAutoActivator(max_workers=5, turbo_mode=True)

def create_account(region, account_name, password_prefix, session):
    if EXIT_FLAG:
        return None
    try:
        current_api = random.choice(API_POOL)
        app_id = current_api["id"]
        secret_key = current_api["key"]

        password = generate_custom_password(password_prefix)
        data = f"password={password}&client_type=2&source=2&app_id={app_id}"
        message = data.encode('utf-8')
        signature = hmac.new(secret_key, message, hashlib.sha256).hexdigest()

        url = f"https://{app_id}.connect.garena.com/oauth/guest/register"
        headers = {
            "User-Agent": "GarenaMSDK/4.0.19P8(ASUS_Z01QD ;Android 12;en;US;)",
            "Authorization": "Signature " + signature,
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept-Encoding": "gzip",
            "Connection": "Keep-Alive"
        }

        response = session.post(url, headers=headers, data=data, timeout=15, verify=False)
        response.raise_for_status()

        response_json = response.json()

        if 'uid' in response_json:
            uid = response_json['uid']
            smart_delay()
            return get_token(uid, password, region, account_name, password_prefix, current_api, session)
        return None
    except Exception as e:
        smart_delay()
        return None

def get_token(uid, password, region, account_name, password_prefix, api_config, session):
    if EXIT_FLAG:
        return None
    try:
        app_id = api_config["id"]
        secret_key = api_config["key"]

        url = f"https://{app_id}.connect.garena.com/oauth/guest/token/grant"
        headers = {
            "Accept-Encoding": "gzip",
            "Connection": "Keep-Alive",
            "Content-Type": "application/x-www-form-urlencoded",
            "Host": f"{app_id}.connect.garena.com",
            "User-Agent": "GarenaMSDK/4.0.19P8(ASUS_Z01QD ;Android 12;en;US;)",
        }
        body = {
            "uid": uid,
            "password": password,
            "response_type": "token",
            "client_type": "2",
            "client_secret": secret_key.hex() if isinstance(secret_key, bytes) else secret_key,
            "client_id": app_id
        }

        response = session.post(url, headers=headers, data=body, timeout=15, verify=False)
        response.raise_for_status()

        response_json = response.json()

        if 'open_id' in response_json:
            open_id = response_json['open_id']
            access_token = response_json["access_token"]

            result = encode_string(open_id)
            field = to_unicode_escaped(result['field_14'])
            field = codecs.decode(field, 'unicode_escape').encode('latin1')
            smart_delay()
            return major_register(access_token, open_id, field, uid, password, region, account_name, password_prefix, api_config, session)
        return None
    except Exception as e:
        smart_delay()
        return None

def major_register(access_token, open_id, field, uid, password, region, account_name, password_prefix, api_config, session):
    if EXIT_FLAG:
        return None
    try:
        if region.upper() in ["ME", "TH"]:
            url = "https://loginbp.common.ggbluefox.com/MajorRegister"
            host = "loginbp.common.ggbluefox.com"
        else:
            url = "https://loginbp.ggblueshark.com/MajorRegister"
            host = "loginbp.ggblueshark.com"

        name = generate_random_name(account_name)

        headers = {
            "Accept-Encoding": "gzip",
            "Authorization": "Bearer",
            "Connection": "Keep-Alive",
            "Content-Type": "application/x-www-form-urlencoded",
            "Expect": "100-continue",
            "Host": host,
            "ReleaseVersion": "OB52",
            "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_I005DA Build/PI)",
            "X-GA": "v1 1",
            "X-Unity-Version": "2018.4."
        }

        lang_code = REGION_LANG.get(region.upper(), "en")
        payload = {
            1: name,
            2: access_token,
            3: open_id,
            5: 102000007,
            6: 4,
            7: 1,
            13: 1,
            14: field,
            15: lang_code,
            16: 1,
            17: 1
        }

        payload_bytes = CrEaTe_ProTo(payload)
        encrypted_payload = E_AEs(payload_bytes.hex())

        response = session.post(url, headers=headers, data=encrypted_payload, verify=False, timeout=15)

        if response.status_code == 200:
            login_result = perform_major_login(uid, password, access_token, open_id, region, session)
            account_id = login_result.get("account_id", "N/A")
            jwt_token = login_result.get("jwt_token", "")

            return {
                "uid": uid,
                "password": password,
                "name": name,
                "region": region,
                "status": "success",
                "account_id": account_id,
                "jwt_token": jwt_token,
                "api_label": api_config["label"]
            }
        return None
    except Exception as e:
        smart_delay()
        return None

def perform_major_login(uid, password, access_token, open_id, region, session):
    try:
        lang = REGION_LANG.get(region.upper(), "en")

        if region.upper() in ["ME", "TH"]:
            url = "https://loginbp.common.ggbluefox.com/MajorLogin"
            host = "loginbp.common.ggbluefox.com"
        else:
            url = "https://loginbp.ggblueshark.com/MajorLogin"
            host = "loginbp.ggblueshark.com"

        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        payload_fields = {
            1: now, 2: "free fire", 3: 1, 4: "1.114.13",
            5: "Android OS 9 / API-28 (PI/rel.cjw.20220518.114133)",
            6: "Handheld", 7: "Android", 8: "WIFI", 9: 300,
            10: "ARMv7 VFPv3 NEON VMH | 2465 | 2", 11: 2019,
            12: "Adreno (TM) 640", 13: "OpenGL ES 3.2",
            14: "Google|1f3ad6b7-ceb4-494b-870b-b1dacd720911",
            15: "197.1.12.135", 16: lang, 17: open_id, 18: 1,
            19: "Handheld", 20: "samsung SM-G955F",
            21: access_token, 22: 1, 23: "Android", 24: "WIFI",
            25: "7428b253defc164018c604a1ebbfebdf", 26: 100000,
            27: 999999, 28: 2999, 29: 2222, 30: 1000,
            31: 999999, 32: 100000, 33: 3,
            34: "/data/app/com.dts.freefireth-1/lib/arm",
            35: 1, 36: "2087f61c19f57f2af4e7feff0b24d9d9|/data/app/com.dts.freefireth-1/base.apk",
            37: 3, 38: 1, 39: "32", 40: "2019118693",
            41: 3, 42: "OpenGLES2", 43: 16383, 44: 4,
            45: 4, 46: 18550, 47: "android",
            48: "KqsHT9GHbXvWLfhcyPAlRRhsbmCgeBuubUUQ1sutmRU6cN0RO7QE1AHnIdt8YcxMaLWT7cmHQ2+sttRy7x0f95T+dVY="
        }

        payload_bytes = CrEaTe_ProTo(payload_fields)
        encrypted = encrypt_api(payload_bytes.hex())

        if not encrypted:
            return {"account_id": "N/A", "jwt_token": ""}

        final_payload = bytes.fromhex(encrypted)

        headers = {
            "Accept-Encoding": "gzip",
            "Authorization": "Bearer",
            "Connection": "Keep-Alive",
            "Content-Type": "application/x-www-form-urlencoded",
            "Expect": "100-continue",
            "Host": host,
            "ReleaseVersion": "OB52",
            "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_I005DA Build/PI)",
            "X-GA": "v1 1",
            "X-Unity-Version": "2018.4.11f1"
        }

        response = session.post(url, headers=headers, data=final_payload, verify=False, timeout=15)

        if response.status_code == 200 and len(response.content) > 0:
            try:
                text = response.content.decode('utf-8', errors='ignore')
                jwt_start = text.find("eyJ")
                if jwt_start != -1:
                    jwt_token = text[jwt_start:]
                    parts = jwt_token.split('.')
                    if len(parts) >= 3:
                        jwt_token = parts[0] + '.' + parts[1] + '.' + parts[2][:43]
                        account_id = decode_jwt_token(jwt_token)
                        return {"account_id": account_id, "jwt_token": jwt_token}
            except:
                pass

        return {"account_id": "N/A", "jwt_token": ""}
    except:
        return {"account_id": "N/A", "jwt_token": ""}

def process_single_account(region, account_name, password_prefix, total_accounts, thread_id, session):
    global SUCCESS_COUNTER, RARE_COUNTER, COUPLES_COUNTER, ACTIVATED_COUNTER, FAILED_ACTIVATION_COUNTER

    if EXIT_FLAG:
        return None

    with LOCK:
        if SUCCESS_COUNTER >= total_accounts:
            return None

    account_result = create_account(region, account_name, password_prefix, session)
    if not account_result:
        return None

    account_id = account_result.get("account_id", "N/A")
    api_label = account_result.get("api_label", "Unknown")
    account_result['thread_id'] = thread_id

    with LOCK:
        SUCCESS_COUNTER += 1
        current_count = SUCCESS_COUNTER

    is_rare, rarity_type, rarity_reason, rarity_score = check_account_rarity(account_result)
    if is_rare:
        with LOCK:
            RARE_COUNTER += 1
            ACTIVATION_STATS['rare_accounts'] += 1
        account_result['rarity'] = {
            'type': rarity_type,
            'score': rarity_score,
            'reason': rarity_reason
        }
        with STORAGE_LOCK:
            region_key = account_result['region']
            if region_key not in RARE_ACCOUNTS_STORAGE:
                RARE_ACCOUNTS_STORAGE[region_key] = []
            RARE_ACCOUNTS_STORAGE[region_key].append(account_result)

    is_couple, couple_reason, partner_data = check_account_couples(account_result, thread_id)
    if is_couple and partner_data:
        with LOCK:
            COUPLES_COUNTER += 1
            ACTIVATION_STATS['couples_found'] += 1
        account_result['couple'] = {
            'reason': couple_reason,
            'partner': partner_data
        }
        with STORAGE_LOCK:
            region_key = account_result['region']
            if region_key not in COUPLES_ACCOUNTS_STORAGE:
                COUPLES_ACCOUNTS_STORAGE[region_key] = []
            COUPLES_ACCOUNTS_STORAGE[region_key].append({
                'account1': account_result,
                'account2': partner_data,
                'reason': couple_reason
            })

    with STORAGE_LOCK:
        region_key = account_result['region']
        if region_key not in ACCOUNTS_STORAGE:
            ACCOUNTS_STORAGE[region_key] = []
        ACCOUNTS_STORAGE[region_key].append(account_result)

    if account_id != "N/A":
        try:
            activator = FixedAutoActivator(max_workers=1, turbo_mode=True)
            success = activator.activate_account(account_result)

            with LOCK:
                ACTIVATION_STATS['total_processed'] += 1

                if success:
                    ACTIVATED_COUNTER += 1
                    ACTIVATION_STATS['successful_activations'] += 1
                    account_result['activation'] = {
                        'status': 'success',
                        'timestamp': datetime.now().isoformat(),
                        'message': 'Account activated successfully'
                    }

                    with STORAGE_LOCK:
                        if region_key not in ACTIVATED_ACCOUNTS_STORAGE:
                            ACTIVATED_ACCOUNTS_STORAGE[region_key] = []
                        ACTIVATED_ACCOUNTS_STORAGE[region_key].append(account_result)
                else:
                    FAILED_ACTIVATION_COUNTER += 1
                    ACTIVATION_STATS['failed_activations'] += 1
                    account_result['activation'] = {
                        'status': 'failed',
                        'timestamp': datetime.now().isoformat(),
                        'message': 'Activation failed'
                    }

                    with STORAGE_LOCK:
                        if region_key not in FAILED_ACTIVATION_STORAGE:
                            FAILED_ACTIVATION_STORAGE[region_key] = []
                        FAILED_ACTIVATION_STORAGE[region_key].append(account_result)
        except Exception as e:
            with LOCK:
                FAILED_ACTIVATION_COUNTER += 1
                ACTIVATION_STATS['failed_activations'] += 1
            account_result['activation'] = {
                'status': 'error',
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }
    else:
        account_result['activation'] = {
            'status': 'skipped',
            'reason': 'No account ID available'
        }

    return account_result

def generate_accounts_batch(region, account_name, password_prefix, count):
    global SUCCESS_COUNTER, RARE_COUNTER, COUPLES_COUNTER, ACTIVATED_COUNTER, FAILED_ACTIVATION_COUNTER, EXIT_FLAG

    SUCCESS_COUNTER = 0
    RARE_COUNTER = 0
    COUPLES_COUNTER = 0
    ACTIVATED_COUNTER = 0
    FAILED_ACTIVATION_COUNTER = 0
    ACTIVATION_STATS['total_processed'] = 0
    ACTIVATION_STATS['successful_activations'] = 0
    ACTIVATION_STATS['failed_activations'] = 0
    ACTIVATION_STATS['rare_accounts'] = 0
    ACTIVATION_STATS['couples_found'] = 0
    EXIT_FLAG = False

    POTENTIAL_COUPLES.clear()

    results = []
    threads = []

    def worker(i):
        session = requests.Session()
        while not EXIT_FLAG:
            with LOCK:
                if SUCCESS_COUNTER >= count:
                    break

            result = process_single_account(region, account_name, password_prefix, count, i, session)
            if result:
                results.append(result)

            time.sleep(random.uniform(0.1, 0.3))

    num_threads = min(count, MAX_WORKERS)
    for i in range(num_threads):
        t = threading.Thread(target=worker, args=(i+1,))
        t.daemon = True
        t.start()
        threads.append(t)

    for t in threads:
        t.join(timeout=600)

    return results

# Flask Routes
HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>RIZER API v12.0 PURE FIXED</title>
    <style>
        body { font-family: Arial; background: linear-gradient(135deg, #1e3c72, #2a5298); color: white; padding: 40px; }
        .container { max-width: 1000px; margin: 0 auto; background: rgba(255,255,255,0.1); padding: 40px; border-radius: 20px; }
        h1 { text-align: center; }
        .endpoint { background: rgba(0,0,0,0.3); padding: 20px; border-radius: 10px; margin: 20px 0; font-family: monospace; }
        .param { color: #ffd700; }
        .download-btn { display: inline-block; background: #00ff88; color: #1e3c72; padding: 15px 30px; border-radius: 30px; text-decoration: none; font-weight: bold; margin: 10px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>RIZER API v12.0 PURE FIXED</h1>
        <p style="text-align: center; color: #00ff88;">ALL ISSUES RESOLVED</p>
        <div class="endpoint">
            /gen?<span class="param">rizername</span>=NAME&<span class="param">password</span>=PASS&<span class="param">count</span>=1-10000&<span class="param">region</span>=REGION
        </div>
        <p>Regions: IND, BD, PK, NA, LK, ID, TH, VN, ME, BR</p>
        <a href="/download/accounts?region=IND" class="download-btn">Download Accounts</a>
        <a href="/download/all" class="download-btn">Download ALL</a>
        <a href="/stats" class="download-btn">View Stats</a>
    </div>
</body>
</html>
"""

@app.route('/')
def home():
    return render_template_string(HTML_TEMPLATE)

@app.route('/gen')
def generate():
    start_time = time.time()
    rizername = request.args.get('rizername', '').strip()
    password = request.args.get('password', '').strip()
    count_str = request.args.get('count', '1').strip()
    region = request.args.get('region', 'IND').strip().upper()

    if not rizername:
        return jsonify({"status": "error", "message": "rizername required"}), 400
    if not password:
        return jsonify({"status": "error", "message": "password required"}), 400

    try:
        count = int(count_str)
        if count < 1 or count > MAX_ACCOUNTS_PER_REQUEST:
            return jsonify({"status": "error", "message": f"Count must be 1-{MAX_ACCOUNTS_PER_REQUEST}"}), 400
    except ValueError:
        return jsonify({"status": "error", "message": "Invalid count"}), 400

    valid_regions = list(ACTIVATION_REGIONS.keys())
    if region not in valid_regions:
        return jsonify({"status": "error", "message": f"Region must be one of {valid_regions}"}), 400

    try:
        accounts = generate_accounts_batch(region, rizername, password, count)
        elapsed_time = time.time() - start_time

        response_data = {
            "status": "success" if accounts else "error",
            "message": f"Generated {len(accounts)}/{count} accounts" if accounts else "No accounts generated",
            "summary": {
                "requested": count,
                "generated": len(accounts),
                "success_rate": f"{len(accounts)/count*100:.1f}%" if count > 0 else "0%",
                "region": region,
                "auto_activation": True,
                "threads_used": min(count, MAX_WORKERS),
                "rarity_threshold": RARITY_SCORE_THRESHOLD,
                "rare_found": RARE_COUNTER,
                "couples_found": COUPLES_COUNTER,
                "activated": ACTIVATED_COUNTER,
                "failed_activation": FAILED_ACTIVATION_COUNTER,
                "time_seconds": round(elapsed_time, 2),
                "speed": round(len(accounts)/elapsed_time, 2) if elapsed_time > 0 else 0
            },
            "activation_stats": ACTIVATION_STATS,
            "accounts": accounts
        }

        return app.response_class(
            response=json.dumps(response_data, indent=2, ensure_ascii=False),
            status=200 if accounts else 500,
            mimetype='application/json'
        )
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/download/accounts')
def download_accounts():
    region = request.args.get('region', 'IND').upper()
    with STORAGE_LOCK:
        data = ACCOUNTS_STORAGE.get(region, [])
    json_data = json.dumps(data, indent=2, ensure_ascii=False)
    buffer = io.BytesIO(json_data.encode('utf-8'))
    buffer.seek(0)
    return send_file(buffer, mimetype='application/json', as_attachment=True, download_name=f'accounts-{region}.json')

@app.route('/download/all')
def download_all():
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
        with STORAGE_LOCK:
            for region, accounts in ACCOUNTS_STORAGE.items():
                if accounts:
                    zf.writestr(f'accounts-{region}.json', json.dumps(accounts, indent=2, ensure_ascii=False))
            for region, accounts in RARE_ACCOUNTS_STORAGE.items():
                if accounts:
                    zf.writestr(f'rare-{region}.json', json.dumps(accounts, indent=2, ensure_ascii=False))
            for region, couples in COUPLES_ACCOUNTS_STORAGE.items():
                if couples:
                    zf.writestr(f'couples-{region}.json', json.dumps(couples, indent=2, ensure_ascii=False))
            for region, accounts in ACTIVATED_ACCOUNTS_STORAGE.items():
                if accounts:
                    zf.writestr(f'activated-{region}.json', json.dumps(accounts, indent=2, ensure_ascii=False))
            for region, accounts in FAILED_ACTIVATION_STORAGE.items():
                if accounts:
                    zf.writestr(f'failed-{region}.json', json.dumps(accounts, indent=2, ensure_ascii=False))
    buffer.seek(0)
    return send_file(buffer, mimetype='application/zip', as_attachment=True, download_name='rizer-accounts-all.zip')

@app.route('/health')
def health_check():
    return jsonify({
        "status": "healthy",
        "service": "RIZER API",
        "version": "12.0 PURE FIXED",
        "max_workers": MAX_WORKERS,
        "rarity_threshold": RARITY_SCORE_THRESHOLD,
        "max_accounts": MAX_ACCOUNTS_PER_REQUEST,
        "features": ["account_activation_fixed", "account_id_showing", "jwt_token_extraction", "auto_activation"],
        "regions": list(ACTIVATION_REGIONS.keys()),
        "protobuf_available": PROTOBUF_AVAILABLE
    })

@app.route('/stats')
def stats():
    with STORAGE_LOCK:
        return jsonify({
            "accounts": {k: len(v) for k, v in ACCOUNTS_STORAGE.items()},
            "rare": {k: len(v) for k, v in RARE_ACCOUNTS_STORAGE.items()},
            "couples": {k: len(v) for k, v in COUPLES_ACCOUNTS_STORAGE.items()},
            "activated": {k: len(v) for k, v in ACTIVATED_ACCOUNTS_STORAGE.items()},
            "failed": {k: len(v) for k, v in FAILED_ACTIVATION_STORAGE.items()},
            "activation_stats": ACTIVATION_STATS
        })

@app.route('/clear')
def clear_storage():
    global SUCCESS_COUNTER, RARE_COUNTER, COUPLES_COUNTER, ACTIVATED_COUNTER, FAILED_ACTIVATION_COUNTER
    with STORAGE_LOCK:
        ACCOUNTS_STORAGE.clear()
        RARE_ACCOUNTS_STORAGE.clear()
        COUPLES_ACCOUNTS_STORAGE.clear()
        ACTIVATED_ACCOUNTS_STORAGE.clear()
        FAILED_ACTIVATION_STORAGE.clear()
        POTENTIAL_COUPLES.clear()
    SUCCESS_COUNTER = 0
    RARE_COUNTER = 0
    COUPLES_COUNTER = 0
    ACTIVATED_COUNTER = 0
    FAILED_ACTIVATION_COUNTER = 0
    ACTIVATION_STATS['total_processed'] = 0
    ACTIVATION_STATS['successful_activations'] = 0
    ACTIVATION_STATS['failed_activations'] = 0
    ACTIVATION_STATS['rare_accounts'] = 0
    ACTIVATION_STATS['couples_found'] = 0
    return jsonify({"status": "success", "message": "All storage cleared"})

@app.route('/activate', methods=['POST'])
def manual_activate():
    data = request.get_json()
    if not data:
        return jsonify({"status": "error", "message": "No data provided"}), 400
    uid = data.get('uid')
    password = data.get('password')
    region = data.get('region', 'IND')
    if not uid or not password:
        return jsonify({"status": "error", "message": "uid and password required"}), 400
    account_data = {
        'uid': uid,
        'password': password,
        'region': region,
        'name': data.get('name', 'Unknown'),
        'account_id': data.get('account_id', 'N/A')
    }
    try:
        activator = FixedAutoActivator(max_workers=1, turbo_mode=True)
        success = activator.activate_account(account_data)
        return jsonify({"status": "success", "activation_status": "success" if success else "failed", "account": account_data})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    print(f"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                    RIZER API v12.0 PURE FIXED                                ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  Port: {port:<69} ║
║  Max Workers: {MAX_WORKERS:<62} ║
║  Rarity Threshold: {RARITY_SCORE_THRESHOLD:<57} ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  FIXED: Account Activation | Account ID | JWT Token | Account Creation       ║
╚══════════════════════════════════════════════════════════════════════════════╝
    """)
    app.run(host='0.0.0.0', port=port, debug=False, threaded=True)
