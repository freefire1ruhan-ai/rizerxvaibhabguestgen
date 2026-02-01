#!/usr/bin/env python3
"""
RIZER GUEST ACCOUNT GENERATOR API - COMPLETE CONVERSION
Version: 10.3 ULTIMATE EDITION - ALL FEATURES FROM ACTRIZER.PY
File: ACTRIZER.py converted to Flask API
Total Features: 100% of original
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
from concurrent.futures import ThreadPoolExecutor, as_completed

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore")

# Install dependencies if missing
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

app = Flask(__name__)

# =============================================================================
# COMPLETE CONFIGURATION FROM ACTRIZER.PY (100%)
# =============================================================================

EXIT_FLAG = False
SUCCESS_COUNTER = 0
TARGET_ACCOUNTS = 0
RARE_COUNTER = 0
COUPLES_COUNTER = 0
ACTIVATED_COUNTER = 0
FAILED_ACTIVATION_COUNTER = 0
RARITY_SCORE_THRESHOLD = 2  # LOCKED TO 2 AS REQUESTED
MAX_ACCOUNTS_PER_REQUEST = 10000
MAX_WORKERS = 100  # LOCKED TO 100 THREADS
LOCK = threading.Lock()
AUTO_ACTIVATION_ENABLED = True

# Region Configuration (COMPLETE)
REGION_LANG = {
    "ME": "ar", "IND": "hi", "ID": "id", "VN": "vi", 
    "TH": "th", "BD": "bn", "PK": "ur", "TW": "zh", 
    "CIS": "ru", "SAC": "es", "BR": "pt"
}

# Activation Regions (COMPLETE)
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

# API Configuration (COMPLETE)
MAIN_HEX_KEY = "32656534343831396539623435393838343531343130363762323831363231383734643064356437616639643866376530306331653534373135623764316533"
API_POOL = [{"id": "100067", "key": bytes.fromhex(MAIN_HEX_KEY), "label": f"API {i:02d} ⚡"} for i in range(1, 8)]
GARENA = "UklaRVI="

# Thread-local storage
thread_local = threading.local()

# File locks and couples tracking (COMPLETE)
FILE_LOCKS = {}
POTENTIAL_COUPLES = {}
COUPLES_LOCK = threading.Lock()

# In-memory storage for API (replaces file storage)
ACCOUNTS_STORAGE = {}
RARE_ACCOUNTS_STORAGE = {}
COUPLES_ACCOUNTS_STORAGE = {}
ACTIVATED_ACCOUNTS_STORAGE = {}
FAILED_ACTIVATION_STORAGE = {}
STORAGE_LOCK = threading.Lock()

# =============================================================================
# CRYPTO FUNCTIONS (100% FROM ACTRIZER)
# =============================================================================

def EnC_Vr(N):
    """Encode varint - EXACT FROM ACTRIZER"""
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
    """Create variant field - EXACT FROM ACTRIZER"""
    field_header = (field_number << 3) | 0
    return EnC_Vr(field_header) + EnC_Vr(value)

def CrEaTe_LenGTh(field_number, value):
    """Create length-delimited field - EXACT FROM ACTRIZER"""
    field_header = (field_number << 3) | 2
    encoded_value = value.encode() if isinstance(value, str) else value
    return EnC_Vr(field_header) + EnC_Vr(len(encoded_value)) + encoded_value

def CrEaTe_ProTo(fields):
    """Create protobuf packet - EXACT FROM ACTRIZER"""
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
    """Encrypt using AES - EXACT FROM ACTRIZER"""
    Z = bytes.fromhex(Pc)
    key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
    iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
    K = AES.new(key, AES.MODE_CBC, iv)
    R = K.encrypt(pad(Z, AES.block_size))
    return R

def encrypt_api(plain_text):
    """Encrypt API payload - EXACT FROM ACTRIZER"""
    try:
        plain_text = bytes.fromhex(plain_text)
        key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
        iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
        cipher = AES.new(key, AES.MODE_CBC, iv)
        cipher_text = cipher.encrypt(pad(plain_text, AES.block_size))
        return cipher_text.hex()
    except Exception as e:
        print(f"Encryption error: {e}")
        return None

def decode_jwt_token(jwt_token):
    """Decode JWT to get account ID - EXACT FROM ACTRIZER"""
    try:
        parts = jwt_token.split('.')
        if len(parts) >= 2:
            payload_part = parts[1]
            padding = 4 - len(payload_part) % 4
            if padding != 4:
                payload_part += '=' * padding
            decoded = base64.urlsafe_b64decode(payload_part)
            data = json.loads(decoded)
            account_id = data.get('account_id') or data.get('external_id')
            if account_id:
                return str(account_id)
    except:
        pass
    return "N/A"

# =============================================================================
# RARITY & COUPLES DETECTION (100% FROM ACTRIZER)
# =============================================================================

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
    """Check account rarity - EXACT FROM ACTRIZER"""
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
    """Check for couples - EXACT FROM ACTRIZER"""
    account_id = account_data.get("account_id", "")
    if account_id == "N/A" or not account_id:
        return False, None, None

    with COUPLES_LOCK:
        for stored_id, stored_data in POTENTIAL_COUPLES.items():
            stored_account_id = stored_data.get('account_id', '')
            couple_found, reason = check_account_couple_patterns(account_id, stored_account_id)
            if couple_found:
                partner_data = stored_data
                del POTENTIAL_COUPLES[stored_id]
                return True, reason, partner_data

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

def check_account_couple_patterns(account_id1, account_id2):
    """Check couple patterns - EXACT FROM ACTRIZER"""
    if account_id1 and account_id2 and abs(int(account_id1) - int(account_id2)) == 1:
        return True, f"Sequential Account IDs: {account_id1} & {account_id2}"

    if account_id1 == account_id2[::-1]:
        return True, f"Mirror Account IDs: {account_id1} & {account_id2}"

    if account_id1 and account_id2:
        sum_acc = int(account_id1) + int(account_id2)
        if sum_acc % 1000 == 0 or sum_acc % 10000 == 0:
            return True, f"Complementary sum: {account_id1} + {account_id2} = {sum_acc}"

    love_numbers = ['520', '521', '1314', '3344']
    for love_num in love_numbers:
        if love_num in account_id1 and love_num in account_id2:
            return True, f"Both contain love number: {love_num}"

    return False, None

# =============================================================================
# ACCOUNT GENERATION HELPERS (100% FROM ACTRIZER)
# =============================================================================

def generate_exponent_number():
    """Generate exponent number - EXACT FROM ACTRIZER"""
    exponent_digits = {'0': '⁰', '1': '¹', '2': '²', '3': '³', '4': '⁴', '5': '⁵', '6': '⁶', '7': '⁷', '8': '⁸', '9': '⁹'}
    number = random.randint(1, 99999)
    number_str = f"{number:05d}"
    return ''.join(exponent_digits[digit] for digit in number_str)

def generate_random_name(base_name):
    """Generate random name - EXACT FROM ACTRIZER"""
    return f"{base_name[:7]}{generate_exponent_number()}"

def generate_custom_password(prefix):
    """Generate custom password - EXACT FROM ACTRIZER"""
    characters = string.ascii_uppercase + string.digits
    random_part = ''.join(random.choice(characters) for _ in range(5))
    return f"{prefix}_RIZER_{random_part}"

def encode_string(original):
    """Encode string - EXACT FROM ACTRIZER"""
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
    """Convert to unicode escaped - EXACT FROM ACTRIZER"""
    return ''.join(c if 32 <= ord(c) <= 126 else '\\u{:04x}'.format(ord(c)) for c in s)

def get_session():
    """Get thread-local session"""
    if not hasattr(thread_local, "session"):
        thread_local.session = requests.Session()
    return thread_local.session

def smart_delay():
    """Smart delay - EXACT FROM ACTRIZER"""
    time.sleep(random.uniform(0.1, 0.3))

# =============================================================================
# AUTO ACTIVATION CLASS (100% FROM ACTRIZER)
# =============================================================================

class AutoActivator:
    """Complete AutoActivator class from ACTRIZER"""
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

    def encrypt_api(self, plain_text):
        try:
            plain_text = bytes.fromhex(plain_text)
            cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
            cipher_text = cipher.encrypt(pad(plain_text, AES.block_size))
            return cipher_text.hex()
        except Exception as e:
            return None

    def parse_my_message(self, serialized_data):
        try:
            text = serialized_data.decode('utf-8', errors='ignore')
            jwt_start = text.find("eyJ")
            if jwt_start != -1:
                jwt_token = text[jwt_start:]
                second_dot = jwt_token.find(".", jwt_token.find(".") + 1)
                if second_dot != -1:
                    jwt_token = jwt_token[:second_dot + 44]
                    return jwt_token, None, None
            return None, None, None
        except:
            return None, None, None

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
        for attempt in range(3):
            try:
                timeout = 8 if self.turbo_mode else 15
                response = self.session.post(url, data=data, timeout=timeout, verify=False)
                if response.status_code == 200:
                    data_json = response.json()
                    return data_json.get('access_token'), data_json.get('open_id')
                elif response.status_code == 429:
                    time.sleep(2 ** attempt)
            except Exception as e:
                pass
            if attempt < 2:
                time.sleep(1)
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
            '1a13323032352d30372d33302031313a30323a3531220966726565206669726528013a07312e3132302e32422c416e64726f6964204f5320372e312e32202f204150492d323320284e32473438482f373030323530323234294a0848616e6468656c645207416e64726f69645a045749464960c00c68840772033332307a1f41524d7637205646507633204e454f4e20564d48207c2032343635207c203480019a1b8a010f416472656e6f2028544d292036343092010d4f70656e474c20455320332e319a012b476f6f676c657c31663361643662372d636562342d343934622d383730622d623164616364373230393131a2010c3139372e312e31322e313335aa0102656eb201203939366136323964626364623339363462653662363937386635643831346462ba010134c2010848616e6468656c64ea014066663930633037656239383135616633306134336234613966363031393531366530653463373033623434303932353136643064656661346365663531663261f00101ca0207416e64726f6964d2020457494649ca03203734323862323533646566633136343031386336303461316562626665626466e003daa907e803899b07f003bf0ff803ae088004999b078804daa9079004999b079804daa907c80403d204262f646174612f6170702f636f6d2e6474732e667265656669726574682d312f6c69622f61726de00401ea044832303837663631633139663537663261663465376665666630623234643964397c2f646174612f6170702f636f6d2e6474732e667265656669726574682d312f626173652e61706bf00403f804018a050233329a050a32303139313138363933b205094f70656e474c455332b805ff7fc00504e005dac901ea0507616e64726f6964f2055c4b71734854394748625876574c6668437950416c52526873626d43676542557562555551317375746d525536634e30524f3751453141486e496474385963784d614c575437636d4851322b7374745279377830663935542b6456593d8806019006019a060134a2060134'
        )
        OLD_OPEN_ID = b"996a629dbcdb3964be6b6978f5d814db"
        OLD_ACCESS_TOKEN = b"ff90c07eb9815af30a43b4a9f6019516e0e4c703b44092516d0defa4cef51f2a"
        payload = payload_template.replace(OLD_OPEN_ID, open_id.encode())
        payload = payload.replace(OLD_ACCESS_TOKEN, access_token.encode())
        encrypted_payload = self.encrypt_api(payload.hex())
        if not encrypted_payload:
            return None
        final_payload = bytes.fromhex(encrypted_payload)
        for attempt in range(3):
            try:
                timeout = 12 if self.turbo_mode else 18
                response = self.session.post(url, headers=headers, data=final_payload, verify=False, timeout=timeout)
                if response.status_code == 200 and len(response.content) > 0:
                    return response.content
            except:
                pass
            if attempt < 2:
                time.sleep(1)
        return None

    def GET_LOGIN_DATA(self, JWT_TOKEN, access_token, region='IND'):
        if self.stop_execution:
            return False

        region_config = ACTIVATION_REGIONS.get(region, ACTIVATION_REGIONS['IND'])
        url = region_config['get_login_data_url']
        client_host = region_config['client_host']

        try:
            token_payload_base64 = JWT_TOKEN.split('.')[1]
            token_payload_base64 += '=' * ((4 - len(token_payload_base64) % 4) % 4)
            decoded_payload = base64.urlsafe_b64decode(token_payload_base64).decode('utf-8')
            decoded_payload = json.loads(decoded_payload)
            NEW_EXTERNAL_ID = decoded_payload['external_id']
            SIGNATURE_MD5 = decoded_payload['signature_md5']
            now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

            payload = bytes.fromhex("1a13323032352d30372d33302031313a30323a3531220966726565206669726528013a07312e3132302e32422c416e64726f6964204f5320372e312e32202f204150492d323320284e32473438482f373030323530323234294a0848616e6468656c645207416e64726f69645a045749464960c00c68840772033332307a1f41524d7637205646507633204e454f4e20564d48207c2032343635207c203480019a1b8a010f416472656e6f2028544d292036343092010d4f70656e474c20455320332e319a012b476f6f676c657c31663361643662372d636562342d343934622d383730622d623164616364373230393131a2010c3139372e312e31322e313335aa0102656eb201203939366136323964626364623339363462653662363937386635643831346462ba010134c2010848616e6468656c64ea014066663930633037656239383135616633306134336234613966363031393531366530653463373033623434303932353136643064656661346365663531663261f00101ca0207416e64726f6964d2020457494649ca03203734323862323533646566633136343031386336303461316562626665626466e003daa907e803899b07f003bf0ff803ae088004999b078804daa9079004999b079804daa907c80403d204262f646174612f6170702f636f6d2e6474732e667265656669726574682d312f6c69622f61726de00401ea044832303837663631633139663537663261663465376665666630623234643964397c2f646174612f6170702f636f6d2e6474732e667265656669726574682d312f626173652e61706bf00403f804018a050233329a050a32303139313138363933b205094f70656e474c455332b805ff7fc00504e005dac901ea0507616e64726f6964f2055c4b71734854394748625876574c6668437950416c52526873626d43676542557562555551317375746d525536634e30524f3751453141486e496474385963784d614c575437636d4851322b7374745279377830663935542b6456593d8806019006019a060134a2060134")
            payload = payload.replace(b"2025-07-30 11:02:51", now.encode())
            payload = payload.replace(b"ff90c07eb9815af30a43b4a9f6019516e0e4c703b44092516d0defa4cef51f2a", access_token.encode("UTF-8"))
            payload = payload.replace(b"996a629dbcdb3964be6b6978f5d814db", NEW_EXTERNAL_ID.encode("UTF-8"))
            payload = payload.replace(b"7428b253defc164018c604a1ebbfebdf", SIGNATURE_MD5.encode("UTF-8"))
            PAYLOAD = payload.hex()
            PAYLOAD = self.encrypt_api(PAYLOAD)
            if not PAYLOAD:
                return False
            final_payload = bytes.fromhex(PAYLOAD)
        except:
            return False

        headers = {
            'Expect': '100-continue',
            'Authorization': f'Bearer {JWT_TOKEN}',
            'X-Unity-Version': '2018.4.11f1',
            'X-GA': 'v1 1',
            'ReleaseVersion': 'OB52',
            'Content-Type': 'application/x-www-form-urlencoded',
            'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 9; G011A Build/PI)',
            'Host': client_host,
            'Connection': 'close',
            'Accept-Encoding': 'gzip, deflate, br',
        }

        for attempt in range(2):
            try:
                timeout = 8 if self.turbo_mode else 12
                response = self.session.post(url, headers=headers, data=final_payload, verify=False, timeout=timeout)
                if response.status_code == 200:
                    return True
            except:
                pass
            if attempt < 1:
                time.sleep(1)
        return False

    def activate_account(self, account_data):
        """Activate a single account"""
        uid = account_data['uid']
        password = account_data['password']
        region = account_data.get('region', 'IND')

        if region not in ACTIVATION_REGIONS:
            region = 'IND'

        access_token, open_id = self.guest_token(uid, password, region)
        if not access_token or not open_id:
            return False

        major_login_response = self.major_login(access_token, open_id, region)
        if not major_login_response:
            return False

        jwt_token, key, iv = self.parse_my_message(major_login_response)
        if not jwt_token:
            return False

        activation_success = self.GET_LOGIN_DATA(jwt_token, access_token, region)
        return activation_success

# Global activator
auto_activator = AutoActivator(max_workers=5, turbo_mode=True)

# =============================================================================
# ACCOUNT CREATION FUNCTIONS (100% FROM ACTRIZER)
# =============================================================================

def create_acc(region, account_name, password_prefix, session, is_ghost=False):
    """Create guest account - EXACT FROM ACTRIZER"""
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

        if 'uid' in response.json():
            uid = response.json()['uid']
            smart_delay()
            return token(uid, password, region, account_name, password_prefix, current_api, session, is_ghost)
        return None
    except Exception as e:
        smart_delay()
        return None

def token(uid, password, region, account_name, password_prefix, api_config, session, is_ghost=False):
    """Get token - EXACT FROM ACTRIZER"""
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
            "client_secret": secret_key,
            "client_id": app_id
        }

        response = session.post(url, headers=headers, data=body, timeout=15, verify=False)
        response.raise_for_status()

        if 'open_id' in response.json():
            open_id = response.json()['open_id']
            access_token = response.json()["access_token"]

            result = encode_string(open_id)
            field = to_unicode_escaped(result['field_14'])
            field = codecs.decode(field, 'unicode_escape').encode('latin1')
            smart_delay()
            return Major_Regsiter(access_token, open_id, field, uid, password, region, account_name, password_prefix, api_config, session, is_ghost)
        return None
    except Exception as e:
        smart_delay()
        return None

def Major_Regsiter(access_token, open_id, field, uid, password, region, account_name, password_prefix, api_config, session, is_ghost=False):
    """Major Register - EXACT FROM ACTRIZER"""
    if EXIT_FLAG:
        return None
    try:
        if is_ghost:
            url = "https://loginbp.ggblueshark.com/MajorRegister"
        else:
            if region.upper() in ["ME", "TH"]:
                url = "https://loginbp.common.ggbluefox.com/MajorRegister"
            else:
                url = "https://loginbp.ggblueshark.com/MajorRegister"

        name = generate_random_name(account_name)

        headers = {
            "Accept-Encoding": "gzip",
            "Authorization": "Bearer",   
            "Connection": "Keep-Alive",
            "Content-Type": "application/x-www-form-urlencoded",
            "Expect": "100-continue",
            "Host": "loginbp.ggblueshark.com" if is_ghost or region.upper() not in ["ME", "TH"] else "loginbp.common.ggbluefox.com",
            "ReleaseVersion": "OB52",
            "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_I005DA Build/PI)",
            "X-GA": "v1 1",
            "X-Unity-Version": "2018.4."
        }

        lang_code = "pt" if is_ghost else REGION_LANG.get(region.upper(), "en")
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
            login_result = perform_major_login(uid, password, access_token, open_id, region, session, is_ghost)
            account_id = login_result.get("account_id", "N/A")
            jwt_token = login_result.get("jwt_token", "")

            return {
                "uid": uid, 
                "password": password, 
                "name": name, 
                "region": "GHOST" if is_ghost else region, 
                "status": "success",
                "account_id": account_id,
                "jwt_token": jwt_token,
                "api_label": api_config["label"]
            }
        return None
    except Exception as e:
        smart_delay()
        return None

def perform_major_login(uid, password, access_token, open_id, region, session, is_ghost=False):
    """Perform major login - EXACT FROM ACTRIZER"""
    try:
        lang = "pt" if is_ghost else REGION_LANG.get(region.upper(), "en")

        payload_parts = [
            b'\x1a\x132025-08-30 05:19:21"\tfree fire(\x01:\x081.114.13B2Android OS 9 / API-28 (PI/rel.cjw.20220518.114133)J\x08HandheldR\nATM MobilsZ\x04WIFI`\xb6\nh\xee\x05r\x03300z\x1fARMv7 VFPv3 NEON VMH | 2400 | 2\x80\x01\xc9\x0f\x8a\x01\x0fAdreno (TM) 640\x92\x01\rOpenGL ES 3.2\x9a\x01+Google|dfa4ab4b-9dc4-454e-8065-e70c733fa53f\xa2\x01\x0e105.235.139.91\xaa\x01\x02',
            lang.encode("ascii"),
            b'\xb2\x01 1d8ec0240ede109973f3321b9354b44d\xba\x01\x014\xc2\x01\x08Handheld\xca\x01\x10Asus ASUS_I005DA\xea\x01@afcfbf13334be42036e4f742c80b956344bed760ac91b3aff9b607a610ab4390\xf0\x01\x01\xca\x02\nATM Mobils\xd2\x02\x04WIFI\xca\x03 7428b253defc164018c604a1ebbfebdf\xe0\x03\xa8\x81\x02\xe8\x03\xf6\xe5\x01\xf0\x03\xaf\x13\xf8\x03\x84\x07\x80\x04\xe7\xf0\x01\x88\x04\xa8\x81\x02\x90\x04\xe7\xf0\x01\x98\x04\xa8\x81\x02\xc8\x04\x01\xd2\x04=/data/app/com.dts.freefireth-PdeDnOilCSFn37p1AH_FLg==/lib/arm\xe0\x04\x01\xea\x04_2087f61c19f57f2af4e7feff0b24d9d9|/data/app/com.dts.freefireth-PdeDnOilCSFn37p1AH_FLg==/base.apk\xf0\x04\x03\xf8\x04\x01\x8a\x05\x0232\x9a\x05\n2019118692\xb2\x05\tOpenGLES2\xb8\x05\xff\x7f\xc0\x05\x04\xe0\x05\xf3F\xea\x05\x07android\xf2\x05pKqsHT5ZLWrYljNb5Vqh//yFRlaPHSO9NWSQsVvOmdhEEn7W+VHNUK+Q+fduA3ptNrGB0Ll0LRz3WW0jOwesLj6aiU7sZ40p8BfUE/FI/jzSTwRe2\xf8\x05\xfb\xe4\x06\x88\x06\x01\x90\x06\x01\x9a\x06\x014\xa2\x06\x014\xb2\x06"GQ@O\x00\x0e^\x00D\x06UA\x0ePM\r\x13hZ\x07T\x06\x0cm\\V\x0ejYV;\x0bU5'
        ]

        payload = b''.join(payload_parts)

        if is_ghost:
            url = "https://loginbp.ggblueshark.com/MajorLogin"
        elif region.upper() in ["ME", "TH"]:
            url = "https://loginbp.common.ggbluefox.com/MajorLogin"
        else:
            url = "https://loginbp.ggblueshark.com/MajorLogin"

        headers = {
            "Accept-Encoding": "gzip",
            "Authorization": "Bearer",
            "Connection": "Keep-Alive",
            "Content-Type": "application/x-www-form-urlencoded",
            "Expect": "100-continue",
            "Host": "loginbp.ggblueshark.com" if is_ghost or region.upper() not in ["ME", "TH"] else "loginbp.common.ggbluefox.com",
            "ReleaseVersion": "OB52",
            "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_I005DA Build/PI)",
            "X-GA": "v1 1",
            "X-Unity-Version": "2018.4.11f1"
        }

        data = payload
        data = data.replace(b'afcfbf13334be42036e4f742c80b956344bed760ac91b3aff9b607a610ab4390', access_token.encode())
        data = data.replace(b'1d8ec0240ede109973f3321b9354b44d', open_id.encode())

        d = encrypt_api(data.hex())
        final_payload = bytes.fromhex(d)

        response = session.post(url, headers=headers, data=final_payload, verify=False, timeout=15)

        if response.status_code == 200 and len(response.text) > 10:
            jwt_start = response.text.find("eyJ")
            if jwt_start != -1:
                jwt_token = response.text[jwt_start:]
                second_dot = jwt_token.find(".", jwt_token.find(".") + 1)
                if second_dot != -1:
                    jwt_token = jwt_token[:second_dot + 44]
                    account_id = decode_jwt_token(jwt_token)
                    return {"account_id": account_id, "jwt_token": jwt_token}

        return {"account_id": "N/A", "jwt_token": ""}
    except:
        return {"account_id": "N/A", "jwt_token": ""}

# =============================================================================
# BATCH GENERATION (100% FROM ACTRIZER LOGIC)
# =============================================================================

def generate_single_account(region, account_name, password_prefix, total_accounts, thread_id, session, is_ghost=False):
    """Generate single account with all features - EXACT FROM ACTRIZER"""
    global SUCCESS_COUNTER, RARE_COUNTER, COUPLES_COUNTER, ACTIVATED_COUNTER, FAILED_ACTIVATION_COUNTER

    if EXIT_FLAG:
        return None

    with LOCK:
        if SUCCESS_COUNTER >= total_accounts:
            return None

    account_result = create_acc(region, account_name, password_prefix, session, is_ghost)
    if not account_result:
        return None

    account_id = account_result.get("account_id", "N/A")
    jwt_token = account_result.get("jwt_token", "")
    api_label = account_result.get("api_label", "Unknown")
    account_result['thread_id'] = thread_id

    with LOCK:
        SUCCESS_COUNTER += 1
        current_count = SUCCESS_COUNTER

    # Check rarity
    is_rare, rarity_type, rarity_reason, rarity_score = check_account_rarity(account_result)
    if is_rare:
        with LOCK:
            RARE_COUNTER += 1
        account_result['rarity'] = {
            'type': rarity_type,
            'score': rarity_score,
            'reason': rarity_reason
        }
        # Save to rare storage
        with STORAGE_LOCK:
            region_key = account_result['region']
            if region_key not in RARE_ACCOUNTS_STORAGE:
                RARE_ACCOUNTS_STORAGE[region_key] = []
            RARE_ACCOUNTS_STORAGE[region_key].append(account_result)

    # Check couples
    is_couple, couple_reason, partner_data = check_account_couples(account_result, thread_id)
    if is_couple and partner_data:
        with LOCK:
            COUPLES_COUNTER += 1
        account_result['couple'] = {
            'reason': couple_reason,
            'partner': partner_data
        }
        # Save to couples storage
        with STORAGE_LOCK:
            region_key = account_result['region']
            if region_key not in COUPLES_ACCOUNTS_STORAGE:
                COUPLES_ACCOUNTS_STORAGE[region_key] = []
            COUPLES_ACCOUNTS_STORAGE[region_key].append({
                'account1': account_result,
                'account2': partner_data,
                'reason': couple_reason
            })

    # Save to normal storage
    with STORAGE_LOCK:
        region_key = account_result['region']
        if region_key not in ACCOUNTS_STORAGE:
            ACCOUNTS_STORAGE[region_key] = []
        ACCOUNTS_STORAGE[region_key].append(account_result)

    # Auto-activation
    if AUTO_ACTIVATION_ENABLED and not is_ghost and account_id != "N/A":
        try:
            activator = AutoActivator(max_workers=1, turbo_mode=True)
            success = activator.activate_account(account_result)
            with LOCK:
                if success:
                    ACTIVATED_COUNTER += 1
                    account_result['activation'] = {'status': 'success'}
                    # Save to activated storage
                    with STORAGE_LOCK:
                        if region_key not in ACTIVATED_ACCOUNTS_STORAGE:
                            ACTIVATED_ACCOUNTS_STORAGE[region_key] = []
                        ACTIVATED_ACCOUNTS_STORAGE[region_key].append(account_result)
                else:
                    FAILED_ACTIVATION_COUNTER += 1
                    account_result['activation'] = {'status': 'failed'}
                    # Save to failed storage
                    with STORAGE_LOCK:
                        if region_key not in FAILED_ACTIVATION_STORAGE:
                            FAILED_ACTIVATION_STORAGE[region_key] = []
                        FAILED_ACTIVATION_STORAGE[region_key].append(account_result)
        except:
            pass

    return account_result

def generate_batch(region, account_name, password_prefix, count, is_ghost=False):
    """Generate batch with 100 threads - EXACT FROM ACTRIZER"""
    global SUCCESS_COUNTER, RARE_COUNTER, COUPLES_COUNTER, ACTIVATED_COUNTER, FAILED_ACTIVATION_COUNTER

    # Reset counters
    SUCCESS_COUNTER = 0
    RARE_COUNTER = 0
    COUPLES_COUNTER = 0
    ACTIVATED_COUNTER = 0
    FAILED_ACTIVATION_COUNTER = 0

    results = []

    def worker(i):
        session = requests.Session()
        accounts_generated = 0

        while not EXIT_FLAG:
            with LOCK:
                if SUCCESS_COUNTER >= count:
                    break

            result = generate_single_account(region, account_name, password_prefix, count, i, session, is_ghost)
            if result:
                results.append(result)
                accounts_generated += 1

            time.sleep(random.uniform(0.1, 0.5))

        return accounts_generated

    # Start threads
    threads = []
    for i in range(min(count, MAX_WORKERS)):
        t = threading.Thread(target=worker, args=(i+1,))
        t.daemon = True
        t.start()
        threads.append(t)

    # Wait for completion
    for t in threads:
        t.join(timeout=300)

    return results

# =============================================================================
# FLASK ROUTES
# =============================================================================

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>RIZER API v10.3 ULTIMATE</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            min-height: 100vh;
            color: white;
            padding: 40px;
        }
        .container {
            max-width: 1000px;
            margin: 0 auto;
            background: rgba(255,255,255,0.1);
            backdrop-filter: blur(10px);
            padding: 40px;
            border-radius: 20px;
            box-shadow: 0 8px 32px rgba(0,0,0,0.3);
        }
        h1 {
            text-align: center;
            font-size: 3em;
            margin-bottom: 10px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }
        .subtitle {
            text-align: center;
            opacity: 0.8;
            margin-bottom: 30px;
        }
        .endpoint {
            background: rgba(0,0,0,0.3);
            padding: 20px;
            border-radius: 10px;
            margin: 20px 0;
            font-family: 'Courier New', monospace;
            word-break: break-all;
            border-left: 4px solid #00ff88;
        }
        .param { color: #ffd700; font-weight: bold; }
        .features {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 15px;
            margin: 20px 0;
        }
        .feature {
            background: rgba(255,255,255,0.1);
            padding: 15px;
            border-radius: 10px;
            text-align: center;
        }
        .regions {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 10px;
            margin: 20px 0;
        }
        .region {
            background: rgba(255,255,255,0.2);
            padding: 10px;
            text-align: center;
            border-radius: 20px;
            font-weight: bold;
        }
        .warning {
            background: rgba(255,193,7,0.2);
            border-left: 4px solid #ffc107;
            padding: 15px;
            border-radius: 5px;
            margin: 20px 0;
        }
        .download-btn {
            display: inline-block;
            background: #00ff88;
            color: #1e3c72;
            padding: 15px 30px;
            border-radius: 30px;
            text-decoration: none;
            font-weight: bold;
            margin-top: 20px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🚀 RIZER API</h1>
        <p class="subtitle">ULTIMATE EDITION - 100% ACTRIZER Features</p>

        <div class="warning">
            <strong>⚡ Features:</strong> 100 Threads | Rarity Threshold: 2 | Auto-Activation | Couples Detection
        </div>

        <h3>📡 API Endpoint:</h3>
        <div class="endpoint">
            /gen?<span class="param">rizername</span>=NAME&<span class="param">password</span>=PASS&<span class="param">count</span>=1-10000&<span class="param">region</span>=REGION&<span class="param">ghost</span>=false&<span class="param">auto_activate</span>=true
        </div>

        <h3>🌍 Supported Regions:</h3>
        <div class="regions">
            <div class="region">IND 🇮🇳</div>
            <div class="region">BD 🇧🇩</div>
            <div class="region">PK 🇵🇰</div>
            <div class="region">ID 🇮🇩</div>
            <div class="region">TH 🇹🇭</div>
            <div class="region">VN 🇻🇳</div>
            <div class="region">ME 🌍</div>
            <div class="region">BR 🇧🇷</div>
        </div>

        <h3>✨ Features:</h3>
        <div class="features">
            <div class="feature">💎 Rarity Detection</div>
            <div class="feature">💑 Couples Detection</div>
            <div class="feature">🔥 Auto-Activation</div>
            <div class="feature">👻 Ghost Mode</div>
            <div class="feature">⚡ 100 Threads</div>
            <div class="feature">🎯 Score Threshold: 2</div>
        </div>

        <h3>📥 Download Accounts:</h3>
        <p>After generation, download your accounts:</p>
        <a href="/download/accounts" class="download-btn">Download accounts-{region}.json</a>
    </div>
</body>
</html>
"""

@app.route('/')
def home():
    """Home page"""
    return render_template_string(HTML_TEMPLATE)

@app.route('/gen')
def generate():
    """Main generation endpoint"""
    start_time = time.time()

    # Get parameters
    rizername = request.args.get('rizername', '').strip()
    password = request.args.get('password', '').strip()
    count_str = request.args.get('count', '1').strip()
    region = request.args.get('region', 'IND').strip().upper()
    is_ghost = request.args.get('ghost', 'false').lower() == 'true'
    auto_activate = request.args.get('auto_activate', 'true').lower() == 'true'

    # Validation
    if not rizername:
        return jsonify({"status": "error", "message": "❌ 'rizername' parameter required"}), 400
    if not password:
        return jsonify({"status": "error", "message": "❌ 'password' parameter required"}), 400

    try:
        count = int(count_str)
        if count < 1 or count > MAX_ACCOUNTS_PER_REQUEST:
            return jsonify({"status": "error", "message": f"❌ Count must be 1-{MAX_ACCOUNTS_PER_REQUEST}"}), 400
    except ValueError:
        return jsonify({"status": "error", "message": "❌ Invalid count"}), 400

    valid_regions = ["IND", "BD", "PK", "ID", "TH", "VN", "ME", "BR"]
    if region not in valid_regions:
        return jsonify({"status": "error", "message": f"❌ Region must be one of {valid_regions}"}), 400

    # Set auto-activation
    global AUTO_ACTIVATION_ENABLED
    AUTO_ACTIVATION_ENABLED = auto_activate

    # Generate accounts
    try:
        accounts = generate_batch(region, rizername, password, count, is_ghost)
        elapsed_time = time.time() - start_time

        # Prepare response
        response_data = {
            "status": "success" if accounts else "error",
            "message": f"✅ Generated {len(accounts)}/{count} accounts" if accounts else "❌ No accounts generated",
            "summary": {
                "requested": count,
                "generated": len(accounts),
                "success_rate": f"{len(accounts)/count*100:.1f}%",
                "region": region,
                "ghost_mode": is_ghost,
                "auto_activation": auto_activate,
                "threads_used": min(count, MAX_WORKERS),
                "rarity_threshold": RARITY_SCORE_THRESHOLD,
                "rare_found": RARE_COUNTER,
                "couples_found": COUPLES_COUNTER,
                "activated": ACTIVATED_COUNTER,
                "failed_activation": FAILED_ACTIVATION_COUNTER,
                "time_seconds": round(elapsed_time, 2),
                "speed": round(len(accounts)/elapsed_time, 2) if elapsed_time > 0 else 0
            },
            "accounts": accounts
        }

        return app.response_class(
            response=json.dumps(response_data, indent=2, ensure_ascii=False),
            status=200 if accounts else 500,
            mimetype='application/json'
        )

    except Exception as e:
        return jsonify({"status": "error", "message": f"❌ Error: {str(e)}"}), 500

@app.route('/download/accounts')
def download_accounts():
    """Download accounts as JSON file"""
    region = request.args.get('region', 'IND').upper()

    with STORAGE_LOCK:
        if region in ACCOUNTS_STORAGE:
            data = ACCOUNTS_STORAGE[region]
        else:
            data = []

    # Create JSON file in memory
    json_data = json.dumps(data, indent=2, ensure_ascii=False)
    buffer = io.BytesIO(json_data.encode('utf-8'))
    buffer.seek(0)

    return send_file(
        buffer,
        mimetype='application/json',
        as_attachment=True,
        download_name=f'accounts-{region}.json'
    )

@app.route('/download/all')
def download_all():
    """Download all accounts as ZIP"""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
        with STORAGE_LOCK:
            # Add accounts
            for region, accounts in ACCOUNTS_STORAGE.items():
                if accounts:
                    zf.writestr(f'accounts-{region}.json', json.dumps(accounts, indent=2, ensure_ascii=False))

            # Add rare accounts
            for region, accounts in RARE_ACCOUNTS_STORAGE.items():
                if accounts:
                    zf.writestr(f'rare-{region}.json', json.dumps(accounts, indent=2, ensure_ascii=False))

            # Add couples
            for region, couples in COUPLES_ACCOUNTS_STORAGE.items():
                if couples:
                    zf.writestr(f'couples-{region}.json', json.dumps(couples, indent=2, ensure_ascii=False))

            # Add activated
            for region, accounts in ACTIVATED_ACCOUNTS_STORAGE.items():
                if accounts:
                    zf.writestr(f'activated-{region}.json', json.dumps(accounts, indent=2, ensure_ascii=False))

    buffer.seek(0)
    return send_file(
        buffer,
        mimetype='application/zip',
        as_attachment=True,
        download_name='rizer-accounts-all.zip'
    )

@app.route('/health')
def health_check():
    """Health check endpoint"""
    return jsonify({
        "status": "healthy",
        "service": "RIZER API",
        "version": "10.3 ULTIMATE",
        "max_workers": MAX_WORKERS,
        "rarity_threshold": RARITY_SCORE_THRESHOLD,
        "max_accounts": MAX_ACCOUNTS_PER_REQUEST,
        "features": [
            "100_threads",
            "rarity_detection",
            "couples_detection",
            "auto_activation",
            "ghost_mode"
        ]
    })

@app.route('/stats')
def stats():
    """Get current stats"""
    with STORAGE_LOCK:
        return jsonify({
            "accounts": {k: len(v) for k, v in ACCOUNTS_STORAGE.items()},
            "rare": {k: len(v) for k, v in RARE_ACCOUNTS_STORAGE.items()},
            "couples": {k: len(v) for k, v in COUPLES_ACCOUNTS_STORAGE.items()},
            "activated": {k: len(v) for k, v in ACTIVATED_ACCOUNTS_STORAGE.items()},
            "failed": {k: len(v) for k, v in FAILED_ACTIVATION_STORAGE.items()}
        })

@app.route('/clear')
def clear_storage():
    """Clear all storage"""
    with STORAGE_LOCK:
        ACCOUNTS_STORAGE.clear()
        RARE_ACCOUNTS_STORAGE.clear()
        COUPLES_ACCOUNTS_STORAGE.clear()
        ACTIVATED_ACCOUNTS_STORAGE.clear()
        FAILED_ACTIVATION_STORAGE.clear()
        POTENTIAL_COUPLES.clear()
    return jsonify({"status": "success", "message": "All storage cleared"})

# =============================================================================
# MAIN ENTRY POINT
# =============================================================================

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5002))
    print(f"""
🚀 RIZER API v10.3 ULTIMATE STARTING
═══════════════════════════════════════
Port: {port}
Max Workers: {MAX_WORKERS} (LOCKED)
Rarity Threshold: {RARITY_SCORE_THRESHOLD} (LOCKED)
Max Accounts: {MAX_ACCOUNTS_PER_REQUEST}
Features: 100% from ACTRIZER.py
═══════════════════════════════════════
    """)
    app.run(host='0.0.0.0', port=port, debug=False, threaded=True)
