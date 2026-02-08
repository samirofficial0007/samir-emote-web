# --- START OF FILE main.py (MODIFIED AND MERGED) ---

# --- Imports from original main.py ---
import requests , os , psutil , sys , jwt , pickle , json , binascii , time , urllib3 , base64 , datetime , re , socket , threading , ssl , pytz , aiohttp
from protobuf_decoder.protobuf_decoder import Parser
from xC4 import * ; from xHeaders import *
from datetime import datetime
from google.protobuf.timestamp_pb2 import Timestamp
from concurrent.futures import ThreadPoolExecutor
from threading import Thread
from Pb2 import DEcwHisPErMsG_pb2 , MajoRLoGinrEs_pb2 , PorTs_pb2 , MajoRLoGinrEq_pb2 , sQ_pb2 , Team_msg_pb2
from cfonts import render, say
import asyncio
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# --- Imports needed from app.py ---
from flask import Flask, request, jsonify, render_template,redirect,url_for,session

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)  

# ... (Your EMOTE_ALIASES dictionary and other global variables remain exactly the same) ...
EMOTE_ALIASES = {
    # Evo Gun Emotes
    "m10": 909000081, "ak": 909000063, "ump": 909000098, "mp40": 909000075,
    "mp40v2": 909040010, "scar": 909000068, "xm8": 909000085, "mp5": 909033002,
    "m4a1": 909033001, "famas": 909000090, "m1887": 909035007, "thompson": 909038010,
    "g18": 909038012, "woodpecker": 909042008, "parafal": 909045001, "groza": 909041005,
    "p90": 909049010, "m60": 909051003, "fist": 909037011,
    
    # Normal Emotes (ছোট নাম)
    "ride": 909051014, "circle": 909050009, "petals": 909051013, "bow": 909051012,
    "bike": 909051010, "shower": 909051004, "dream": 909051002, "angelic": 909051001,
    "paint": 909048015, "sword": 909044015, "flare": 909041008, "owl": 909049003,
    "thor": 909050008, "bigdill": 909049001, "csgm": 909041013, "mapread": 909050014,
    "tomato": 909050015, "ninja": 909050002, "level100": 909042007, "auraboat": 909050028,
    "flyingguns": 909049012, "heart": 909000045, "flag": 909000034, "pushup": 909000012,
    "devil": 909000020, "shootdance": 909000008, "chicken": 909000006, "throne": 909000014,
    "rose": 909000010, "valentine": 909038004, "rampage": 909034001, "guildflag": 909049017,
    "fish": 909040004, "inosuke": 909041003, "brgm": 909041012,
    "naruto": 909050003, "kabuto": 909050002, "minato": 909050006, "football": 909048016,
    "p": 909000012, "t": 909000014, "r": 909000010, "l100": 909042007 
}

# Flask app initialization
app = Flask(__name__)
LOOP = None # For storing the asyncio event loop

# ... (All your global variables: online_writer, key, iv, etc. remain the same) ...
online_writer = None
whisper_writer = None
spam_room = False
spammer_uid = None
spam_chat_id = None
spam_uid = None
Spy = False
Chat_Leave = False
key = None
iv = None
region = None
server2 = "bd" 
key2 = "YOUR_API_KEY"
BYPASS_TOKEN = "YOUR_BYPASS_TOKEN"

# Monitoring system variables
from collections import deque, defaultdict
import threading
import time

# Request monitoring variables
request_timestamps = deque()  # Stores timestamps of requests for RPM calculation
team_codes_seen = defaultdict(int)  # Tracks unique team codes
monitoring_lock = threading.Lock()  # Thread safety for monitoring data
last_minute_reset = time.time()  # Last time the minute window was reset

# ==================== MULTI-BOT SYSTEM WITH SERVER SUPPORT ====================
# Bot credentials storage - Separate for each server
# Add your UID and passwords here for all supported servers

# List of all valid server names
VALID_SERVERS = ['india', 'bangladesh', 'middleeast', 'pakistan', 'africa', 'brazil', 'europe', 'indonesia', 'malaysia', 'mexico', 'russia', 'singapore', 'taiwan', 'thailand', 'unitedstates']

BOT_CREDENTIALS = {
    'india': [

       {'uid': '4474187851', 'password': 'F4B002C1C6513BA0A51EFD796E8C0B37BB7E9CF2D0A8DE6653404B1C4A7824F8'}
      
        
        
    ],
    'bangladesh': [
       {'uid': '4493299816', 'password': 'F02C6A3271FE4DC1F165D259EBF03349BDEA58D735A430333FF5AD324AA8768E'},
       {'uid': '4493299822', 'password': 'E100108298511722BD166B27857B87BDC13FF8EA604D3080E126FBF8916A71D4'},
       {'uid': '4493299840', 'password': '307F198A82F5DD9179FEDD48246344CB9447F115C2AA8F513C2725CCBA6DA74D'},
       {'uid': '4493299823', 'password': '25E8C02505D3024F76FA82BF31A8F27D277639C58FB926409410B4D209788909'},
       {'uid': '4493299828', 'password': '55AC776C0EE70C6653F454C02C5216A930043271632DFCE481361184ABE62584'},
       {'uid': '4493301497', 'password': '715CA97680AEEEA180A540973C0B31BD84028EAB4FB680D8A82D429EC52D8AA3'},
       {'uid': '4493301569', 'password': '0CD23795ECB21245BD644512D1894EB43CAFF89DC1010B4D6D7E51F656E09022'},
       {'uid': '4493301554', 'password': '4DD322ADF1D3A87A19DAED4C18FF06D4C6753BD40CAB70BC0A6604A2C12F435D'},
       {'uid': '4493301512', 'password': '69A7AD6ED8133287B76EB010EFC9BC514275DC76B9E1C3DFCEB0E189459F12EA'},
       {'uid': '4493305184', 'password': '26B308C5EB9B8AC3263AE89022FB02EBA095A2462F7E189EA6382E07B00035FD'},
       {'uid': '4493307746', 'password': '5A8C1D74B6CDFC325BD981080B22E26AC972C8B9051CFB81A20CD6C1786F24EA'},
       {'uid': '4493307741', 'password': '9DF04FD3CE01AEAE4A130032F1A66D346868FD3C08889E8732F38ECF50509AB5'},
       {'uid': '4493308328', 'password': '94B9FC468E720DDA22AB28C0B22E18E17D68CD898EE3B56D9BAFD02EF768189B'},
       {'uid': '4493308972', 'password': '8E8FCF0C5B585F33627AECC82D953F6A0578C65D46A1485D0FA01E6F2253A706'},
       {'uid': '4493309317', 'password': '5240036002A295DD88CF1129ABE9B48F6682766758857214AB334DE5571FEA26'},
       {'uid': '4493309320', 'password': 'E30C0677B3D46D9750F78DE5A3F81D22E2E449CA671F8AD2F052221FDF90C6C6'},
       {'uid': '4493309321', 'password': 'A06978379F566B49396D82206A586BF1C5BCE072255871836D19B5D6DA2E3539'},
       {'uid': '4493309651', 'password': '8C3374D5F69E38B0389DB485860D4D31F401BE1D15D82B2C3CDF1D417E418009'},
       {'uid': '4493309654', 'password': '07EBC7A98119729730DA44B67CD8A0473FD389FD7788848C3A84DC19065DB0A8'},
       {'uid': '4493309655', 'password': '2B42220D21677029BCA5ABD9C9762286DB2F630772BF70D4B4FC45126A2E7044'},
       {'uid': '4493310995', 'password': 'CE457E773DBF2E00C4DEFA0E0727025DD1FF7DAE71B3CB1928E391B430A10CA4'},
       {'uid': '4493311456', 'password': 'C170B5A54DE0D277FF16B2247AA701106D21934D2266124C6D5217AC35E5D928'},
       {'uid': '4493311850', 'password': '5F279212CE95C1C1C40593D8B3FEC670C5A6486197E84144873C7C9210399658'},
       {'uid': '4493312280', 'password': '983CF07BDF8A56FE0D5B1348ABEAB77D5B5565099EFDECF2B22CF0723D3C0657'},
       {'uid': '4493312871', 'password': '06C254376B862B46EDBE18ABBD543F2A17EEE1658A9BB6AD58F61D821D25920D'}
     
        # Add more Bangladesh server bot credentials here
        # Example format:
        # {'uid': 'YOUR_UID', 'password': 'YOUR_PASSWORD'},
    ],
    'middleeast': [
        # Add your Middle East server bot credentials here
        # Example format:
        # {'uid': 'YOUR_UID', 'password': 'YOUR_PASSWORD'},
    ],
    'pakistan': [
        # Add your Pakistan server bot credentials here
        # Example format:
        # {'uid': 'YOUR_UID', 'password': 'YOUR_PASSWORD'},
    ],
    'africa': [
        # Add your Africa server bot credentials here
        # Example format:
        # {'uid': 'YOUR_UID', 'password': 'YOUR_PASSWORD'},
    ],
    'brazil': [
        # Add your Brazil server bot credentials here
        # Example format:
        # {'uid': 'YOUR_UID', 'password': 'YOUR_PASSWORD'},
    ],
    'europe': [
        # Add your Europe server bot credentials here
        # Example format:
        # {'uid': 'YOUR_UID', 'password': 'YOUR_PASSWORD'},
    ],
    'indonesia': [
        # Add your Indonesia server bot credentials here
        # Example format:
        # {'uid': 'YOUR_UID', 'password': 'YOUR_PASSWORD'},
    ],
    'malaysia': [
        # Add your Malaysia server bot credentials here
        # Example format:
        # {'uid': 'YOUR_UID', 'password': 'YOUR_PASSWORD'},
    ],
    'mexico': [
        # Add your Mexico server bot credentials here
        # Example format:
        # {'uid': 'YOUR_UID', 'password': 'YOUR_PASSWORD'},
    ],
    'russia': [
        # Add your Russia server bot credentials here
        # Example format:
        # {'uid': 'YOUR_UID', 'password': 'YOUR_PASSWORD'},
    ],
    'singapore': [
        # Add your Singapore server bot credentials here
        # Example format:
        # {'uid': 'YOUR_UID', 'password': 'YOUR_PASSWORD'},
    ],
    'taiwan': [
        # Add your Taiwan server bot credentials here
        # Example format:
        # {'uid': 'YOUR_UID', 'password': 'YOUR_PASSWORD'},
    ],
    'thailand': [
        # Add your Thailand server bot credentials here
        # Example format:
        # {'uid': 'YOUR_UID', 'password': 'YOUR_PASSWORD'},
    ],
    'unitedstates': [
        # Add your United States server bot credentials here
        # Example format:
        # {'uid': 'YOUR_UID', 'password': 'YOUR_PASSWORD'},
    ]
}
@app.route("/api/keep-alive")
def keep_alive():
    return jsonify({"status": "alive", "time": datetime.now().isoformat()})
# Bot instance class to encapsulate bot-specific data
class BotInstance:
    def __init__(self, bot_id, uid, password):
        self.bot_id = bot_id
        self.uid = uid
        self.password = password
        self.online_writer = None
        self.whisper_writer = None
        self.key = None
        self.iv = None
        self.region = None
        self.is_connected = False
        self.lock = threading.Lock()
        self.current_team_code = None
        
# Bot Manager to handle team code to bot mapping
class BotManager:
    def __init__(self, server_name):
        self.server_name = server_name
        self.team_code_to_bot = {}  # Maps team_code -> BotInstance
        self.bot_instances = []     # List of all bot instances
        self.bot_index = 0          # For round-robin assignment
        self.lock = threading.Lock()
        
    def get_or_assign_bot(self, team_code):
        """Returns the bot instance for a team code. If not assigned, assigns one."""
        with self.lock:
            if team_code in self.team_code_to_bot:
                # Same team code, return same bot
                return self.team_code_to_bot[team_code]
            
            # Different team code, assign a different bot (round-robin)
            if not self.bot_instances:
                return None
            
            assigned_bot = self.bot_instances[self.bot_index % len(self.bot_instances)]
            self.bot_index += 1
            self.team_code_to_bot[team_code] = assigned_bot
            print(f"[BotManager-{self.server_name}] Team code {team_code} assigned to Bot {assigned_bot.bot_id}")
            return assigned_bot

# Global bot managers for each server
bot_managers = {
    'india': BotManager('india'),
    'bangladesh': BotManager('bangladesh'),
    'middleeast': BotManager('middleeast'),
    'pakistan': BotManager('pakistan'),
    'africa': BotManager('africa'),
    'brazil': BotManager('brazil'),
    'europe': BotManager('europe'),
    'indonesia': BotManager('indonesia'),
    'malaysia': BotManager('malaysia'),
    'mexico': BotManager('mexico'),
    'russia': BotManager('russia'),
    'singapore': BotManager('singapore'),
    'taiwan': BotManager('taiwan'),
    'thailand': BotManager('thailand'),
    'unitedstates': BotManager('unitedstates')
}

# ...
# ... (ALL your original async functions like GeNeRaTeAccEss, TcPChaT, TcPOnLine, etc., go here UNCHANGED)
# ... (I'm skipping them here for brevity, but they must be in your file)
# ...
# The code from line 81 to line 695 of your original main.py file stays here.
# Make sure to include all those functions.
async def encrypted_proto(encoded_hex):
    key_aes = b'Yg&tc%DEuh6%Zc^8'
    iv_aes = b'6oyZDr22E3ychjM%'
    cipher = AES.new(key_aes, AES.MODE_CBC, iv_aes)
    padded_message = pad(encoded_hex, AES.block_size)
    encrypted_payload = cipher.encrypt(padded_message)
    return encrypted_payload
    
async def GeNeRaTeAccEss(uid , password):
    url = "https://100067.connect.garena.com/oauth/guest/token/grant"
    # Hr should be imported or defined, using Hr from main.py's original position
    Hr = {
        'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 11; ASUS_Z01QD Build/PI)",
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Content-Type': "application/x-www-form-urlencoded",
        'Expect': "100-continue",
        'X-Unity-Version': "2018.4.11f1",
        'X-GA': "v1 1",
        'ReleaseVersion': "OB52"} 
    headers = {
        "Host": "100067.connect.garena.com",
        "User-Agent": (await Ua()),
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "close"}
    data = {
        "uid": uid,
        "password": password,
        "response_type": "token",
        "client_type": "2",
        "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
        "client_id": "100067"}
    async with aiohttp.ClientSession() as session:
        async with session.post(url, headers=Hr, data=data) as response:
            if response.status != 200: return "Failed to get access token"
            data = await response.json()
            open_id = data.get("open_id")
            access_token = data.get("access_token")
            return (open_id, access_token) if open_id and access_token else (None, None)

async def EncRypTMajoRLoGin(open_id, access_token):
    # ... (MajorLogin message creation and serialization, same as original)
    # Re-defining Hr for this scope if not globally accessible
    Hr = {
        'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 11; ASUS_Z01QD Build/PI)",
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Content-Type': "application/x-www-form-urlencoded",
        'Expect': "100-continue",
        'X-Unity-Version': "2018.4.11f1",
        'X-GA': "v1 1",
        'ReleaseVersion': "OB52"}
    major_login = MajoRLoGinrEq_pb2.MajorLogin()
    # ... (Populate major_login fields as per your original code) .
    # (Skipping long field assignment for brevity, assuming original logic is here)
    major_login.event_time = str(datetime.now())[:-7]
    major_login.game_name = "free fire"
    major_login.platform_id = 1
    major_login.client_version = "1.120.2"
    major_login.system_software = "Android OS 9 / API-28 (PQ3B.190801.10101846/G9650ZHU2ARC6)"
    major_login.system_hardware = "Handheld"
    major_login.telecom_operator = "Verizon"
    major_login.network_type = "WIFI"
    major_login.screen_width = 1920
    major_login.screen_height = 1080
    major_login.screen_dpi = "280"
    major_login.processor_details = "ARM64 FP ASIMD AES VMH | 2865 | 4"
    major_login.memory = 3003
    major_login.gpu_renderer = "Adreno (TM) 640"
    major_login.gpu_version = "OpenGL ES 3.1 v1.46"
    major_login.unique_device_id = "Google|34a7dcdf-a7d5-4cb6-8d7e-3b0e448a0c57"
    major_login.client_ip = "223.191.51.89"
    major_login.language = "en"
    major_login.open_id = open_id
    major_login.open_id_type = "4"
    major_login.device_type = "Handheld"
    memory_available = major_login.memory_available
    memory_available.version = 55
    memory_available.hidden_value = 81
    major_login.access_token = access_token
    major_login.platform_sdk_id = 1
    major_login.network_operator_a = "Verizon"
    major_login.network_type_a = "WIFI"
    major_login.client_using_version = "7428b253defc164018c604a1ebbfebdf"
    major_login.external_storage_total = 36235
    major_login.external_storage_available = 31335
    major_login.internal_storage_total = 2519
    major_login.internal_storage_available = 703
    major_login.game_disk_storage_available = 25010
    major_login.game_disk_storage_total = 26628
    major_login.external_sdcard_avail_storage = 32992
    major_login.external_sdcard_total_storage = 36235
    major_login.login_by = 3
    major_login.library_path = "/data/app/com.dts.freefireth-YPKM8jHEwAJlhpmhDhv5MQ==/lib/arm64"
    major_login.reg_avatar = 1
    major_login.library_token = "5b892aaabd688e571f688053118a162b|/data/app/com.dts.freefireth-YPKM8jHEwAJlhpmhDhv5MQ==/base.apk"
    major_login.channel_type = 3
    major_login.cpu_type = 2
    major_login.cpu_architecture = "64"
    major_login.client_version_code = "2019118695"
    major_login.graphics_api = "OpenGLES2"
    major_login.supported_astc_bitset = 16383
    major_login.login_open_id_type = 4
    major_login.analytics_detail = b"FwQVTgUPX1UaUllDDwcWCRBpWAUOUgsvA1snWlBaO1kFYg=="
    major_login.loading_time = 13564
    major_login.release_channel = "android"
    major_login.extra_info = "KqsHTymw5/5GB23YGniUYN2/q47GATrq7eFeRatf0NkwLKEMQ0PK5BKEk72dPflAxUlEBir6Vtey83XqF593qsl8hwY="
    major_login.android_engine_init_flag = 110009
    major_login.if_push = 1
    major_login.is_vpn = 1
    major_login.origin_platform_type = "4"
    major_login.primary_platform_type = "4"
    string = major_login.SerializeToString()
    return  await encrypted_proto(string)

async def MajorLogin(payload):
    url = "https://loginbp.ggblueshark.com/MajorLogin"
    Hr = {
        'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 11; ASUS_Z01QD Build/PI)",
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Content-Type': "application/x-www-form-urlencoded",
        'Expect': "100-continue",
        'X-Unity-Version': "2018.4.11f1",
        'X-GA': "v1 1",
        'ReleaseVersion': "OB52"}
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    async with aiohttp.ClientSession() as session:
        async with session.post(url, data=payload, headers=Hr, ssl=ssl_context) as response:
            if response.status == 200: return await response.read()
            return None

async def GetLoginData(base_url, payload, token):
    url = f"{base_url}/GetLoginData"
    Hr = {
        'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 11; ASUS_Z01QD Build/PI)",
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Content-Type': "application/x-www-form-urlencoded",
        'Expect': "100-continue",
        'X-Unity-Version': "2018.4.11f1",
        'X-GA': "v1 1",
        'ReleaseVersion': "OB52"}
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    Hr['Authorization']= f"Bearer {token}"
    async with aiohttp.ClientSession() as session:
        async with session.post(url, data=payload, headers=Hr, ssl=ssl_context) as response:
            if response.status == 200: return await response.read()
            return None

async def DecRypTMajoRLoGin(MajoRLoGinResPonsE):
    proto = MajoRLoGinrEs_pb2.MajorLoginRes()
    proto.ParseFromString(MajoRLoGinResPonsE)
    return proto

async def DecRypTLoGinDaTa(LoGinDaTa):
    proto = PorTs_pb2.GetLoginData()
    proto.ParseFromString(LoGinDaTa)
    return proto

async def DecodeWhisperMessage(hex_packet):
    packet = bytes.fromhex(hex_packet)
    proto = DEcwHisPErMsG_pb2.DecodeWhisper()
    proto.ParseFromString(packet)
    return proto
    
async def decode_team_packet(hex_packet):
    packet = bytes.fromhex(hex_packet)
    proto = sQ_pb2.recieved_chat()
    proto.ParseFromString(packet)
    return proto
    
async def xAuThSTarTuP(TarGeT, token, timestamp, key, iv):
    uid_hex = hex(TarGeT)[2:]
    uid_length = len(uid_hex)
    encrypted_timestamp = await DecodE_HeX(timestamp)
    encrypted_account_token = token.encode().hex()
    encrypted_packet = await EnC_PacKeT(encrypted_account_token, key, iv)
    encrypted_packet_length = hex(len(encrypted_packet) // 2)[2:]
    if uid_length == 9: headers = '0000000'
    elif uid_length == 8: headers = '00000000'
    elif uid_length == 10: headers = '000000'
    elif uid_length == 7: headers = '000000000'
    else: print('Unexpected length') ; headers = '0000000'
    return f"0115{headers}{uid_hex}{encrypted_timestamp}00000{encrypted_packet_length}{encrypted_packet}"
     
async def cHTypE(H):
    if not H: return 'Squid'
    elif H == 1: return 'CLan'
    elif H == 2: return 'PrivaTe'
    
async def SEndMsG(H , message , Uid , chat_id , key , iv):
    TypE = await cHTypE(H)
    if TypE == 'Squid': msg_packet = await xSEndMsgsQ(message , chat_id , key , iv)
    elif TypE == 'CLan': msg_packet = await xSEndMsg(message , 1 , chat_id , chat_id , key , iv)
    elif TypE == 'PrivaTe': msg_packet = await xSEndMsg(message , 2 , Uid , Uid , key , iv)
    return msg_packet

async def SEndPacKeT(OnLinE , ChaT , TypE , PacKeT, bot_instance=None):
    if bot_instance:
        if TypE == 'ChaT' and ChaT and bot_instance.whisper_writer: 
            bot_instance.whisper_writer.write(PacKeT) 
            await bot_instance.whisper_writer.drain()
        elif TypE == 'OnLine' and bot_instance.online_writer: 
            bot_instance.online_writer.write(PacKeT) 
            await bot_instance.online_writer.drain()
        else: return 'UnsoPorTed TypE ! >> ErrrroR (:():)'
    else:
        if TypE == 'ChaT' and ChaT: whisper_writer.write(PacKeT) ; await whisper_writer.drain()
        elif TypE == 'OnLine': online_writer.write(PacKeT) ; await online_writer.drain()
        else: return 'UnsoPorTed TypE ! >> ErrrroR (:():)' 
           
async def TcPOnLine(ip, port, key, iv, AutHToKen, bot_instance=None, reconnect_delay=0.5):
    global online_writer , spam_room , whisper_writer , spammer_uid , spam_chat_id , spam_uid , XX , uid , Spy,data2, Chat_Leave
    # Use bot_instance if provided, otherwise use global
    writer_ref = bot_instance.online_writer if bot_instance else None
    while True:
        try:
            reader , writer = await asyncio.open_connection(ip, int(port))
            if bot_instance:
                bot_instance.online_writer = writer
                writer_ref = bot_instance.online_writer
            else:
                online_writer = writer
                writer_ref = online_writer
            bytes_payload = bytes.fromhex(AutHToKen)
            writer_ref.write(bytes_payload)
            await writer_ref.drain()
            while True:
                data2 = await reader.read(9999)
                if not data2: break
                
                if data2.hex().startswith('0500') and len(data2.hex()) > 1000:
                    try:
                        print(data2.hex()[10:])
                        packet = await DeCode_PackEt(data2.hex()[10:])
                        print(packet)
                        packet = json.loads(packet)
                        OwNer_UiD , CHaT_CoDe , SQuAD_CoDe = await GeTSQDaTa(packet)

                        JoinCHaT = await AutH_Chat(3 , OwNer_UiD , CHaT_CoDe, key,iv)
                        await SEndPacKeT(whisper_writer , online_writer , 'ChaT' , JoinCHaT)


                        message = f'[B][C]{get_random_color()}\n- WeLComE To Emote Bot ! '
                        P = await SEndMsG(0 , message , OwNer_UiD , OwNer_UiD , key , iv)
                        await SEndPacKeT(whisper_writer , online_writer , 'ChaT' , P)

                    except:
                        if data2.hex().startswith('0500') and len(data2.hex()) > 1000:
                            try:
                                print(data2.hex()[10:])
                                packet = await DeCode_PackEt(data2.hex()[10:])
                                print(packet)
                                packet = json.loads(packet)
                                OwNer_UiD , CHaT_CoDe , SQuAD_CoDe = await GeTSQDaTa(packet)

                                JoinCHaT = await AutH_Chat(3 , OwNer_UiD , CHaT_CoDe, key,iv)
                                await SEndPacKeT(whisper_writer , online_writer , 'ChaT' , JoinCHaT)


                                message = f'[B][C]{get_random_color()}\n- WeLComE To Emote Bot ! \n\n{get_random_color()}- Commands : @a {xMsGFixinG("player_uid")} {xMsGFixinG("909000001")}\n\n[00FF00]Dev : @{xMsGFixinG("Spideerio")}'
                                P = await SEndMsG(0 , message , OwNer_UiD , OwNer_UiD , key , iv)
                                await SEndPacKeT(whisper_writer , online_writer , 'ChaT' , P)
                            except:
                                pass

            if bot_instance:
                if bot_instance.online_writer:
                    bot_instance.online_writer.close() 
                    await bot_instance.online_writer.wait_closed() 
                    bot_instance.online_writer = None
            else:
                online_writer.close() ; await online_writer.wait_closed() ; online_writer = None

        except Exception as e: 
            if bot_instance:
                bot_instance.online_writer = None
            else:
                online_writer = None
            print(f"- ErroR With {ip}:{port} - {e}")
        await asyncio.sleep(0.05)
                            
async def TcPChaT(ip, port, AutHToKen, key, iv, LoGinDaTaUncRypTinG, ready_event, region , bot_instance=None, reconnect_delay=0.5):
    global spam_room , whisper_writer , spammer_uid , spam_chat_id , spam_uid , online_writer , chat_id , XX , uid , Spy,data2, Chat_Leave
    # Use bot_instance if provided, otherwise use global
    writer_ref = bot_instance.whisper_writer if bot_instance else None
    while True:
        try:
            reader , writer = await asyncio.open_connection(ip, int(port))
            if bot_instance:
                bot_instance.whisper_writer = writer
                writer_ref = bot_instance.whisper_writer
            else:
                whisper_writer = writer
                writer_ref = whisper_writer
            bytes_payload = bytes.fromhex(AutHToKen)
            writer_ref.write(bytes_payload)
            await writer_ref.drain()
            ready_event.set()
            if LoGinDaTaUncRypTinG.Clan_ID:
                clan_id = LoGinDaTaUncRypTinG.Clan_ID
                clan_compiled_data = LoGinDaTaUncRypTinG.Clan_Compiled_Data
                print('\n - TarGeT BoT in CLan ! ')
                print(f' - Clan Uid > {clan_id}')
                print(f' - BoT ConnEcTed WiTh CLan ChaT SuccEssFuLy ! ')
                pK = await AuthClan(clan_id , clan_compiled_data , key , iv)
                if writer_ref: writer_ref.write(pK) ; await writer_ref.drain()
            while True:
                data = await reader.read(9999)
                if not data: break
                
                if data.hex().startswith("120000"):

                    msg = await DeCode_PackEt(data.hex()[10:])
                    chatdata = json.loads(msg)
                    try:
                        response = await DecodeWhisperMessage(data.hex()[10:])
                        uid = response.Data.uid
                        chat_id = response.Data.Chat_ID
                        XX = response.Data.chat_type
                        inPuTMsG = response.Data.msg.lower()
                    except:
                        response = None


                    if response:
                        if inPuTMsG.startswith(("/5")):
                            try:
                                dd = chatdata['5']['data']['16']
                                print('msg in private')
                                message = f"[B][C]{get_random_color()}\n\nAccepT My Invitation FasT\n\n"
                                P = await SEndMsG(response.Data.chat_type , message , uid , chat_id , key , iv)
                                await SEndPacKeT(whisper_writer , online_writer , 'ChaT' , P)
                                PAc = await OpEnSq(key , iv,region)
                                await SEndPacKeT(whisper_writer , online_writer , 'OnLine' , PAc)
                                C = await cHSq(5, uid ,key, iv,region)
                                await asyncio.sleep(0.05)
                                await SEndPacKeT(whisper_writer , online_writer , 'OnLine' , C)
                                V = await SEnd_InV(5 , uid , key , iv,region)
                                await asyncio.sleep(0.05)
                                await SEndPacKeT(whisper_writer , online_writer , 'OnLine' , V)
                                E = await ExiT(None , key , iv, region)
                                await asyncio.sleep(0.2)
                                await SEndPacKeT(whisper_writer , online_writer , 'OnLine' , E)
                            except:
                                print('msg in squad')



                        if inPuTMsG.startswith('/t '):
                            CodE = inPuTMsG.split('/t ')[1]
                            try:
                                dd = chatdata['5']['data']['16']
                                print('msg in private')
                                EM = await GenJoinSquadsPacket(CodE , key , iv, region)
                                await SEndPacKeT(whisper_writer , online_writer , 'OnLine' , EM)


                            except:
                                print('msg in squad')

                        if inPuTMsG.startswith('/solo'):
                            leave = await ExiT(uid,key,iv,region)
                            await SEndPacKeT(whisper_writer , online_writer , 'OnLine' , leave)

                        if inPuTMsG.strip().startswith('/s'):
                            EM = await FS(key , iv, region)
                            await SEndPacKeT(whisper_writer , online_writer , 'OnLine' , EM)

                        # >>>>>>>>>>>>> MODIFIED SHORTCUT EMOTE COMMAND HANDLER <<<<<<<<<<<<<
                        parts = inPuTMsG.strip().split()
                        
                        # Command is /emote_name uid (or) /emote_name teamcode uid
                        if len(parts) >= 2 and parts[0].startswith('/') and parts[0][1:] in EMOTE_ALIASES:
                            emote_alias = parts[0][1:]
                            emote_id = EMOTE_ALIASES[emote_alias]
                            
                            is_auto_mode = len(parts) >= 3 and parts[1].isdigit() and parts[2].isdigit() # /ak teamcode uid
                            is_squad_mode = len(parts) >= 2 and parts[1].isdigit() # /ak uid
                            
                            if not is_squad_mode and not is_auto_mode:
                                message = f'[B][C][FF0000]ERROR:\nভুল কমান্ড ফরম্যাট।\nব্যবহার:\n১. স্কোয়াডে থাকলে: /{emote_alias} (uid) [uid2...]\n২. Guild/Friend চ্যাটে: /{emote_alias} (teamcode) (uid) [uid2...]'
                                P = await SEndMsG(response.Data.chat_type, message, uid, chat_id, key, iv)
                                await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)
                                response = None # Prevent falling through to /e
                                continue

                            # Define where the UID list starts
                            uid_start_index = 1 if not is_auto_mode else 2
                            
                            # Extract UIDs (first UID is mandatory, others are optional)
                            target_uids = []
                            for i in range(uid_start_index, min(uid_start_index + 5, len(parts))): # Up to 5 UIDs
                                if parts[i].isdigit():
                                    target_uids.append(int(parts[i]))
                                else:
                                    break
                            
                            # Check if valid UIDs were found
                            if not target_uids:
                                message = f'[B][C][FF0000]ERROR:\nUID অবশ্যই সংখ্যা হতে হবে।\nব্যবহার:\n১. স্কোয়াডে থাকলে: /{emote_alias} (uid) [uid2...]\n২. Guild/Friend চ্যাটে: /{emote_alias} (teamcode) (uid) [uid2...]'
                                P = await SEndMsG(response.Data.chat_type, message, uid, chat_id, key, iv)
                                await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)
                                response = None
                                continue
                            
                            # --- CORE EMOTE LOGIC ---
                            
                            # 1. Check for Auto Mode (Join Team, Emote, Leave)
                            if is_auto_mode:
                                team_code = parts[1]
                                
                                try:
                                    # Attempt to Join
                                    EM = await GenJoinSquadsPacket(team_code , key , iv, region)
                                    await SEndPacKeT(whisper_writer , online_writer , 'OnLine' , EM)
                                    await asyncio.sleep(0.15) # Wait for join
                                    
                                    # Emote
                                    message = f'[B][C]{get_random_color()}\nACITVE Emote /{emote_alias} on -> {xMsGFixinG(target_uids[0])}{" and others" if len(target_uids) > 1 else ""}\n'
                                    P = await SEndMsG(response.Data.chat_type, message, uid, chat_id, key, iv)
                                    await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)
                                    
                                    for target_uid in target_uids:
                                        H = await Emote_k(target_uid, emote_id, key, iv, region)
                                        await SEndPacKeT(whisper_writer, online_writer, 'OnLine', H)
                                        # Removed delay for maximum speed
                                        
                                    await asyncio.sleep(0.2) # Wait for emote animation
                                    
                                    # Leave
                                    leave = await ExiT(None, key, iv, region) # None to leave current team
                                    await SEndPacKeT(whisper_writer , online_writer , 'OnLine' , leave)
                                    
                                    message = f'[B][C]{get_random_color()}\nBot left the squad after performing emote.'
                                    P = await SEndMsG(response.Data.chat_type, message, uid, chat_id, key, iv)
                                    await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)

                                except Exception as e:
                                    message = f'[B][C][FF0000]ERROR: Auto Emote Failed. Team Code or UID invalid. Error: {str(e)}'
                                    P = await SEndMsG(response.Data.chat_type, message, uid, chat_id, key, iv)
                                    await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)


                            # 2. Check for Squad Mode (Emote only) - If already in Squad chat
                            elif is_squad_mode:
                                try:
                                    chatdata['5']['data']['16'] # This line will raise an exception if not in Squad chat (Private/Guild)
                                    print('msg in private/guild. Squad Mode not applicable.')
                                    message = f"[B][C]{get_random_color()}\n\nCommand Available OnLy In SQuaD, or use the format: /{emote_alias} (teamcode) (uid) in Guild/Private chat! \n\n"
                                    P = await SEndMsG(response.Data.chat_type, message, uid, chat_id, key, iv)
                                    await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)
                                    
                                except:
                                    # This is a Squad chat
                                    print(f'msg in squad: /{emote_alias} -> {target_uids}')
                                    message = f'[B][C]{get_random_color()}\nACITVE Emote /{emote_alias} on -> {xMsGFixinG(target_uids[0])}{" and others" if len(target_uids) > 1 else ""}\n'
                                    P = await SEndMsG(response.Data.chat_type, message, uid, chat_id, key, iv)
                                    await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)
                                    
                                    for target_uid in target_uids:
                                        H = await Emote_k(target_uid, emote_id, key, iv, region)
                                        await SEndPacKeT(whisper_writer, online_writer, 'OnLine', H)
                                        # Removed delay for maximum speed
                            
                            response = None # Command was handled, skip the rest
                        # >>>>>>>>>>>>> END MODIFIED SHORTCUT EMOTE COMMAND HANDLER <<<<<<<<<<<<<
                        
                        
                        if response and inPuTMsG.strip().startswith('/e'): # Only proceed if response is still valid (not handled by shortcut)

                            try:
                                dd = chatdata['5']['data']['16']
                                print('msg in private')
                                message = f"[B][C]{get_random_color()}\n\nCommand Available OnLy In SQuaD ! \n\n"
                                P = await SEndMsG(response.Data.chat_type, message, uid, chat_id, key, iv)
                                await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)

                            except:
                                print('msg in squad')

                                parts = inPuTMsG.strip().split()
                                print(response.Data.chat_type, uid, chat_id)
                                message = f'[B][C]{get_random_color()}\nACITVE TarGeT -> {xMsGFixinG(uid)}\n'

                                P = await SEndMsG(response.Data.chat_type, message, uid, chat_id, key, iv)

                                uid2 = uid3 = uid4 = uid5 = None
                                s = False

                                try:
                                    uid = int(parts[1])
                                    uid2 = int(parts[2])
                                    uid3 = int(parts[3])
                                    uid4 = int(parts[4])
                                    uid5 = int(parts[5])
                                    idT = int(parts[5])

                                except ValueError as ve:
                                    print("ValueError:", ve)
                                    s = True

                                except Exception:
                                    idT = len(parts) - 1
                                    idT = int(parts[idT])
                                    print(idT)
                                    print(uid)

                                if not s:
                                    try:
                                        await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)

                                        H = await Emote_k(uid, idT, key, iv,region)
                                        await SEndPacKeT(whisper_writer, online_writer, 'OnLine', H)

                                        if uid2:
                                            H = await Emote_k(uid2, idT, key, iv,region)
                                            await SEndPacKeT(whisper_writer, online_writer, 'OnLine', H)
                                        if uid3:
                                            H = await Emote_k(uid3, idT, key, iv,region)
                                            await SEndPacKeT(whisper_writer, online_writer, 'OnLine', H)
                                        if uid4:
                                            H = await Emote_k(uid4, idT, key, iv,region)
                                            await SEndPacKeT(whisper_writer, online_writer, 'OnLine', H)
                                        if uid5:
                                            H = await Emote_k(uid5, idT, key, iv,region)
                                            await SEndPacKeT(whisper_writer, online_writer, 'OnLine', H)
                                        

                                    except Exception as e:
                                        pass

                        
                        # >>>>>>>>>>>>> MODIFIED HELP MESSAGE <<<<<<<<<<<<<
                        if inPuTMsG in ("hi" , "hello" , "fen" , "help"):
                            uid = response.Data.uid
                            chat_id = response.Data.Chat_ID
                            message = f'''[C][B][00FFFF]━━━━━━━━━━━━
[ffd319][B]☂︎Add 100 Likes
[FFFFFF]/like/(uid)
[ffd319][b]❄︎Join Bot In Group
[FFFFFF][b]/t (teamcode)
[ffd319][b]❀To Perform AnyEmote (Full Code)
[FFFFFF][b]/e (uid) (emote code)
[00FF7F][B]★ সহজ ইমোট কমান্ড (Emote Shortcut) ★
[FFFFFF][b]১. স্কোয়াডে থাকলে: /(emote_name) (uid) [uid2...]
[FFFFFF][b]২. Guild/Friend চ্যাটে (Auto-Mode): [00FF00]/(emote_name) (teamcode) (uid) [uid2...]
[FFFFFF][b]উদাহরণ (Auto-Mode): /ak 12345 521475527
[FFFFFF][b]উপলব্ধ ইমোট: [00FF00]{", ".join(EMOTE_ALIASES.keys())}
[ffd319]⚡Make 5 Player Group:
[FFFFFF]❄️/5 
[ffd319][b][c]🎵Make leave Bot 
[FFFFFF][b][c]©️/solo
[00FF7F][B]!!admin Commond!!
[ffd319][b]To Stop The Bot
[FFFFFF][b]/stop
[ffd319][b]To Mute Bot
[FFFFFF][b]/mute (time)
[C][B][FFB300]OWNER: WINTER
[00FFFF]━━━━━━━━━━━━
[00FF00]
[00ff00][B]⚓Thankyou For Joining Our Guild⚓                            
'''
                            P = await SEndMsG(response.Data.chat_type , message , uid , chat_id , key , iv)
                            await SEndPacKeT(whisper_writer , online_writer , 'ChaT' , P)
                        response = None
                            
            if bot_instance:
                if bot_instance.whisper_writer:
                    bot_instance.whisper_writer.close() 
                    await bot_instance.whisper_writer.wait_closed() 
                    bot_instance.whisper_writer = None
            else:
                whisper_writer.close() ; await whisper_writer.wait_closed() ; whisper_writer = None
        except Exception as e: 
            if bot_instance:
                bot_instance.whisper_writer = None
            else:
                whisper_writer = None
            print(f"ErroR {ip}:{port} - {e}")
        await asyncio.sleep(0.05)
# ------------------------------------------
# This async function is the core logic for sending emotes.
# Both /join and /send_emote will use this.
# ------------------------------------------
async def perform_emote_sequence(uids_list, emote_id, team_code_str, bot_instance=None):
    """Joins a squad, performs emotes on a list of UIDs, and then leaves."""
    global online_writer, whisper_writer, key, iv, region 
    
    # Use bot_instance data if provided, otherwise use globals
    bot_key = bot_instance.key if bot_instance else key
    bot_iv = bot_instance.iv if bot_instance else iv
    bot_region = bot_instance.region if bot_instance else region

    # --- Join Squad (once) ---
    EM = await GenJoinSquadsPacket(team_code_str, bot_key, bot_iv, bot_region)
    await SEndPacKeT(None, None, 'OnLine', EM, bot_instance)
    await asyncio.sleep(0.15)  # Wait for join to complete

    # --- Emote on each UID (loop) ---
    for uid_target in uids_list:
        H = await Emote_k(uid_target, emote_id, bot_key, bot_iv, bot_region)
        await SEndPacKeT(None, None, 'OnLine', H, bot_instance)
        # Removed delay for maximum speed

    await asyncio.sleep(0.2)  # Wait for the last emote animation to finish

    # --- Leave Squad ---
    # You can uncomment this if you want the bot to leave automatically
    # leave = await ExiT(None, bot_key, bot_iv, bot_region)
    # await SEndPacKeT(None, None, 'OnLine', leave, bot_instance)
    # await asyncio.sleep(1)

# ##########################################################################
# # --- START: FLASK API ROUTES (MERGED AND MODIFIED FROM APP.PY) ---
# ##########################################################################
app.secret_key = 'dev123'  # Random secret key

@app.route("/", methods=["GET"])
def gate():
    session['passed_gate'] = True
    return render_template("GLASS.html")


# ---------------------- KEEP ALIVE SYSTEM ----------------------
def self_ping():
    url = os.getenv("https://kiraclient-28ti.onrender.com/")  # Render আপনার public URL এখানে দেয়
    if not url:
        print("No RENDER_EXTERNAL_URL found!")
        return
    
    while True:
        try:
            requests.get(url)
            print("✔ Self-Ping sent to:", url)
        except Exception as e:
            print("Ping Error:", e)

        time.sleep(10 * 60)  # প্রতি 14 মিনিটে ping পাঠাবে (Render sleep করবে না)


# Background self-ping thread start
threading.Thread(target=self_ping, daemon=True).start()
# Background self-ping thread start

@app.route('/login', methods=['GET', 'POST'])  # ✅ Both GET and POST
def index():
    # Check if user came through gate
    if not session.get('passed_gate'):
        return redirect(url_for('gate'))
    
    # Clear the session flag
    session.pop('passed_gate', None)
    
    """Renders the main web page (index.html)."""
    try:
        # Assumes emotes.json is in the same directory as this script
        with open('emotes.json', 'r') as f:
            emotes = json.load(f)
        return render_template('index.html', emotes=emotes)
    except FileNotFoundError:
        print("ERROR: emotes.json file not found in the root directory.")
        return "ERROR: emotes.json file not found.", 500
    except Exception as e:
        print(f"An error occurred loading index.html: {e}")
        return "An internal server error occurred.", 500

@app.route('/send_emote', methods=['POST'])
def send_emote():
    """Receives data from the web UI and directly triggers the bot's emote logic."""
    global LOOP, request_timestamps, team_codes_seen, last_minute_reset
    
    if LOOP is None:
        return jsonify({
            "status": "error",
            "message": "Error: Bot system is not initialized. Please wait or restart."
        }), 503

    try:
        data = request.get_json()
        team_code = data.get('team_code')
        emote_id_str = data.get('emote_id')
        uids_str = data.get('uids', [])
        server = data.get('server', 'india').lower()  # Default to 'india' if not provided

        # Validation
        if not all([team_code, emote_id_str, uids_str]):
            return jsonify({'message': 'Error: Missing team_code, emote_id, or UIDs'}), 400
        
        # Validate server
        if server not in VALID_SERVERS:
            return jsonify({'message': f'Error: Invalid server. Valid servers: {", ".join(VALID_SERVERS)}'}), 400
        
        target_uids_int = [int(uid) for uid in uids_str]
        emote_id_int = int(emote_id_str)
        
        # Track request for monitoring (thread-safe)
        with monitoring_lock:
            current_time = time.time()
            
            # Add current timestamp to the queue
            request_timestamps.append(current_time)
            
            # Track unique team code
            team_codes_seen[team_code] = current_time
            
            # Remove timestamps older than 1 minute
            while request_timestamps and request_timestamps[0] < current_time - 60:
                request_timestamps.popleft()
                
            # Reset team codes if a minute has passed
            if current_time - last_minute_reset > 60:
                # Only keep team codes from the last minute
                for tc in list(team_codes_seen.keys()):
                    if team_codes_seen[tc] < current_time - 60:
                        del team_codes_seen[tc]
                last_minute_reset = current_time

    except (ValueError, TypeError) as e:
        return jsonify({"status": "error", "message": f"Invalid data format: {e}"}), 400
    
    # Get the correct bot manager for the server
    bot_manager = bot_managers.get(server)
    if not bot_manager:
        return jsonify({
            "status": "error",
            "message": f"Error: Server '{server}' is not configured."
        }), 503
    
    # Get or assign bot for this team code
    assigned_bot = bot_manager.get_or_assign_bot(str(team_code))
    if not assigned_bot:
        return jsonify({
            "status": "error",
            "message": "Error: No bots available. Please configure bot credentials."
        }), 503
    
    # Check if the assigned bot is connected
    if not assigned_bot.is_connected or not assigned_bot.online_writer or not assigned_bot.whisper_writer:
        return jsonify({
            "status": "error",
            "message": f"Error: Bot {assigned_bot.bot_id} is not connected yet. Please wait a moment."
        }), 503
    
    # Run the async emote function in the bot's event loop from this synchronous Flask thread
    try:
        future = asyncio.run_coroutine_threadsafe(
            perform_emote_sequence(target_uids_int, emote_id_int, str(team_code), assigned_bot), 
            LOOP
        )
        future.result(timeout=10)  # Wait for the async task to complete with a timeout
        
        return jsonify({
            'status': 'success',
            'message': f'Emote request sent successfully for UIDs: {", ".join(uids_str)} using Bot {assigned_bot.bot_id} on {server.upper()} server!'
        })

    except asyncio.TimeoutError:
         return jsonify({
            "status": "error",
            "message": "Error: Operation timed out. The game server might be unresponsive or the team code was invalid."
        }), 500
    except Exception as e:
        print(f"Error in send_emote logic: {e}")
        return jsonify({
            "status": "error",
            "message": f"An internal error occurred during the emote operation: {str(e)}"
        }), 500

@app.route('/join', methods=['GET'])
def join_and_emote_api():
    """Original GET API endpoint for direct calls (kept for compatibility)."""
    global LOOP 

    target_uids_str = [request.args.get(f'uid{i}') for i in range(1, 6) if request.args.get(f'uid{i}')]
    emote_id_str = request.args.get('emote_id')
    team_code = request.args.get('tc')
    server = request.args.get('server', 'india').lower()  # Default to 'india'
    
    if not target_uids_str or not emote_id_str or not team_code:
        return jsonify({"status": "error", "message": "Error: 'uid1', 'emote_id', and 'tc' are required parameters."}), 400

    if LOOP is None:
        return jsonify({"status": "error", "message": "Error: Bot system is not initialized."}), 503

    # Validate server
    if server not in VALID_SERVERS:
        return jsonify({"status": "error", "message": f"Error: Invalid server. Valid servers: {', '.join(VALID_SERVERS)}"}), 400

    try:
        target_uids_int = [int(uid) for uid in target_uids_str]
        emote_id = int(emote_id_str)
    except ValueError:
        return jsonify({"status": "error", "message": "Error: UIDs and Emote ID must be numbers."}), 400

    # Get the correct bot manager for the server
    bot_manager = bot_managers.get(server)
    if not bot_manager:
        return jsonify({
            "status": "error",
            "message": f"Error: Server '{server}' is not configured."
        }), 503

    # Get or assign bot for this team code
    assigned_bot = bot_manager.get_or_assign_bot(str(team_code))
    if not assigned_bot:
        return jsonify({
            "status": "error",
            "message": "Error: No bots available. Please configure bot credentials."
        }), 503
    
    # Check if the assigned bot is connected
    if not assigned_bot.is_connected or not assigned_bot.online_writer or not assigned_bot.whisper_writer:
        return jsonify({
            "status": "error",
            "message": f"Error: Bot {assigned_bot.bot_id} is not connected yet. Please wait a moment."
        }), 503

    try:
        future = asyncio.run_coroutine_threadsafe(
            perform_emote_sequence(target_uids_int, emote_id, str(team_code), assigned_bot), 
            LOOP
        )
        future.result(timeout=30) 
        
        return jsonify({
            "status": "success",
            "message": f"Successfully sent emote command for UIDs: {', '.join(target_uids_str)} using Bot {assigned_bot.bot_id} on {server.upper()} server."
        }), 200

    except asyncio.TimeoutError:
         return jsonify({"status": "error", "message": "Error: Operation timed out."}), 500
    except Exception as e:
        return jsonify({"status": "error", "message": f"An error occurred: {str(e)}"}), 500

# Monitoring API endpoint
@app.route('/monitoring', methods=['GET'])
def monitoring():
    """Returns monitoring metrics for the system."""
    with monitoring_lock:
        current_time = time.time()
        
        # Calculate requests per minute
        # Only count requests from the last 60 seconds
        rpm_count = len([ts for ts in request_timestamps if ts > current_time - 60])

        # Calculate requests per 24 hours
        rp24h_count = len([ts for ts in request_timestamps if ts > current_time - 86400])
        
        # Count unique team codes (users) in the last minute
        unique_team_codes_minute = {tc for tc, ts in team_codes_seen.items() if ts > current_time - 60}
        user_count_minute = len(unique_team_codes_minute)

        # Count unique team codes (users) in the last 24 hours
        unique_team_codes_24_hours = {tc for tc, ts in team_codes_seen.items() if ts > current_time - 86400}
        user_count_24_hours = len(unique_team_codes_24_hours)
        
        # Return monitoring data
        return jsonify({
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'requests_per_minute': rpm_count,
            'unique_users_minute': user_count_minute,
            'unique_team_codes': list(unique_team_codes_minute)
        })

# Monitoring dashboard web page
# ########################################################################

# ------------------------------------------
# >>> MaiiiinE and StarTinG functions (modified for multi-bot) <<<
# ------------------------------------------
async def MaiiiinE_bot(bot_instance):
    """Bot-specific main function that handles a single bot instance."""
    global LOOP
    
    # --- IMPORTANT: Set the global event loop for Flask to use (only once) ---
    if LOOP is None:
        LOOP = asyncio.get_running_loop()
    
    Uid = bot_instance.uid
    Pw = bot_instance.password
    
    print(f"[Bot {bot_instance.bot_id}] Starting authentication...")
    open_id , access_token = await GeNeRaTeAccEss(Uid , Pw)
    if not open_id or not access_token: 
        print(f"[Bot {bot_instance.bot_id}] ErroR - InvaLid AccounT") 
        return None
    
    PyL = await EncRypTMajoRLoGin(open_id , access_token)
    MajoRLoGinResPonsE = await MajorLogin(PyL)
    if not MajoRLoGinResPonsE: 
        print(f"[Bot {bot_instance.bot_id}] TarGeT AccounT => BannEd / NoT ReGisTeReD ! ") 
        return None
    
    MajoRLoGinauTh = await DecRypTMajoRLoGin(MajoRLoGinResPonsE)
    UrL = MajoRLoGinauTh.url
    print(f"[Bot {bot_instance.bot_id}] Login URL: {UrL}")
    bot_instance.region = MajoRLoGinauTh.region
    
    ToKen = MajoRLoGinauTh.token
    TarGeT = MajoRLoGinauTh.account_uid
    bot_instance.key = MajoRLoGinauTh.key
    bot_instance.iv = MajoRLoGinauTh.iv
    timestamp = MajoRLoGinauTh.timestamp
    
    LoGinDaTa = await GetLoginData(UrL , PyL , ToKen)
    if not LoGinDaTa: 
        print(f"[Bot {bot_instance.bot_id}] ErroR - GeTinG PorTs From LoGin Da Ta !") 
        return None
    LoGinDaTaUncRypTinG = await DecRypTLoGinDaTa(LoGinDaTa)
    OnLinePorTs = LoGinDaTaUncRypTinG.Online_IP_Port
    ChaTPorTs = LoGinDaTaUncRypTinG.AccountIP_Port
    OnLineiP , OnLineporT = OnLinePorTs.split(":")
    ChaTiP , ChaTporT = ChaTPorTs.split(":")
    acc_name = LoGinDaTaUncRypTinG.AccountName
    
    equie_emote(ToKen,UrL)
    AutHToKen = await xAuThSTarTuP(int(TarGeT) , ToKen , int(timestamp) , bot_instance.key , bot_instance.iv)
    ready_event = asyncio.Event()
    
    print(f"[Bot {bot_instance.bot_id}] Connecting to chat server...")
    task1 = asyncio.create_task(TcPChaT(ChaTiP, ChaTporT , AutHToKen , bot_instance.key , bot_instance.iv , LoGinDaTaUncRypTinG , ready_event , bot_instance.region, bot_instance))
    await ready_event.wait()
    await asyncio.sleep(0.1)
    print(f"[Bot {bot_instance.bot_id}] Connecting to online server...")
    task2 = asyncio.create_task(TcPOnLine(OnLineiP , OnLineporT , bot_instance.key , bot_instance.iv , AutHToKen, bot_instance))
    
    bot_instance.is_connected = True
    print(f"[Bot {bot_instance.bot_id}] ✓ Connected! Bot Name: {acc_name} | Target UID: {TarGeT}")
    
    await asyncio.gather(task1, task2)

async def MaiiiinE():
    """Legacy single-bot function for backward compatibility."""
    global LOOP, key, iv, region, whisper_writer, online_writer
    
    LOOP = asyncio.get_running_loop()
    
    Uid , Pw = '4493312871' , '06C254376B862B46EDBE18ABBD543F2A17EEE1658A9BB6AD58F61D821D25920D'
    
    open_id , access_token = await GeNeRaTeAccEss(Uid , Pw)
    if not open_id or not access_token: print("ErroR - InvaLid AccounT") ; return None
    
    PyL = await EncRypTMajoRLoGin(open_id , access_token)
    MajoRLoGinResPonsE = await MajorLogin(PyL)
    if not MajoRLoGinResPonsE: print("TarGeT AccounT => BannEd / NoT ReGisTeReD ! ") ; return None
    
    MajoRLoGinauTh = await DecRypTMajoRLoGin(MajoRLoGinResPonsE)
    UrL = MajoRLoGinauTh.url
    print(UrL)
    region = MajoRLoGinauTh.region
    
    ToKen = MajoRLoGinauTh.token
    TarGeT = MajoRLoGinauTh.account_uid
    key = MajoRLoGinauTh.key
    iv = MajoRLoGinauTh.iv
    timestamp = MajoRLoGinauTh.timestamp
    
    LoGinDaTa = await GetLoginData(UrL , PyL , ToKen)
    if not LoGinDaTa: print("ErroR - GeTinG PorTs From LoGin Da Ta !") ; return None
    LoGinDaTaUncRypTinG = await DecRypTLoGinDaTa(LoGinDaTa)
    OnLinePorTs = LoGinDaTaUncRypTinG.Online_IP_Port
    ChaTPorTs = LoGinDaTaUncRypTinG.AccountIP_Port
    OnLineiP , OnLineporT = OnLinePorTs.split(":")
    ChaTiP , ChaTporT = ChaTPorTs.split(":")
    acc_name = LoGinDaTaUncRypTinG.AccountName
    
    equie_emote(ToKen,UrL)
    AutHToKen = await xAuThSTarTuP(int(TarGeT) , ToKen , int(timestamp) , key , iv)
    ready_event = asyncio.Event()
    
    task1 = asyncio.create_task(TcPChaT(ChaTiP, ChaTporT , AutHToKen , key , iv , LoGinDaTaUncRypTinG , ready_event ,region))
    await ready_event.wait()
    await asyncio.sleep(0.1)
    task2 = asyncio.create_task(TcPOnLine(OnLineiP , OnLineporT , key , iv , AutHToKen))
    
    # --- This part remains the same: starting Flask in a new thread ---
    def run_flask():
        app.run(host='0.0.0.0', port=30151, debug=False)

    flask_thread = threading.Thread(target=run_flask)
    flask_thread.daemon = True
    flask_thread.start()
    
    os.system('clear')
    print(render('WINTER', colors=['white', 'green'], align='center'))
    print('')
    print(f" - BoT STarTinG And OnLine on TarGeT : {TarGeT} | BOT NAME : {acc_name}\n")
    print(f" - BoT sTaTus > GooD | OnLinE ! (:")
    print(f" - Web UI and API started on http://0.0.0.0:30151/")
    print(f" - API Example: http://<YOUR_IP>:30151/join?uid1=<UID>&emote_id=<ID>&tc=<CODE>")
    print(f" - Subscribe > Spideerio | Gaming ! (:")    
    await asyncio.gather(task1, task2)
    
async def StarTinG_multi():
    """Starts multiple bots and manages them for all servers."""
    global LOOP
    
    # Initialize bot instances for each server
    total_bots = 0
    for server_name, credentials in BOT_CREDENTIALS.items():
        if not credentials:
            print(f"[{server_name.upper()}] No bot credentials configured!")
            continue
        
        bot_manager = bot_managers[server_name]
        bot_id_counter = 1
        
        for cred in credentials:
            bot_instance = BotInstance(bot_id_counter, cred['uid'], cred['password'])
            bot_manager.bot_instances.append(bot_instance)
            print(f"[BotManager-{server_name.upper()}] Initialized Bot {bot_instance.bot_id} with UID: {cred['uid'][:5]}...")
            bot_id_counter += 1
        
        print(f"[BotManager-{server_name.upper()}] Total bots initialized: {len(bot_manager.bot_instances)}")
        total_bots += len(bot_manager.bot_instances)
    
    print(f"\n[Total] All servers: {total_bots} bots initialized")
    
    # Start Flask server once
    def run_flask():
        app.run(host='0.0.0.0', port=30151, debug=False)
    
    flask_thread = threading.Thread(target=run_flask)
    flask_thread.daemon = True
    flask_thread.start()
    
    os.system('clear')
    print(render('WINTER', colors=['white', 'green'], align='center'))
    print('')
    print(f"[Multi-Bot System] Starting {total_bots} bots across all servers...")
    print(f" - Web UI and API started on http://0.0.0.0:30151/")
    print(f" - Server Selection: {len(VALID_SERVERS)} servers available")
    print(f" - Available servers: {', '.join([s.capitalize() for s in VALID_SERVERS])}")
    print(f" - Team codes will be automatically assigned to different bots")
    print(f" - Same team code = Same bot | Different team code = Different bot")
    print('')
    
    # Start all bots concurrently for all servers
    async def bot_worker(bot, server_name):
        """Worker function for a single bot instance."""
        while True:
            try:
                await asyncio.wait_for(MaiiiinE_bot(bot), timeout=7 * 60 * 60)
            except asyncio.TimeoutError:
                print(f"[Bot-{server_name.upper()} {bot.bot_id}] Token ExpiRed! Restarting...")
                bot.is_connected = False
            except Exception as e:
                print(f"[Bot-{server_name.upper()} {bot.bot_id}] ErroR TcP - {e} => Restarting...")
                bot.is_connected = False
            await asyncio.sleep(1)  # Wait before reconnecting
    
    bot_tasks = []
    for server_name, bot_manager in bot_managers.items():
        for bot in bot_manager.bot_instances:
            bot_tasks.append(asyncio.create_task(bot_worker(bot, server_name)))
    
    await asyncio.gather(*bot_tasks)
    
async def StarTinG():
    """Legacy single-bot starter (kept for backward compatibility)."""
    while True:
        try: await asyncio.wait_for(MaiiiinE(), timeout=7 * 60 * 60)
        except asyncio.TimeoutError: print("Token ExpiRed! Restarting...")
        except Exception as e: print(f"ErroR TcP - {e} => Restarting...")

if __name__ == '__main__':
    # Use multi-bot system if credentials are configured
    total_creds = sum(len(creds) for creds in BOT_CREDENTIALS.values())
    if total_creds > 1:
        print("[System] Multi-bot mode enabled with server support")
        asyncio.run(StarTinG_multi())
    elif total_creds == 1:
        print("[System] Single-bot mode (legacy)")
        asyncio.run(StarTinG())
    else:
        print("[System] ERROR: No bot credentials configured!")

# --- END OF FILE main.py (MODIFIED AND MERGED) ---
