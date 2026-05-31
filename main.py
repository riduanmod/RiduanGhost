import os
import sys
import json
import time
import base64
import socket
import select
import random
import threading
import signal
import atexit
import concurrent.futures
import urllib3
import requests
import jwt
from datetime import datetime
from flask import Flask, request, jsonify
from google.protobuf.timestamp_pb2 import Timestamp
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from protobuf_decoder.protobuf_decoder import Parser
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import symbol_database as _symbol_database
from google.protobuf.internal import builder as _builder
from config import FreeFireVersion

Payload1A13 = "1a13323032362d30342d30382031323a30303a3030220966726565206669726528013a07312e3132332e314239416e64726f6964204f5320372e312e32202f204150492d32352028515031412e3139303731312e3032302f473938384e4b53553141544544294a0848616e6468656c645208542d4d6f62696c655a045749464960b60a68ee0572033234307a1841524d7637205646507633204e454f4e207c2030207c20348001ec1e8a010f416472656e6f2028544d29203635309201234f70656e474c20455320332e312028342e352e30204e5649444941203537372e3030299a012b476f6f676c657c32663563383830652d306533662d343236362d626638662d643331613666303462333464a2010d3130352e3130372e37312e3134aa0102656eb201206237303234356239326265383237616635366438393332333436663335316632ba010134c2010848616e6468656c64ca011073616d73756e6720534d2d473938384eea014031306532393962653966383139396264353066386335326262616534363935626331393335353633626131376433383539633937323337626434356362343238f00101ca0208542d4d6f62696c65d2020457494649ca03203734323862323533646566633136343031386336303461316562626665626466e003faf603e803baaf03f003fe3df803c62a800497c9038804faf603900497c9039804faf603c80402d204262f646174612f6170702f636f6d2e6474732e667265656669726574682d312f6c69622f61726de00401ea044832303837663631633139663537663261663465376665666630623234643964397c2f646174612f6170702f636f6d2e6474732e667265656669726574682d312f626173652e61706bf00403f804018a050233329a050a32303139313138363932b205094f70656e474c455332b805ff7fc00504d2050b436f6e7374616e74696e65da05023235e0058b8b0bea0507616e64726f6964f205704b717348543876426332444378756538733871597a7675572f4e786463336a4230305152464554524f39454e656156674b2f662f6b4b79413566625531597350374d55477a686344423555454841637464656f662b5057634d4b644f4878342f625562704772413831714445563244418806019a060134a2060134b2062543001544565c5f5348535c175554415845395e540b075b7109145c6241505b5b403e000e35"
GetLoginDataRegion = "https://clientbp.ggpolarbear.com/GetLoginData"
MajorLoginRegion = "https://loginbp.ggpolarbear.com/MajorLogin"

_sym_db = _symbol_database.Default()
DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(
    b'\n\x13MajorLoginRes.proto"\x87\x05\n\rMajorLoginRes\x12\x12\n\naccount_id\x18\x01 \x01(\x03\x12\x13\n\x0block_region\x18\x02 \x01(\t\x12\x13\n\x0bnoti_region\x18\x03 \x01(\t\x12\x11\n\tip_region\x18\x04 \x01(\t\x12\x19\n\x11\x61gora_environment\x18\x05 \x01(\t\x12\x19\n\x11new_active_region\x18\x06 \x01(\t\x12\r\n\x05token\x18\x08 \x01(\t\x12\x0b\n\x03ttl\x18\t \x01(\x05\x12\x12\n\nserver_url\x18\n \x01(\t\x12\x16\n\x0e\x65mulator_score\x18\x0c \x01(\x03\x12\x32\n\tblacklist\x18\r \x01(\x0b\x32\x1f.MajorLoginRes.BlacklistInfoRes\x12\x31\n\nqueue_info\x18\x0f \x01(\x0b\x32\x1d.MajorLoginRes.LoginQueueInfo\x12\x0e\n\x06tp_url\x18\x10 \x01(\t\x12\x15\n\rapp_server_id\x18\x11 \x01(\x03\x12\x0f\n\x07\x61no_url\x18\x12 \x01(\t\x12\x0f\n\x07ip_city\x18\x13 \x01(\t\x12\x16\n\x0eip_subdivision\x18\x14 \x01(\t\x12\x0b\n\x03kts\x18\x15 \x01(\x03\x12\n\n\x02\x61k\x18\x16 \x01(\x0c\x12\x0b\n\x03\x61iv\x18\x17 \x01(\x0c\x1aQ\n\x10\x42lacklistInfoRes\x12\x12\n\nban_reason\x18\x01 \x01(\x05\x12\x17\n\x0f\x65xpire_duration\x18\x02 \x01(\x03\x12\x10\n\x08\x62\x61n_time\x18\x03 \x01(\x03\x1a\x66\n\x0eLoginQueueInfo\x12\r\n\x05\x41llow\x18\x01 \x01(\x08\x12\x16\n\x0equeue_position\x18\x02 \x01(\x03\x12\x16\n\x0eneed_wait_secs\x18\x03 \x01(\x03\x12\x15\n\rqueue_is_full\x18\x04 \x01(\x08\x62\x06proto3'
)
_globals = globals()
_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, _globals)
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, "MajorLoginRes_pb2", _globals)
if _descriptor._USE_C_DESCRIPTORS == False:
    DESCRIPTOR._options = None
    _globals["_MAJORLOGINRES"]._serialized_start = 24
    _globals["_MAJORLOGINRES"]._serialized_end = 671
    _globals["_MAJORLOGINRES_BLACKLISTINFORES"]._serialized_start = 486
    _globals["_MAJORLOGINRES_BLACKLISTINFORES"]._serialized_end = 567
    _globals["_MAJORLOGINRES_LOGINQUEUEINFO"]._serialized_start = 569
    _globals["_MAJORLOGINRES_LOGINQUEUEINFO"]._serialized_end = 671

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

Key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
Iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])

def encode_varint(num):
    if num < 0:
        raise ValueError("Number must be non-negative")
    out = []
    while True:
        b = num & 0x7F
        num >>= 7
        if num:
            b |= 0x80
        out.append(b)
        if not num:
            break
    return bytes(out)

def create_field(num, val):
    if isinstance(val, int):
        return encode_varint((num << 3) | 0) + encode_varint(val)
    if isinstance(val, (str, bytes)):
        v = val.encode() if isinstance(val, str) else val
        return encode_varint((num << 3) | 2) + encode_varint(len(v)) + v
    if isinstance(val, dict):
        nested = create_packet(val)
        return encode_varint((num << 3) | 2) + encode_varint(len(nested)) + nested
    return b""

def create_packet(fields):
    return b"".join(create_field(k, v) for k, v in fields.items())

def dec_to_hex(n):
    return f"{n:02x}"

def encrypt_packet(plain_text, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(bytes.fromhex(plain_text), AES.block_size)).hex()

def encrypt_api(plain_text):
    return encrypt_packet(plain_text, Key, Iv)

def aes_encrypt(data, key, iv):
    data = bytes.fromhex(data) if isinstance(data, str) else data
    return AES.new(key, AES.MODE_CBC, iv).encrypt(pad(data, 16)).hex()

def parse_results(parsed_results):
    result_dict = {}
    for result in parsed_results:
        field_data = {"wire_type": result.wire_type}
        if result.wire_type in ["varint", "string", "bytes"]:
            field_data["data"] = result.data
        elif result.wire_type == "length_delimited":
            field_data["data"] = parse_results(result.data.results)
        result_dict[result.field] = field_data
    return result_dict

def get_available_room(input_text):
    try:
        return json.dumps(parse_results(Parser().parse(input_text)))
    except Exception:
        return None

def get_packet2(key, iv):
    fields = {1: 3, 2: {2: 5, 3: "en"}}
    packet = create_packet(fields).hex() + "7200"
    hlen = len(aes_encrypt(packet, key, iv)) // 2
    return bytes.fromhex("1215000000" + dec_to_hex(hlen) + aes_encrypt(packet, key, iv))

def EnC_PacKeT(HeX, K, V):
    return AES.new(K, AES.MODE_CBC, V).encrypt(pad(bytes.fromhex(HeX), 16)).hex()

def DecodE_HeX(H):
    F = str(hex(H))[2:]
    return "0" + F if len(F) == 1 else F

def GeneRaTePk(Pk, N, K, V):
    PkEnc = EnC_PacKeT(Pk, K, V)
    _ = DecodE_HeX(int(len(PkEnc) // 2))
    HeadEr = N + "0" * (8 - len(_))
    return bytes.fromhex(HeadEr + _ + PkEnc)

def EnC_Uid(H, Tp):
    e, H = [], int(H)
    while H:
        e.append((H & 0x7F) | (0x80 if H > 0x7F else 0))
        H >>= 7
    return bytes(e).hex() if Tp == "Uid" else None

def ArA_CoLor():
    return random.choice([
        "FFFFFF", "F8F9FA", "F5F5F5", "E0E0E0", 
        "FFD700", "DAA520", "B8860B", "C0C0C0", 
        "E5E4E2", "0B0F1A", "1A1A2E", "1F2833", 
        "FF0000", "00FF00", "0000FF", "00FFFF", 
        "FF00FF", "8A2BE2", "00FA9A", "FF4500"  
    ])

def ExiT(account_id, K, V):
    fields = {1: 7, 2: {1: int(account_id)}}
    return GeneRaTePk(str(create_packet(fields).hex()), "0515", K, V)

def GenJoinSquadsPacket(code, key, iv):
    fields = {
        1: 4,
        2: {
            4: bytes.fromhex("01090a0b121920"),
            5: str(code),
            6: 6,
            8: 1,
            9: {2: 1393, 6: 11, 8: "1.120.2", 9: 5, 10: 1}
        }
    }
    return GeneRaTePk(str(create_packet(fields).hex()), "0515", key, iv)

def ghost_pakcet(player_id, nm, secret_code, key, iv):
    fields = {
        1: 61,
        2: {
            1: int(player_id),
            2: {
                1: int(player_id),
                2: 1159,
                3: f"[b][c][{ArA_CoLor()}]{nm}",
                5: 12,
                6: 15,
                7: 1,
                8: {2: 1, 3: 1},
                9: 3,
            },
            3: secret_code,
        },
    }
    return GeneRaTePk(str(create_packet(fields).hex()), "0515", key, iv)

def Fix_PackEt(parsed_results):
    return parse_results(parsed_results)

def DeCode_PackEt(input_text):
    return get_available_room(input_text)

app = Flask(__name__)
app.config['JSON_SORT_KEYS'] = False
if hasattr(app, 'json'):
    app.json.sort_keys = False

clients = {}
shutting_down = False

def AuTo_ResTartinG():
    return

class TcpBotConnectMain:
    def __init__(self, account_id, password):
        self.account_id = account_id
        self.password = password
        self.key = None
        self.iv = None
        self.socket_client = None
        self.clientsocket = None
        self.running = False
        self.connection_attempts = 0
        self.max_connection_attempts = 2
        self.AutH = None
        self.DaTa2 = None
        self.sockf1_thread = None

    def run(self):
        if shutting_down:
            return

        if not hasattr(self, "auto_restart_thread_started"):
            t = threading.Thread(target=AuTo_ResTartinG, daemon=True)
            t.start()
            self.auto_restart_thread_started = True

        self.running = True
        self.connection_attempts = 0

        while (
            self.running
            and not shutting_down
            and self.connection_attempts < self.max_connection_attempts
        ):
            try:
                self.connection_attempts += 1
                self.get_tok()
                break
            except Exception:
                if self.connection_attempts >= self.max_connection_attempts:
                    self.stop()
                    break
                time.sleep(5)

    def stop(self):
        self.running = False
        try:
            if self.clientsocket:
                self.clientsocket.close()
        except:
            pass
        try:
            if self.socket_client:
                self.socket_client.close()
        except:
            pass

    def restart(self, delay=5):
        if shutting_down:
            return
        time.sleep(delay)
        self.run()

    def is_socket_connected(self, sock):
        try:
            if sock is None:
                return False
            writable = select.select([], [sock], [], 0.1)[1]
            if sock in writable:
                sock.send(b"")
                return True
            return False
        except (OSError, socket.error):
            return False
        except Exception:
            return False

    def ensure_connection(self):
        if not self.is_socket_connected(self.socket_client) and self.running:
            self.restart(delay=2)
            return False
        return True

    def sockf1(self, tok, online_ip, online_port, packet, key, iv):
        while self.running and not shutting_down:
            try:
                self.socket_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.socket_client.settimeout(30)
                self.socket_client.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)

                online_port = int(online_port)
                self.socket_client.connect((online_ip, online_port))
                self.socket_client.send(bytes.fromhex(tok))

                while (
                    self.running
                    and not shutting_down
                    and self.is_socket_connected(self.socket_client)
                ):
                    try:
                        readable, _, _ = select.select([self.socket_client], [], [], 1.0)
                        if self.socket_client in readable:
                            self.DaTa2 = self.socket_client.recv(99999)
                            if not self.DaTa2:
                                break

                            if "0500" in self.DaTa2.hex()[0:4] and len(self.DaTa2.hex()) > 30:
                                try:
                                    self.packet = json.loads(
                                        DeCode_PackEt(f'08{self.DaTa2.hex().split("08", 1)[1]}')
                                    )
                                    self.AutH = self.packet["5"]["data"]["7"]["data"]
                                except Exception:
                                    pass
                    except socket.timeout:
                        continue
                    except (OSError, socket.error, Exception):
                        break

            except Exception:
                pass

            if self.running and not shutting_down:
                time.sleep(2)

    def connect(self, tok, packet, key, iv, whisper_ip, whisper_port, online_ip, online_port):
        while self.running and not shutting_down:
            try:
                self.clientsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.clientsocket.settimeout(None)
                self.clientsocket.connect((whisper_ip, int(whisper_port)))
                self.clientsocket.send(bytes.fromhex(tok))
                self.data = self.clientsocket.recv(1024)
                self.clientsocket.send(get_packet2(self.key, self.iv))
                self.sockf1_thread = threading.Thread(
                    target=self.sockf1,
                    args=(tok, online_ip, online_port, "anything", key, iv),
                    daemon=True
                )
                self.sockf1_thread.start()

                while self.running and not shutting_down:
                    dataS = self.clientsocket.recv(1024)
                    if not dataS:
                        break
            except Exception:
                time.sleep(3)
            finally:
                if self.clientsocket:
                    try: 
                        self.clientsocket.close()
                    except: 
                        pass
                if self.running and not shutting_down:
                    time.sleep(2)

    def parse_my_message(self, serialized_data):
        MajorLogRes = MajorLoginRes()
        MajorLogRes.ParseFromString(serialized_data)
        timestamp = MajorLogRes.kts
        key = MajorLogRes.ak
        iv = MajorLogRes.aiv
        BASE64_TOKEN = MajorLogRes.token
        timestamp_obj = Timestamp()
        timestamp_obj.FromNanoseconds(timestamp)
        combined_timestamp = timestamp_obj.seconds * 1_000_000_000 + timestamp_obj.nanos
        return combined_timestamp, key, iv, BASE64_TOKEN

    def GET_PAYLOAD_BY_DATA(self, JWT_TOKEN, NEW_ACCESS_TOKEN, date):
        token_payload_base64 = JWT_TOKEN.split(".")[1]
        token_payload_base64 += "=" * ((4 - len(token_payload_base64) % 4) % 4)
        decoded_payload = json.loads(base64.urlsafe_b64decode(token_payload_base64).decode("utf-8"))
        NEW_EXTERNAL_ID = decoded_payload["external_id"]
        SIGNATURE_MD5 = decoded_payload["signature_md5"]
        now = str(datetime.now())[: len(str(datetime.now())) - 7]
        payload = bytes.fromhex(Payload1A13)
        payload = payload.replace(b"2025-08-02 17:15:04", str(now).encode())
        payload = payload.replace(
            b"10e299be9f8199bd50f8c52bbae4695bc1935563ba17d3859c97237bd45cb428",
            NEW_ACCESS_TOKEN.encode("UTF-8"),
        )
        payload = payload.replace(b"b70245b92be827af56d8932346f351f2", NEW_EXTERNAL_ID.encode("UTF-8"))
        payload = payload.replace(b"7428b253defc164018c604a1ebbfebdf", SIGNATURE_MD5.encode("UTF-8"))
        PAYLOAD = bytes.fromhex(encrypt_api(payload.hex()))
        return self.GET_LOGIN_DATA(JWT_TOKEN, PAYLOAD)

    def GET_LOGIN_DATA(self, JWT_TOKEN, PAYLOAD):
        headers = {
            "Expect": "100-continue",
            "Authorization": f"Bearer {JWT_TOKEN}",
            "X-Unity-Version": "2018.4.11f1",
            "X-GA": "v1 1",
            "ReleaseVersion": FreeFireVersion,
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; G011A Build/PI)",
            "Host": "client.ind.freefiremobile",
            "Connection": "close",
            "Accept-Encoding": "gzip, deflate, br",
        }
        for attempt in range(3):
            if shutting_down: break
            try:
                response = requests.post(GetLoginDataRegion, headers=headers, data=PAYLOAD, verify=False)
                response.raise_for_status()
                parsed_data = json.loads(get_available_room(response.content.hex()))
                whisper_address = parsed_data["32"]["data"]
                online_address = parsed_data["14"]["data"]
                return (whisper_address[:-6], int(whisper_address[-5:]),
                        online_address[:-6], int(online_address[-5:]))
            except requests.RequestException:
                time.sleep(2)
        return None, None, None, None

    def guest_token(self, uid, password):
        url = "https://ffmconnect.ggpolarbear.com/oauth/guest/token/grant"
        headers = {
            "Host": "ffmconnect.ggpolarbear.com",
            "User-Agent": "GarenaMSDK/4.0.19P4(G011A ;Android 10;en;EN;)",
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "close",
        }
        data = {
            "uid": f"{uid}",
            "password": f"{password}",
            "response_type": "token",
            "client_type": "2",
            "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
            "client_id": "100067",
        }
        response = requests.post(url, headers=headers, data=data)
        resp_data = response.json()
        return self.TOKEN_MAKER(
            "10e299be9f8199bd50f8c52bbae4695bc1935563ba17d3859c97237bd45cb428",
            resp_data["access_token"],
            "b70245b92be827af56d8932346f351f2",
            resp_data["open_id"],
            uid
        )

    def TOKEN_MAKER(self, OLD_ACCESS_TOKEN, NEW_ACCESS_TOKEN, OLD_OPEN_ID, NEW_OPEN_ID, id):
        headers = {
            "X-Unity-Version": "2018.4.11f1",
            "ReleaseVersion": FreeFireVersion,
            "Content-Type": "application/x-www-form-urlencoded",
            "X-GA": "v1 1",
            "Content-Length": "928",
            "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 7.1.2; ASUS_Z01QD Build/QKQ1.190825.002)",
            "Host": "loginbp.ggpolarbear.com",
            "Connection": "Keep-Alive",
            "Accept-Encoding": "gzip",
        }
        data = bytes.fromhex(Payload1A13)
        data = data.replace(OLD_OPEN_ID.encode(), NEW_OPEN_ID.encode())
        data = data.replace(OLD_ACCESS_TOKEN.encode(), NEW_ACCESS_TOKEN.encode())
        Final_Payload = bytes.fromhex(encrypt_api(data.hex()))
        RESPONSE = requests.post(MajorLoginRegion, headers=headers, data=Final_Payload, verify=False)
        
        if RESPONSE.status_code == 200 and len(RESPONSE.text) > 10:
            combined_timestamp, key, iv, BASE64_TOKEN = self.parse_my_message(RESPONSE.content)
            w_ip, w_port, o_ip, o_port = self.GET_PAYLOAD_BY_DATA(BASE64_TOKEN, NEW_ACCESS_TOKEN, 1)
            self.key, self.iv = key, iv
            return BASE64_TOKEN, key, iv, combined_timestamp, w_ip, w_port, o_ip, o_port
        return False

    def get_tok(self):
        token_data = self.guest_token(self.account_id, self.password)
        if not token_data:
            self.restart()
            return

        token, key, iv, Timestamp, whisper_ip, whisper_port, online_ip, online_port = token_data
        try:
            decoded = jwt.decode(token, options={"verify_signature": False})
            encoded_acc = hex(decoded.get("account_id"))[2:]
            time_hex = hex(Timestamp)[2:].zfill(2)
            BASE64_TOKEN_ = token.encode().hex()
            
            zeros_map = {9: "0000000", 8: "00000000", 10: "000000", 7: "000000000"}
            zeros = zeros_map.get(len(encoded_acc), "00000000")
            head = hex(len(encrypt_packet(BASE64_TOKEN_, key, iv)) // 2)[2:]
            final_token = f"0115{zeros}{encoded_acc}{time_hex}00000{head}" + encrypt_packet(BASE64_TOKEN_, key, iv)
            
            self.connect(final_token, "anything", key, iv, whisper_ip, whisper_port, online_ip, online_port)
        except Exception:
            self.restart()

    def execute_command(self, command, *args):
        if command == "/XRRR":
            try:
                if not self.socket_client or not self.is_socket_connected(self.socket_client):
                    return "Socket not connected, please wait for connection..."

                team_code = args[0] if len(args) > 0 else None
                account_name = args[1] if len(args) > 1 else "UnknownGhost"

                if not team_code:
                    return "No team code provided"

                self.socket_client.send(GenJoinSquadsPacket(team_code, self.key, self.iv))
                time.sleep(0.2)
                
                start_time = time.time()
                got_0500, idT, sq = False, None, None

                while not got_0500 and (time.time() - start_time) < 8:
                    if self.DaTa2 and len(self.DaTa2.hex()) >= 4 and "0500" in self.DaTa2.hex()[0:4]:
                        try:
                            dT = json.loads(DeCode_PackEt(self.DaTa2.hex()[10:]))
                            if "5" in dT and "31" in dT["5"]["data"]:
                                sq = dT["5"]["data"]["31"]["data"]
                                idT = dT["5"]["data"]["1"]["data"]
                                got_0500 = True
                                break
                        except Exception:
                            pass
                    time.sleep(0.05)

                if not got_0500:
                    return f"Failed to get response for team code {team_code} within timeout"

                self.socket_client.send(ExiT(self.account_id, self.key, self.iv))
                time.sleep(0.05)
                self.socket_client.send(ghost_pakcet(idT, account_name, sq, self.key, self.iv))
                time.sleep(0.05)
                self.socket_client.send(ExiT(self.account_id, self.key, self.iv))

                return f"Successfully joined"
            except Exception as e:
                return f"Error executing command: {e}"
        
        elif command == "/LEAVE":
            try:
                if not self.socket_client or not self.is_socket_connected(self.socket_client):
                    return "Socket not connected, unable to leave."
                
                self.socket_client.send(ExiT(self.account_id, self.key, self.iv))
                self.socket_client.close()
                self.socket_client = None
                return f"Ghost left the squad successfully."
            except Exception as e:
                return f"Error leaving squad: {e}"
                
        return f"Unknown command: {command}"

def load_accounts(file_path):
    with open(file_path, "r") as file:
        return json.load(file)

def cleanup():
    global shutting_down
    shutting_down = True
    for account_id, client in list(clients.items()):
        client.stop()
        del clients[account_id]

def initialize_clients_if_needed():
    if not clients and not shutting_down:
        try:
            accs = load_accounts("accounts.json")
            for account_id, password in accs.items():
                client = TcpBotConnectMain(account_id, password)
                clients[account_id] = client
                t = threading.Thread(target=client.run, daemon=True)
                t.start()
                time.sleep(0.5)
        except Exception:
            pass

@app.route("/", methods=["GET"])
def home():
    response_data = {
        "Developer": "Riduanul Islam",
        "TelegramBot": "https://t.me/RiduanFFBot",
        "TelegramChannel": "https://t.me/RiduanOfficialBD",
        "Project": "FreeFire Ghost Bot API",
        "Message": "Welcome to Riduan Ghost API",
        "API_Usage_Guide": {
            "Type_1_Default_Single": "/ghost?teamcode={teamcode}",
            "Type_2_Default_Multiple": "/ghost?teamcode={teamcode}&ghost={count}",
            "Type_3_Custom_Single": "/ghost?teamcode={teamcode}&name={name}",
            "Type_4_Custom_Multiple_Same_Name": "/ghost?teamcode={teamcode}&name={name}&ghost={count}",
            "Type_5_Custom_Multiple_Diff_Names": "/ghost?teamcode={teamcode}&name={name1},{name2},{name3}&ghost={count}",
            "Leave_Squad": "/leave"
        },
        "Demo_Examples": {
            "Type_1": "/ghost?teamcode=1234567",
            "Type_2": "/ghost?teamcode=1234567&ghost=3",
            "Type_3": "/ghost?teamcode=1234567&name=ProPlayer",
            "Type_4": "/ghost?teamcode=1234567&name=ProPlayer&ghost=3",
            "Type_5": "/ghost?teamcode=1234567&name=Bot1,Bot2,Bot3&ghost=3"
        }
    }
    return jsonify(response_data), 200

@app.route("/ghost", methods=["GET"])
def ghost():
    if shutting_down:
        return jsonify({"error": "Server is shutting down"}), 503

    initialize_clients_if_needed()

    teamcode = request.args.get("teamcode")
    ghost_count_param = request.args.get("ghost")
    name_param = request.args.get("name")
    default_name = "—͞Rɪᴅᴜᴀɴ Cᴏᴅᴇx </>"

    if not teamcode:
        return jsonify({
            "Developer": "Riduanul Islam",
            "TelegramBot": "https://t.me/RiduanFFBot",
            "TelegramChannel": "https://t.me/RiduanOfficialBD",
            "error": "teamcode parameter is required"
        }), 400

    try:
        if ghost_count_param:
            ghost_count = int(ghost_count_param)
            ghost_count = max(1, min(5, ghost_count))
        else:
            ghost_count = 1
    except ValueError:
        ghost_count = 1

    if name_param:
        parsed_names = [n.strip() for n in name_param.split(",") if n.strip()]
        if not parsed_names:
            final_names = [default_name] * 5
        elif len(parsed_names) == 1:
            final_names = [parsed_names[0]] * 5
        else:
            final_names = parsed_names
    else:
        final_names = [default_name] * 5

    while len(final_names) < 5:
        final_names.append(final_names[-1])

    available_clients = sorted(clients.items(), key=lambda x: int(x[0]))
    if not available_clients:
        return jsonify({
            "Developer": "Riduanul Islam",
            "TelegramBot": "https://t.me/RiduanFFBot",
            "TelegramChannel": "https://t.me/RiduanOfficialBD",
            "error": "No clients available to deploy"
        }), 500

    actual_ghosts_to_deploy = min(ghost_count, len(available_clients))
    selected_clients = available_clients[:actual_ghosts_to_deploy]

    results = {}
    
    def deploy_bot(client_data):
        idx, account_id, client = client_data
        assigned_name = final_names[idx]
        result = client.execute_command("/XRRR", teamcode, assigned_name)
        return account_id, f"{result} | Name: {assigned_name}"

    client_data_list = [(idx, acc_id, cl) for idx, (acc_id, cl) in enumerate(selected_clients)]

    with concurrent.futures.ThreadPoolExecutor(max_workers=actual_ghosts_to_deploy) as executor:
        futures = [executor.submit(deploy_bot, data) for data in client_data_list]
        for future in concurrent.futures.as_completed(futures):
            acc_id, res = future.result()
            results[acc_id] = res

    response_data = {
        "Developer": "Riduanul Islam",
        "TelegramBot": "https://t.me/RiduanFFBot",
        "TelegramChannel": "https://t.me/RiduanOfficialBD",
        "teamcode": teamcode,
        "ghosts_deployed": actual_ghosts_to_deploy,
        "results": results
    }
    
    return jsonify(response_data)

@app.route("/leave", methods=["GET"])
def leave_group():
    if shutting_down:
        return jsonify({"error": "Server is shutting down"}), 503

    initialize_clients_if_needed()
    results = {}
    
    def leave_bot(acc_id, client):
        return acc_id, client.execute_command("/LEAVE")

    with concurrent.futures.ThreadPoolExecutor(max_workers=len(clients)) as executor:
        futures = [executor.submit(leave_bot, acc_id, client) for acc_id, client in clients.items()]
        for future in concurrent.futures.as_completed(futures):
            acc_id, res = future.result()
            results[acc_id] = res

    response_data = {
        "Developer": "Riduanul Islam",
        "TelegramBot": "https://t.me/RiduanFFBot",
        "TelegramChannel": "https://t.me/RiduanOfficialBD",
        "Action": "Leave All Groups",
        "results": results
    }
    
    return jsonify(response_data)

def signal_handler(sig, frame):
    cleanup()
    sys.exit(0)

if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    atexit.register(cleanup)
    
    initialize_clients_if_needed()

    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)