import base64, json, hashlib, re, sys

import paho.mqtt.client as mqtt
from urllib import parse
import urllib3

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization

class VigiCamera:
    def __init__(self, ip) -> None:
        self.ip = ip
        self.username = None
        self.password_hash = None
        self.stok = None
        self.headers = {"Accept": "application/json", "Content-Type": "application/json; charset=UTF-8"}

        context = urllib3.util.create_urllib3_context()
        context.set_ciphers("AES256-GCM-SHA384")
        context.check_hostname = False

        self.http = urllib3.PoolManager(cert_reqs = "CERT_NONE", ssl_context=context)

    """
    Authenticates the camera object.
    """
    def auth(self, username: str, password: str) -> bool:
        self.username = username
        self.password = password
        prefixed = f"TPCQ75NF2Y:{password}"
        self.password_hash = hashlib.md5(prefixed.encode()).hexdigest().upper()

        # Get nonce, encryption key info from camera
        authReqBody = {'user_management': {'get_encrypt_info': None}, 'method': 'do'}
        authReq = self.http.request("POST", f"https://{self.ip}/", headers=self.headers, json=authReqBody)
        nonce = authReq.json()['data']['nonce']
        key = authReq.json()['data']['key']

        print(f"Authenticating with {self.username}, {self.password_hash}, {nonce}, {key}")
            
        public_key_der = base64.b64decode(parse.unquote(key))
        public_key = serialization.load_der_public_key(public_key_der)

        a = f"{self.password_hash}:{nonce}"
        encrypted = base64.b64encode(public_key.encrypt(a.encode(), padding.PKCS1v15())).decode()

        body = {"method":"do", "login": {"username": username, "password": encrypted, "passwdType":"md5","encrypt_type":"2"}}
        print(f"Sending {body}")
        resp = self.http.request("POST", f"https://{self.ip}/", json=body, headers=self.headers)

        if resp.json()["error_code"] == 0:
            print(resp.json())
            self.stok = resp.json()["stok"]
            return True
        else:
            print("Auth failed:", resp.json())
            return False
        
    def test_auth(self) -> bool:
        req = self.http.request("POST", f"https://{self.ip}/stok={self.stok}/ds", json={"image":{"name":"switch"},"method":"get"}, headers=self.headers)
        if req.json()["error_code"] == 0:
            return True
        else:
            # Try to log out?
            # self.http.request("POST", f"https://{self.ip}/stok={self.stok}/ds", json={"system":{"logout":None},"method":"do"}, headers=self.headers)
            # Try to re-auth
            return self.auth(self.username, self.password)


    def set_mode(self, lights_on: bool) -> None:
        if self.stok is None:
            raise PermissionError("The camera is not yet authenticated.")
        
        if not self.test_auth():
            raise PermissionError("Unable to re-authenticate camera.")

        if lights_on:
            # Set night vision mode to colour (white LEDs), set illuminators to always on
            self.http.request("POST", f"https://{self.ip}/stok={self.stok}/ds", json={"method":"set", "image": {"switch": {"night_vision_mode": "wtl_night_vision"}}}, headers=self.headers)
            self.http.request("POST", f"https://{self.ip}/stok={self.stok}/ds", json={'image': {'common': {'inf_type': 'on', 'wtl_type': 'on'}}, 'method': 'set'}, headers=self.headers)
        else:
            self.http.request("POST", f"https://{self.ip}/stok={self.stok}/ds", json={"method":"set", "image": {"switch": {"night_vision_mode": "inf_night_vision"}}}, headers=self.headers)
            self.http.request("POST", f"https://{self.ip}/stok={self.stok}/ds", json={'image': {'common': {'inf_type': 'auto', 'wtl_type': 'auto'}}, 'method': 'set'}, headers=self.headers)

def on_mqtt_connect(client, userdata, flags, rc):
    print("Connected with result code "+str(rc))

    if rc != 0:
        sys.exit(1)

    # Subscribing in on_connect() means that if we lose the connection and reconnect then subscriptions will be renewed.
    for cam_name in cameras:
        print(f"Subscribed to vigi_leds/{cam_name}/mode")
        client.subscribe(f"vigi_leds/{cam_name}/mode")

def on_mqtt_message(client, userdata, msg):
    # Use a named group to identify camera name
    exp = re.compile(r"(?:vigi_leds/)(?P<cam>.+)(?:/mode)")
    match = exp.match(msg.topic)
    if match is not None:
        cameras[match.group("cam")].set_mode(msg.payload.decode() == "on")


cameras = {}

urllib3.disable_warnings()
client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION1)
client.on_connect = on_mqtt_connect
client.on_message = on_mqtt_message

with open("config.json") as config_file:
    config_data = json.loads(config_file.read())

    for camera_datum in config_data["cameras"]:
        cameras[camera_datum["name"]] = VigiCamera(camera_datum["ip"])
        if cameras[camera_datum["name"]].auth(camera_datum["username"], camera_datum["password"]):
            print(f"Authenticated {camera_datum['name']}")
        else:
            print(f"Unable to authenticate {camera_datum['name']}")

    client.username_pw_set(config_data["mqtt_username"], config_data["mqtt_password"])
    client.connect(config_data["mqtt_host"], 1883, 60)

client.loop_forever()