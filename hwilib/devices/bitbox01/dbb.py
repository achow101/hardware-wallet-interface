# Adapted from https://github.com/digitalbitbox/mcu/blob/master/py/dbb_utils.py

import base64
import binascii
import hid
import hashlib
import hmac
import json
import os
import pyaes
import struct
import socket

applen = 225280 # flash size minus bootloader length
chunksize = 8*512
usb_report_size = 64 # firmware > v2.0
report_buf_size = 4096 # firmware v2.0.0
boot_buf_size_send = 4098
boot_buf_size_reply = 256
HWW_CID = 0xFF000000
HWW_CMD = 0x80 + 0x40 + 0x01

DBB_VENDOR_ID = 0x03eb
DBB_1_DEVICE_ID = 0x2402
DBB_2_DEVICE_ID = 0x2403

class BitboxSimulator():
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.connect((self.ip, self.port))
        self.socket.settimeout(1)

    def send_recv(self, msg):
        self.socket.sendall(msg)
        data = self.socket.recv(3584)
        return data

    def close(self):
        self.socket.close()

    def get_serial_number_string(self):
        return 'dbb_fw:v5.0.0'

def aes_encrypt_with_iv(key, iv, data):
    aes_cbc = pyaes.AESModeOfOperationCBC(key, iv=iv)
    aes = pyaes.Encrypter(aes_cbc)
    e = aes.feed(data) + aes.feed()  # empty aes.feed() appends pkcs padding
    return e

def aes_decrypt_with_iv(key, iv, data):
    aes_cbc = pyaes.AESModeOfOperationCBC(key, iv=iv)
    aes = pyaes.Decrypter(aes_cbc)
    s = aes.feed(data) + aes.feed()  # empty aes.feed() strips pkcs padding
    return s

def encrypt_aes(secret, s):
    iv = bytes(os.urandom(16))
    ct = aes_encrypt_with_iv(secret, iv, s)
    e = iv + ct
    return e

def decrypt_aes(secret, e):
    iv, e = e[:16], e[16:]
    s = aes_decrypt_with_iv(secret, iv, e)
    return s

def sha256(x):
    return hashlib.sha256(x).digest()

def sha512(x):
    return hashlib.sha512(x).digest()

def double_hash(x):
    if type(x) is not bytearray: x=x.encode('utf-8')
    return sha256(sha256(x))

def derive_keys(x):
    h = double_hash(x)
    h = sha512(h)
    return (h[:len(h)//2], h[len(h)//2:])

def to_string(x, enc):
    if isinstance(x, (bytes, bytearray)):
        return x.decode(enc)
    if isinstance(x, str):
        return x
    else:
        raise TypeError("Not a string or bytes like object")

def send_frame(data, device):
    data = bytearray(data)
    data_len = len(data)
    seq = 0;
    idx = 0;
    write = []
    while idx < data_len:
        if idx == 0:
            # INIT frame
            write = data[idx : idx + min(data_len, usb_report_size - 7)]
            device.write(b'\0' + struct.pack(">IBH",HWW_CID, HWW_CMD, data_len & 0xFFFF) + write + b'\xEE' * (usb_report_size - 7 - len(write)))
        else:
            # CONT frame
            write = data[idx : idx + min(data_len, usb_report_size - 5)]
            device.write(b'\0' + struct.pack(">IB", HWW_CID, seq) + write + b'\xEE' * (usb_report_size - 5 - len(write)))
            seq += 1
        idx += len(write)

def read_frame(device):
    # INIT response
    read = bytearray(device.read(usb_report_size))
    cid = ((read[0] * 256 + read[1]) * 256 + read[2]) * 256 + read[3]
    cmd = read[4]
    data_len = read[5] * 256 + read[6]
    data = read[7:]
    idx = len(read) - 7;
    while idx < data_len:
        # CONT response
        read = bytearray(device.read(usb_report_size))
        data += read[5:]
        idx += len(read) - 5
    assert cid == HWW_CID, '- USB command ID mismatch'
    assert cmd == HWW_CMD, '- USB command frame mismatch'
    return data

def get_firmware_version(device):
    serial_number = device.get_serial_number_string()
    split_serial = serial_number.split(':')
    firm_ver = split_serial[1][1:] # Version is vX.Y.Z, we just need X.Y.Z
    split_ver = firm_ver.split('.')
    return (int(split_ver[0]), int(split_ver[1]), int(split_ver[2])) # major, minor, revision

def send_plain(msg, device):
    reply = ""
    try:
        if isinstance(device, BitboxSimulator):
            r = device.send_recv(msg)
        else:
            firm_ver = get_firmware_version(device)
            if (firm_ver[0] == 2 and firm_ver[1] == 0) or (firm_ver[0] == 1):
                hidBufSize = 4096
                device.write('\0' + msg + '\0' * (hidBufSize - len(msg)))
                r = bytearray()
                while len(r) < hidBufSize:
                    r += bytearray(self.dbb_hid.read(hidBufSize))
            else:
                send_frame(msg, device)
                r = read_frame(device)
        r = r.rstrip(b' \t\r\n\0')
        r = r.replace(b"\0", b'')
        r = to_string(r, 'utf8')
        reply = json.loads(r)
    except Exception as e:
        reply = json.loads('{"error":"Exception caught while sending plaintext message to DigitalBitbox ' + str(e) + '"}')
    return reply

def send_encrypt(msg, password, device):
    reply = ""
    try:
        firm_ver = get_firmware_version(device)
        if firm_ver[0] >= 5:
            encryption_key, authentication_key = derive_keys(password)
            msg = encrypt_aes(encryption_key, msg)
            hmac_digest = hmac.new(authentication_key, msg, digestmod=hashlib.sha256).digest()
            authenticated_msg = base64.b64encode(msg + hmac_digest)
        else:
            encryption_key = double_hash(password)
            authenticated_msg = base64.b64encode(encrypt_aes(encryption_key, msg))
        reply = send_plain(authenticated_msg, device)
        if 'ciphertext' in reply:
            b64_unencoded = bytes(base64.b64decode(''.join(reply["ciphertext"])))
            if firm_ver[0] >= 5:
                msg = b64_unencoded[:-32]
                reply_hmac = b64_unencoded[-32:]
                hmac_calculated = hmac.new(authentication_key, msg, digestmod=hashlib.sha256).digest()
                if not hmac.compare_digest(reply_hmac, hmac_calculated):
                    raise Exception("Failed to validate HMAC")
            else:
                msg = b64_unencoded
            reply = decrypt_aes(encryption_key, msg)
            reply = json.loads(reply.decode("utf-8"))
        if 'error' in reply:
            password = None
    except Exception as e:
        import traceback
        traceback.print_exc()
        reply = {'error':'Exception caught while sending encrypted message to DigitalBitbox ' + str(e)}
    return reply

