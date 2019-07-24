# Digital Bitbox interaction script

import base64
import binascii
import hashlib
import hid
import struct
import json
import logging
import sys
import time

from ..hwwclient import HardwareWalletClient
from ..errors import ActionCanceledError, BadArgumentError, DeviceFailureError, DeviceAlreadyInitError, DEVICE_NOT_INITIALIZED, DeviceNotReadyError, HWWError, NoPasswordError, UnavailableActionError, UNKNWON_DEVICE_TYPE, UNKNOWN_ERROR, common_err_msgs, handle_errors
from ..serializations import CTransaction, PSBT, hash256, hash160, ser_sig_der, ser_sig_compact, ser_compact_size
from ..base58 import get_xpub_fingerprint, decode, to_address, xpub_main_2_test, get_xpub_fingerprint_hex
from .bitbox01.dbb import BitboxSimulator, DBB_VENDOR_ID, DBB_1_DEVICE_ID, DBB_2_DEVICE_ID, send_encrypt, send_plain

# Errors codes from the device
bad_args = [
    102, # The password length must be at least " STRINGIFY(PASSWORD_LEN_MIN) " characters.
    103, # No input received.
    104, # Invalid command.
    105, # Only one command allowed at a time.
    109, # JSON parse error.
    204, # Invalid seed.
    253, # Incorrect serialized pubkey length. A 33-byte hexadecimal value (66 characters) is expected.
    254, # Incorrect serialized pubkey hash length. A 32-byte hexadecimal value (64 characters) is expected.
    256, # Failed to pair with second factor, because the previously received hash of the public key does not match the computed hash of the public key.
    300, # Incorrect pubkey length. A 33-byte hexadecimal value (66 characters) is expected.
    301, # Incorrect hash length. A 32-byte hexadecimal value (64 characters) is expected.
    304, # Incorrect TFA pin.
    411, # Filenames limited to alphanumeric values, hyphens, and underscores.
    412, # Please provide an encryption key.
    112, # Device password matches reset password. Disabling reset password.
    251, # Could not generate key.
]

device_failures = [
    101, # Please set a password.
    107, # Output buffer overflow.
    200, # Seed creation requires an SD card for automatic encrypted backup of the seed.
    250, # Master key not present.
    252, # Could not generate ECDH secret.
    303, # Could not sign.
    400, # Please insert SD card.
    401, # Could not mount the SD card.
    402, # Could not open a file to write - it may already exist.
    403, # Could not open the directory.
    405, # Could not write the file.
    407, # Could not read the file.
    408, # May not have erased all files (or no file present).
    410, # Backup file does not match wallet.
    500, # Chip communication error.
    501, # Could not read flash.
    502, # Could not encrypt.
    110, # Too many failed access attempts. Device reset.
    111, # Device locked. Erase device to access this command.
    113, # Due to many login attempts, the next login requires holding the touch button for 3 seconds.
    900, # attempts remain before the device is reset.
    901, # Ignored for non-embedded testing.
    902, # Too many backup files to read. The list is truncated.
    903, # attempts remain before the device is reset. The next login requires holding the touch button.
]

cancels = [
    600, # Aborted by user.
    601, # Touchbutton timed out.
]

ERR_MEM_SETUP = 503 # Device initialization in progress.

class DBBError(Exception):
    def __init__(self, error):
        Exception.__init__(self)
        self.error = error

    def get_error(self):
        return self.error['error']['message']

    def get_code(self):
        return self.error['error']['code']

    def __str__(self):
        return 'Error: {}, Code: {}'.format(self.error['error']['message'], self.error['error']['code'])

def digitalbitbox_exception(f):
    def func(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except DBBError as e:
            if e.get_code() in bad_args:
                raise BadArgumentError(e.get_error())
            elif e.get_code() in device_failures:
                raise DeviceFailureError(e.get_error())
            elif e.get_code() in cancels:
                raise ActionCanceledError(e.get_error())
            elif e.get_code() == ERR_MEM_SETUP:
                raise DeviceNotReadyError(e.get_error())

    return func

def stretch_backup_key(password):
    key = hashlib.pbkdf2_hmac('sha512', password.encode(), b'Digital Bitbox', 20480)
    return binascii.hexlify(key).decode()

def format_backup_filename(name):
    return '{}-{}.pdf'.format(name, time.strftime('%Y-%m-%d-%H-%M-%S', time.localtime()))

# This class extends the HardwareWalletClient for Digital Bitbox 1 specific things
class Digitalbitbox1Client(HardwareWalletClient):

    def __init__(self, path, password):
        super(Digitalbitbox1Client, self).__init__(path, password)
        if not password:
            raise NoPasswordError('Password must be supplied for digital BitBox')
        if path.startswith('udp:'):
            split_path = path.split(':')
            ip = split_path[1]
            port = int(split_path[2])
            self.device = BitboxSimulator(ip, port)
        else:
            self.device = hid.device()
            self.device.open_path(path.encode())
        self.password = password

    # Must return a dict with the xpub
    # Retrieves the public key at the specified BIP 32 derivation path
    @digitalbitbox_exception
    def get_pubkey_at_path(self, path):
        if '\'' not in path and 'h' not in path and 'H' not in path:
            raise BadArgumentError('The digital bitbox requires one part of the derivation path to be derived using hardened keys')
        reply = send_encrypt('{"xpub":"' + path + '"}', self.password, self.device)
        if 'error' in reply:
            raise DBBError(reply)

        if self.is_testnet:
            return {'xpub':xpub_main_2_test(reply['xpub'])}
        else:
            return {'xpub':reply['xpub']}

    # Must return a hex string with the signed transaction
    # The tx must be in the PSBT format
    @digitalbitbox_exception
    def sign_tx(self, tx):

        # Create a transaction with all scriptsigs blanekd out
        blank_tx = CTransaction(tx.tx)

        # Get the master key fingerprint
        master_fp = get_xpub_fingerprint(self.get_pubkey_at_path('m/0h')['xpub'])

        # create sighashes
        sighash_tuples = []
        for txin, psbt_in, i_num in zip(blank_tx.vin, tx.inputs, range(len(blank_tx.vin))):
            sighash = b""
            pubkeys = []
            if psbt_in.non_witness_utxo:
                utxo = psbt_in.non_witness_utxo.vout[txin.prevout.n]

                # Check if P2SH
                if utxo.is_p2sh():
                    # Look up redeemscript
                    redeemscript = psbt_in.redeem_script
                    # Add to blank_tx
                    txin.scriptSig = redeemscript
                # Check if P2PKH
                elif utxo.is_p2pkh() or utxo.is_p2pk():
                    txin.scriptSig = psbt_in.non_witness_utxo.vout[txin.prevout.n].scriptPubKey
                # We don't know what this is, skip it
                else:
                    continue

                # Serialize and add sighash ALL
                ser_tx = blank_tx.serialize_without_witness()
                ser_tx += b"\x01\x00\x00\x00"

                # Hash it
                sighash += hash256(ser_tx)
                txin.scriptSig = b""
            elif psbt_in.witness_utxo:
                # Calculate hashPrevouts and hashSequence
                prevouts_preimage = b""
                sequence_preimage = b""
                for inputs in blank_tx.vin:
                    prevouts_preimage += inputs.prevout.serialize()
                    sequence_preimage += struct.pack("<I", inputs.nSequence)
                hashPrevouts = hash256(prevouts_preimage)
                hashSequence = hash256(sequence_preimage)

                # Calculate hashOutputs
                outputs_preimage = b""
                for output in blank_tx.vout:
                    outputs_preimage += output.serialize()
                hashOutputs = hash256(outputs_preimage)

                # Get the scriptCode
                scriptCode = b""
                witness_program = b""
                if psbt_in.witness_utxo.is_p2sh():
                    # Look up redeemscript
                    redeemscript = psbt_in.redeem_script
                    witness_program = redeemscript
                else:
                    witness_program = psbt_in.witness_utxo.scriptPubKey

                # Check if witness_program is script hash
                if len(witness_program) == 34 and witness_program[0] == 0x00 and witness_program[1] == 0x20:
                    # look up witnessscript and set as scriptCode
                    witnessscript = psbt_in.witness_script
                    scriptCode += ser_compact_size(len(witnessscript)) + witnessscript
                else:
                    scriptCode += b"\x19\x76\xa9\x14"
                    scriptCode += witness_program[2:]
                    scriptCode += b"\x88\xac"

                # Make sighash preimage
                preimage = b""
                preimage += struct.pack("<i", blank_tx.nVersion)
                preimage += hashPrevouts
                preimage += hashSequence
                preimage += txin.prevout.serialize()
                preimage += scriptCode
                preimage += struct.pack("<q", psbt_in.witness_utxo.nValue)
                preimage += struct.pack("<I", txin.nSequence)
                preimage += hashOutputs
                preimage += struct.pack("<I", tx.tx.nLockTime)
                preimage += b"\x01\x00\x00\x00"

                # hash it
                sighash = hash256(preimage)

            # Figure out which keypath thing is for this input
            for pubkey, keypath in psbt_in.hd_keypaths.items():
                if master_fp == keypath[0]:
                    # Add the keypath strings
                    keypath_str = 'm'
                    for index in keypath[1:]:
                        keypath_str += '/'
                        if index >= 0x80000000:
                            keypath_str += str(index - 0x80000000) + 'h'
                        else:
                            keypath_str += str(index)

                    # Create tuples and add to List
                    tup = (binascii.hexlify(sighash).decode(), keypath_str, i_num, pubkey)
                    sighash_tuples.append(tup)

        # Return early if nothing to do
        if len(sighash_tuples) == 0:
            return {'psbt':tx.serialize()}

        # Sign the sighashes
        to_send = '{"sign":{"data":['
        for tup in sighash_tuples:
            to_send += '{"hash":"'
            to_send += tup[0]
            to_send += '","keypath":"'
            to_send += tup[1]
            to_send += '"},'
        if to_send[-1] == ',':
            to_send = to_send[:-1]
        to_send += ']}}'
        logging.debug(to_send)

        reply = send_encrypt(to_send, self.password, self.device)
        logging.debug(reply)
        if 'error' in reply:
            raise DBBError(reply)
        print("Touch the device for 3 seconds to sign. Touch briefly to cancel", file=sys.stderr)
        reply = send_encrypt(to_send, self.password, self.device)
        logging.debug(reply)
        if 'error' in reply:
            raise DBBError(reply)

        # Extract sigs
        sigs = []
        for item in reply['sign']:
            sigs.append(binascii.unhexlify(item['sig']))

        # Make sigs der
        der_sigs = []
        for sig in sigs:
            der_sigs.append(ser_sig_der(sig[0:32], sig[32:64]))

        # add sigs to tx
        for tup, sig in zip(sighash_tuples, der_sigs):
            tx.inputs[tup[2]].partial_sigs[tup[3]] = sig

        return {'psbt':tx.serialize()}

    # Must return a base64 encoded string with the signed message
    # The message can be any string
    @digitalbitbox_exception
    def sign_message(self, message, keypath):
        to_hash = b""
        to_hash += self.message_magic
        to_hash += ser_compact_size(len(message))
        to_hash += message.encode()

        hashed_message = hash256(to_hash)

        to_send = '{"sign":{"data":[{"hash":"'
        to_send += binascii.hexlify(hashed_message).decode()
        to_send += '","keypath":"'
        to_send += keypath
        to_send += '"}]}}'

        reply = send_encrypt(to_send, self.password, self.device)
        logging.debug(reply)
        if 'error' in reply:
            raise DBBError(reply)
        print("Touch the device for 3 seconds to sign. Touch briefly to cancel", file=sys.stderr)
        reply = send_encrypt(to_send, self.password, self.device)
        logging.debug(reply)
        if 'error' in reply:
            raise DBBError(reply)

        sig = binascii.unhexlify(reply['sign'][0]['sig'])
        r = sig[0:32]
        s = sig[32:64]
        recid = binascii.unhexlify(reply['sign'][0]['recid'])
        compact_sig = ser_sig_compact(r, s, recid)
        logging.debug(binascii.hexlify(compact_sig))

        return {"signature":base64.b64encode(compact_sig).decode('utf-8')}

    # Display address of specified type on the device. Only supports single-key based addresses.
    def display_address(self, keypath, p2sh_p2wpkh, bech32):
        raise UnavailableActionError('The Digital Bitbox does not have a screen to display addresses on')

    # Setup a new device
    @digitalbitbox_exception
    def setup_device(self, label='', passphrase=''):
        # Make sure this is not initialized
        reply = send_encrypt('{"device" : "info"}', self.password, self.device)
        if 'error' not in reply or ('error' in reply and reply['error']['code'] != 101):
            raise DeviceAlreadyInitError('Device is already initialized. Use wipe first and try again')

        # Need a wallet name and backup passphrase
        if not label or not passphrase:
            raise BadArgumentError('The label and backup passphrase for a new Digital Bitbox wallet must be specified and cannot be empty')

        # Set password
        to_send = {'password': self.password}
        reply = send_plain(json.dumps(to_send).encode(), self.device)

        # Now make the wallet
        key = stretch_backup_key(passphrase)
        backup_filename = format_backup_filename(label)
        to_send = {'seed': {'source': 'create', 'key': key, 'filename': backup_filename}}
        reply = send_encrypt(json.dumps(to_send).encode(), self.password, self.device)
        if 'error' in reply:
            return {'success': False, 'error': reply['error']['message']}
        return {'success': True}

    # Wipe this device
    @digitalbitbox_exception
    def wipe_device(self):
        reply = send_encrypt('{"reset" : "__ERASE__"}', self.password, self.device)
        if 'error' in reply:
            return {'success': False, 'error': reply['error']['message']}
        return {'success': True}

    # Restore device from mnemonic or xprv
    def restore_device(self, label=''):
        raise UnavailableActionError('The Digital Bitbox does not support restoring via software')

    # Begin backup process
    @digitalbitbox_exception
    def backup_device(self, label='', passphrase=''):
        # Need a wallet name and backup passphrase
        if not label or not passphrase:
            raise BadArgumentError('The label and backup passphrase for a Digital Bitbox backup must be specified and cannot be empty')

        key = stretch_backup_key(passphrase)
        backup_filename = format_backup_filename(label)
        to_send = {'backup': {'source': 'all', 'key': key, 'filename': backup_filename}}
        reply = send_encrypt(json.dumps(to_send).encode(), self.password, self.device)
        if 'error' in reply:
            raise DBBError(reply)
        return {'success': True}

    # Close the device
    def close(self):
        self.device.close()

    # Prompt pin
    def prompt_pin(self):
        raise UnavailableActionError('The Digital Bitbox does not need a PIN sent from the host')

    # Send pin
    def send_pin(self, pin):
        raise UnavailableActionError('The Digital Bitbox does not need a PIN sent from the host')

# This class extends the HardwareWalletClient for Digital Bitbox specific things
class DigitalbitboxClient(HardwareWalletClient):

    def __init__(self, path, password):
        self.client = None
        super(DigitalbitboxClient, self).__init__(path, password)
        if path.startswith('udp:'):
            self.client = Digitalbitbox1Client(path, password)
        else:
            device = hid.device()
            prod_id = device['product_id']
            device.open_path(path.encode())
            device.close()

            if prod_id == DBB_1_DEVICE_ID:
                self.client = Digitalbitbox1Client(path, password)
            else:
                raise UnknownDeviceError('Specified device is not a known Digital Bitbox device.')

    # Must return a dict with the xpub
    # Retrieves the public key at the specified BIP 32 derivation path
    def get_pubkey_at_path(self, path):
        return self.client.get_pubkey_at_path(path)

    # Must return a hex string with the signed transaction
    # The tx must be in the combined unsigned transaction format
    def sign_tx(self, tx):
        return self.client.sign_tx(tx)

    # Must return a base64 encoded string with the signed message
    # The message can be any string. keypath is the bip 32 derivation path for the key to sign with
    def sign_message(self, message, keypath):
        return self.client.sign_message(message, keypath)

    # Display address of specified type on the device. Only supports single-key based addresses.
    def display_address(self, keypath, p2sh_p2wpkh, bech32):
        return self.client.display_address(keypath, p2sh_p2wpkh, bech32)

    # Setup a new device
    def setup_device(self, label='', passphrase=''):
        return self.client.setup_device(label, passphrase)

    # Wipe this device
    def wipe_device(self):
        return self.client.wipe_device()

    # Restore device from mnemonic or xprv
    def restore_device(self, label=''):
        return self.client.restore_device(label)

    # Begin backup process
    def backup_device(self, label='', passphrase=''):
        return self.client.backup_device(label, passphrase)

    # Close the device
    def close(self):
        return self.client.close()

    # Prompt pin
    def prompt_pin(self):
        return self.client.prompt_pin()

    # Send pin
    def send_pin(self, pin):
        return self.client.send_pin(pin)

    # pass through changes to is_testnet to the underlying client
    @property
    def is_testnet(self):
        if self.client:
            return self.client.is_testnet
        else:
            return False

    @is_testnet.setter
    def is_testnet(self, value):
        if self.client:
            self.client.is_testnet = value

def enumerate(password=''):
    results = []
    devices = hid.enumerate(DBB_VENDOR_ID)
    # Try connecting to simulator
    try:
        dev = BitboxSimulator('127.0.0.1', 35345)
        res = dev.send_recv(b'{"device" : "info"}')
        devices.append({'path': b'udp:127.0.0.1:35345', 'interface_number': 0, 'product_id': DBB_1_DEVICE_ID})
        dev.close()
    except:
        pass
    for d in devices:
        if ('interface_number' in d and  d['interface_number'] == 0 \
        or ('usage_page' in d and d['usage_page'] == 0xffff)):
            d_data = {}

            path = d['path'].decode()
            d_data['type'] = 'digitalbitbox'

            client = None
            if d['product_id'] == DBB_1_DEVICE_ID:
                d_data['model'] = 'digitalbitbox_01'
                if path == 'udp:127.0.0.1:35345':
                    d_data['model'] += '_simulator'
                d_data['path'] = path

                with handle_errors(common_err_msgs["enumerate"], d_data):
                    client = Digitalbitbox1Client(path, password)

                    # Check initialized
                    reply = send_encrypt('{"device" : "info"}', password, client.device)
                    if 'error' in reply and reply['error']['code'] == 101:
                        d_data['error'] = 'Not initialized'
                        d_data['code'] = DEVICE_NOT_INITIALIZED
                    else:
                        master_xpub = client.get_pubkey_at_path('m/0h')['xpub']
                        d_data['fingerprint'] = get_xpub_fingerprint_hex(master_xpub)
                    d_data['needs_pin_sent'] = False
                    d_data['needs_passphrase_sent'] = True

            elif d['product_id'] == DBB_2_DEVICE_ID:
                d_data['model'] = 'digitalbitbox_02'
                d_data['path'] = path
                d_data['error'] = 'Full suppport not yet enabled'
                d_data['code'] = UNKNWON_DEVICE_TYPE
            else:
                # We don't know this, skip it
                continue

            if client:
                client.close()

            results.append(d_data)
    return results
