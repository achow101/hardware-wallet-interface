# General device client class and related constants and enums

from enum import IntEnum

class DeviceFeature(IntEnum):
    SUPPORTED = 1 # The device supports the feature and so does HWI
    NOT_SUPPORTED = 2 # The device supports the feature but HWI has not implemented it yet
    FIRMWARE_NOT_SUPPORTED = 3 # The firmware does not support the feature so HWI cannot

class SupportedFeatures(object):

    def __init__(self):
        self.getxpub = DeviceFeature.NOT_SUPPORTED
        self.signmessage = DeviceFeature.NOT_SUPPORTED
        self.setup = DeviceFeature.NOT_SUPPORTED
        self.wipe = DeviceFeature.NOT_SUPPORTED
        self.recover = DeviceFeature.NOT_SUPPORTED
        self.backup = DeviceFeature.NOT_SUPPORTED
        self.sign_p2pkh = DeviceFeature.NOT_SUPPORTED
        self.sign_p2sh_p2wpkh = DeviceFeature.NOT_SUPPORTED
        self.sign_p2wpkh = DeviceFeature.NOT_SUPPORTED
        self.sign_multi_p2sh = DeviceFeature.NOT_SUPPORTED
        self.sign_multi_p2sh_p2wsh = DeviceFeature.NOT_SUPPORTED
        self.sign_multi_p2wsh = DeviceFeature.NOT_SUPPORTED
        self.sign_multi_bare = DeviceFeature.NOT_SUPPORTED
        self.sign_arbitrary_bare = DeviceFeature.NOT_SUPPORTED
        self.sign_arbitrary_p2sh = DeviceFeature.NOT_SUPPORTED
        self.sign_arbitrary_p2sh_p2wsh = DeviceFeature.NOT_SUPPORTED
        self.sign_arbitrary_p2wsh = DeviceFeature.NOT_SUPPORTED
        self.sign_coinjoin = DeviceFeature.NOT_SUPPORTED
        self.sign_mixed_segwit = DeviceFeature.NOT_SUPPORTED
        self.display_address = DeviceFeature.NOT_SUPPORTED

    def get_printable_dict(self):
        d = {}
        d['getxpub'] = self.getxpub
        d['signmessage'] = self.signmessage
        d['setup'] = self.setup
        d['wipe'] = self.wipe
        d['recover'] = self.recover
        d['backup'] = self.backup
        d['sign_p2pkh'] = self.sign_p2pkh
        d['sign_p2sh_p2wpkh'] = self.sign_p2sh_p2wpkh
        d['sign_p2wpkh'] = self.sign_p2wpkh
        d['sign_multi_p2sh'] = self.sign_multi_p2sh
        d['sign_multi_p2sh_p2wsh'] = self.sign_multi_p2sh_p2wsh
        d['sign_multi_p2wsh'] = self.sign_multi_p2wsh
        d['sign_multi_bare'] = self.sign_multi_bare
        d['sign_arbitrary_bare'] = self.sign_arbitrary_bare
        d['sign_arbitrary_p2sh'] = self.sign_arbitrary_p2sh
        d['sign_arbitrary_p2sh_p2wsh'] = self.sign_arbitrary_p2sh_p2wsh
        d['sign_arbitrary_p2wsh'] = self.sign_arbitrary_p2wsh
        d['sign_coinjoin'] = self.sign_coinjoin
        d['sign_mixed_segwit'] = self.sign_mixed_segwit
        d['display_address'] = self.display_address
        return d

# This is an abstract class that defines all of the methods that each Hardware
# wallet subclass must implement.
class HardwareWalletClient(object):

    # device is an HID device that has already been opened.
    def __init__(self, path, password):
        self.path = path
        self.password = password
        self.message_magic = b"\x18Bitcoin Signed Message:\n"
        self.is_testnet = False
        self.fingerprint = None
        self.xpub_cache = {}

    # Get the master BIP 44 pubkey
    def get_master_xpub(self):
        return self.get_pubkey_at_path('m/44\'/0\'/0\'')

    # Must return a dict with the xpub
    # Retrieves the public key at the specified BIP 32 derivation path
    def get_pubkey_at_path(self, path):
        raise NotImplementedError('The HardwareWalletClient base class does not '
                                  'implement this method')

    # Must return a hex string with the signed transaction
    # The tx must be in the combined unsigned transaction format
    def sign_tx(self, tx):
        raise NotImplementedError('The HardwareWalletClient base class does not '
                                  'implement this method')

    # Must return a base64 encoded string with the signed message
    # The message can be any string. keypath is the bip 32 derivation path for the key to sign with
    def sign_message(self, message, keypath):
        raise NotImplementedError('The HardwareWalletClient base class does not '
                                  'implement this method')

    # Setup a new device
    def setup_device(self, label=''):
        raise NotImplementedError('The HardwareWalletClient base class does not '
                                  'implement this method')

    # Wipe this device
    def wipe_device(self):
        raise NotImplementedError('The HardwareWalletClient base class does not '
                                  'implement this method')

    # Restore device from mnemonic or xprv
    def restore_device(self, label=''):
        raise NotImplementedError('The HardwareWalletClient base class does not implement this method')

    # Begin backup process
    def backup_device(self):
        raise NotImplementedError('The HardwareWalletClient base class does not implement this method')

    # Close the device
    def close(self):
        raise NotImplementedError('The HardwareWalletClient base class does not '
                                  'implement this method')

    # Prompt pin
    def prompt_pin(self):
        raise NotImplementedError('The HardwareWalletClient base class does not implement this method')

    # Send pin
    def send_pin(self):
        raise NotImplementedError('The HardwareWalletClient base class does not implement this method')

    # Get HWI features for this device
    @classmethod
    def get_features(self):
        raise NotImplementedError('The HardwareWalletClient base class does not implement this method')

    # Change the device passphrase
    def set_passphrase(self, passphrase):
        self.password = passphrase
