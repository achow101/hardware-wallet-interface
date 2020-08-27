"""
Hardware Wallet Client Interface
********************************

The :class:`HardwareWalletClient` is the class which all of the specific device implementations subclass.
"""

from typing import Dict, Optional, Union

from .base58 import get_xpub_fingerprint_hex
from .descriptor import Descriptor
from .serializations import PSBT


class HardwareWalletClient(object):
    """
    Create a client for a device that has already been opened.

    This abstract class defines the methods
    that hardware wallet subclasses should implement.
    """

    def __init__(self, path: str, password: str, expert: bool) -> None:
        self.path = path
        self.password = password
        self.message_magic = b"\x18Bitcoin Signed Message:\n"
        self.is_testnet = False
        self.fingerprint: Optional[str] = None
        # {bip32_path: <xpub string>}
        self.xpub_cache: Dict[str, str] = {}
        self.expert = expert

    def get_master_xpub(self) -> Dict[str, str]:
        """
        Return the master BIP44 public key.

        Subclasses generally should not override this.

        :return: A dictionary containing the public key at the ``m/44'/0'/0'`` derivation path.
            Returned as ``{"xpub": <xpub string>}``.
        """
        # FIXME testnet is not handled yet
        return self.get_pubkey_at_path("m/44h/0h/0h")

    def get_master_fingerprint_hex(self) -> str:
        """
        Return the master public key fingerprint as hex-string.
        This is done by retrieving the extended pubkey at ``m/0'`` and the fingerprint extracting the fingerprint.

        Subclasses should only override this if the fingerprint can be more easily retrieved in a different way.

        :return: The master key fingerprint
        """
        master_xpub = self.get_pubkey_at_path("m/0h")["xpub"]
        return get_xpub_fingerprint_hex(master_xpub)

    def get_pubkey_at_path(self, bip32_path: str) -> Dict[str, str]:
        """
        Return the extended public key at the BIP32 derivation path.

        Subclasses must implement this.

        :param bip32_path: The derivation path to retrieve the key for.
        :return: A dictionary containing the public key at the ``bip32_path``.
            Returned as ``{"xpub": <xpub string>}``.
        :raises: NotImplementedError: when the subclass has not implemented this.
        """
        raise NotImplementedError("The HardwareWalletClient base class "
                                  "does not implement this method")

    def sign_tx(self, psbt: PSBT) -> Dict[str, str]:
        """
        Sign a partially signed bitcoin transaction (PSBT).

        Subclasses must implement this.

        :param psbt: The PSBT to sign
        :return: A dictionary containing the processed PSBT serialized in Base64.
            Returned as ``{"psbt": <base64 psbt string>}``.
        :raises: NotImplementedError: when the subclass has not implemented this.
        """
        raise NotImplementedError("The HardwareWalletClient base class "
                                  "does not implement this method")

    def sign_message(
        self, message: Union[str, bytes], bip32_path: str
    ) -> Dict[str, str]:
        """
        Sign a message (bitcoin message signing).

        Subclasses must implement this.

        :param message: The message to be signed. If a string, it is encoded to bytes.
            If it is already bytes, no additional conversions or encoding is done, other than the signed message processing.
        :param bip32_path: The derivation path to the key to sign with.
        :return: A dictionary containing the signature.
            Returned as ``{"signature": <base64 signature string>}``.
        :raises: NotImplementedError: when the subclass has not implemented this.
        """
        raise NotImplementedError("The HardwareWalletClient base class "
                                  "does not implement this method")

    def display_address(
        self,
        bip32_path: str,
        p2sh_p2wpkh: bool,
        bech32: bool,
        redeem_script: Optional[str] = None,
        descriptor: Optional[Descriptor] = None,
    ) -> Dict[str, str]:
        """
        Display and return the address of specified type.

        Some devices support multisig address display.
        Those devices will need the ``redeem_script`` to display such addresses.
        Some devices also support displaying multisig addresses where the keys are derived from extended pubkeys.
        To display such addresses, a descriptor containing extended pubkeys must be provided.

        Subclasses must implement this.

        :param bip32_path: The derivation path to the public key for the address to show
        :param p2sh_p2wpkh: Whether to show a Nested Segwit address
        :param bech32: Whether to show a bech32 address
        :param redeem_script: A hex string that specifies a multisig redeemScript to display multisig addresses
        :param descriptor: A output script descriptor containing key origins from which ``bip32_path``, ``p2sh_p2wpkh``, ``bech32``, and ``redeem_script`` can be inferred
        :return: A dictionary containing the address displayed.
            Returend as ``{"address": <base58 or bech32 address string>}``.
        :raises: NotImplementedError: when the subclass has not implemented this.
        """
        raise NotImplementedError("The HardwareWalletClient base class "
                                  "does not implement this method")

    def wipe_device(self) -> Dict[str, Union[bool, str, int]]:
        """
        Wipe the device.

        Subclasses must implement this.
        If device wiping is not supported, :class:`~hwilib.errors.NotImplementedError` must be raised.

        :return: A dictionary with the "success" key.
        :raises: NotImplementedError: when the subclass has not implemented this.
        """
        raise NotImplementedError("The HardwareWalletClient base class "
                                  "does not implement this method")

    def setup_device(
        self, label: str = "", passphrase: str = ""
    ) -> Dict[str, Union[bool, str, int]]:
        """
        Setup the device.

        Subclasses must implement this.
        If device setup is not supported, :class:`~hwilib.errors.NotImplementedError` must be raised.

        :param label: The label to give to the device
        :param passphrase: The passphrase to use on the device
        :return: A dictionary with the "success" key.
        :raises: NotImplementedError: when the subclass has not implemented this.
        """
        raise NotImplementedError("The HardwareWalletClient base class "
                                  "does not implement this method")

    def restore_device(
        self, label: str = "", word_count: int = 24
    ) -> Dict[str, Union[bool, str, int]]:
        """
        Restore the device from mnemonic.

        Subclasses must implement this.
        If device restore is not supported, :class:`~hwilib.errors.NotImplementedError` must be raised.

        :param label: The label to give to the device
        :param word_count: The number of words in the mnemonic
        :return: A dictionary with the "success" key.
        :raises: NotImplementedError: when the subclass has not implemented this.
        """
        raise NotImplementedError("The HardwareWalletClient base class "
                                  "does not implement this method")

    def backup_device(
        self, label: str = "", passphrase: str = ""
    ) -> Dict[str, Union[bool, str, int]]:
        """
        Backup the device.

        Subclasses must implement this.
        If device backup is not supported, :class:`~hwilib.errors.NotImplementedError` must be raised.

        :param label: The label to give to the backup
        :param passphrase: The passphrase to use for the backup
        :return: A dictionary with the "success" key.
        :raises: NotImplementedError: when the subclass has not implemented this.
        """
        raise NotImplementedError("The HardwareWalletClient base class "
                                  "does not implement this method")

    def close(self) -> None:
        """
        Safely close and disconnect from the device.

        Subclasses must implement this.
        """
        raise NotImplementedError("The HardwareWalletClient base class "
                                  "does not implement this method")

    def prompt_pin(self) -> Dict[str, Union[bool, str, int]]:
        """
        Prompt for PIN.

        Subclasses must implement this.
        If PIN prompting is not supported, :class:`~hwilib.errors.NotImplementedError` must be raised.

        :return: A dictionary with the "success" key.
        :raises: NotImplementedError: when the subclass has not implemented this.
        """
        raise NotImplementedError("The HardwareWalletClient base class "
                                  "does not implement this method")

    def send_pin(self, pin: str) -> Dict[str, Union[bool, str, int]]:
        """
        Send PIN.

        Subclasses must implement this.
        If PIN sending is not supported, :class:`~hwilib.errors.NotImplementedError` must be raised.

        :param pin: The pin to send to the device
        :return: A dictionary with the "success" key.
        :raises: NotImplementedError: when the subclass has not implemented this.
        """
        raise NotImplementedError("The HardwareWalletClient base class "
                                  "does not implement this method")

    def toggle_passphrase(self) -> Dict[str, Union[bool, str, int]]:
        """
        Toggle passphrase.

        Subclasses must implement this.
        If passphrase toggling is not supported, :class:`~hwilib.errors.NotImplementedError` must be raised.

        :return: A dictionary with the "success" key.
        :raises: NotImplementedError: when the subclass has not implemented this.
        """
        raise NotImplementedError("The HardwareWalletClient base class "
                                  "does not implement this method")
