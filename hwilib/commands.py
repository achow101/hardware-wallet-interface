#! /usr/bin/env python3

"""
Commands
********

The functions in this module are the primary way to interact with hardware wallets.
Each function that takes a ``client`` uses a :class:`~hwilib.hwwclient.HardwareWalletClient`.
The functions then call public members of that client to retrieve the data needed.

Clients can be constructed using :func:`~find_device` or :func:`~get_device`.

The :func:`~enumerate` function returns information about what devices are available to be connected to.
These information can then be used with :func:`~find_device` or :func:`~get_device` to get a :class:`~hwilib.hwwclient.HardwareWalletClient`.

Note that this documentation does not specify every exception that can be raised.
Many exceptions are buried within the functions implemented by each device's ``HardwareWalletClient``.
For more information about the exceptions that those can raise, please see the specific client documentation.
"""

import binascii
import importlib
import platform

from .serializations import PSBT
from .base58 import xpub_to_pub_hex
from .key import (
    H_,
    HARDENED_FLAG,
    is_hardened,
    KeyOriginInfo,
    parse_path,
)
from .errors import (
    BadArgumentError,
    NotImplementedError,
    UnknownDeviceError,
)
from .descriptor import (
    Descriptor,
    parse_descriptor,
    MultisigDescriptor,
    PKHDescriptor,
    PubkeyProvider,
    SHDescriptor,
    WPKHDescriptor,
    WSHDescriptor,
)
from .devices import __all__ as all_devs
from .hwwclient import HardwareWalletClient

from enum import Enum
from itertools import count

from typing import (
    Dict,
    MutableSequence,
    Optional,
    Sequence,
    Union,
)

KeypoolDict = Dict[str, Union[str, Sequence[int], bool]]

class AddressType(Enum):
    """
    An enum representing the type of address.
    """

    PKH = 1
    """Public Key Hash. Legacy single key address. Begins with ``1`` (or ``m`` or ``n`` for testnet)"""

    WPKH = 2
    """Witness Public Key Hash. Bech32 Segwit v0 single key address. Begin with ``bc`` (or ``tb`` for testnet)"""

    SH_WPKH = 3
    """Witness Public Key Hash inside of a Script Hash. Legacy address containing a WPKH script. Begins with ``3`` (or ``2`` for testnet)"""

# Get the client for the device
def get_client(device_type: str, device_path: str, password: str = '', expert: bool = False) -> 'HardwareWalletClient':
    """
    Returns a HWWClient for the given device type at the device path

    :param device_type: The type of device
    :param device_path: The path specifying where the device can be accessed as returned by :func:`~enumerate`
    :param password: The password to use for this device
    :param expert: Whether the device should be opened in expert mode (prints more information for some commands)
    :return: A `~hwilib.hwwclient.HardwareWalletClient` to interact with the device
    :raises: UnknownDeviceError: if the device type is not known by HWI
    """

    device_type = device_type.split('_')[0]
    class_name = device_type.capitalize()
    module = device_type.lower()

    client: Optional['HardwareWalletClient'] = None
    try:
        imported_dev = importlib.import_module('.devices.' + module, __package__)
        client_constructor = getattr(imported_dev, class_name + 'Client')
        client = client_constructor(device_path, password, expert)
    except ImportError:
        if client:
            client.close()
        raise UnknownDeviceError('Unknown device type specified')

    # If client failed to init, there would be some other exception raised
    assert client is not None

    return client

# Get a list of all available hardware wallets
def enumerate(password: str = '') -> Sequence[Dict[str, str]]:
    """
    Enumerate all of the devices that HWI can potentially access.

    :param password: The password to use for devices which take passwords from the host.
    :return: A list of devices for which clients can be created for.
    """

    result = []

    for module in all_devs:
        try:
            imported_dev = importlib.import_module('.devices.' + module, __package__)
            result.extend(getattr(imported_dev, 'enumerate')(password))
        except ImportError:
            pass # Ignore ImportErrors, the user may not have all device dependencies installed
    return result

# Fingerprint or device type required
def find_device(
    password: str = '',
    device_type: Optional[str] = None,
    fingerprint: Optional[str] = None,
    expert: bool = False
) -> Optional['HardwareWalletClient']:
    """
    Find a device from the device type or fingerprint and get a client to access it.
    This is used as an alternative to :func::`~get_client` if the device path is not known.

    :param password: A password that may be needed to access the device if it can take passwords from the host
    :param device_type: The type of device. The client returned will be for this type of device.
        If not provided, the fingerprint must be provided
    :param fingerprint: The fingerprint of the master public key for the device.
        The client returned will have a master public key fingerprint matching this.
        If not provided, device_type must be provided.
    :param expert: Whether the device should be opened in expert mode (enables additional output for some actions)
    :return: A client to interact with the found device
    """

    devices = enumerate(password)
    for d in devices:
        if device_type is not None and d['type'] != device_type and d['model'] != device_type:
            continue
        client = None
        try:
            client = get_client(d['type'], d['path'], password, expert)

            master_fpr = d.get('fingerprint', None)
            if master_fpr is None:
                master_fpr = client.get_master_fingerprint_hex()

            if fingerprint and master_fpr != fingerprint:
                client.close()
                continue
            return client
        except Exception:
            if client:
                client.close()
            pass # Ignore things we wouldn't get fingerprints for
    return None

def getmasterxpub(client: 'HardwareWalletClient') -> Dict[str, str]:
    """
    Get the master extended public key from a client

    :param client: The client to interact with
    :return: A dictionary containing the public key at the ``m/44'/0'/0'`` derivation path.
        Returned as ``{"xpub": <xpub string>}``.
    """
    return client.get_master_xpub()

def signtx(client: 'HardwareWalletClient', psbt: str) -> Dict[str, str]:
    """
    Sign a Partially Signed Bitcoin Transaction (PSBT) with the client.

    :param client: The client to interact with
    :param psbt: The PSBT to sign
    :return: A dictionary containing the processed PSBT serialized in Base64.
        Returned as ``{"psbt": <base64 psbt string>}``.
    """
    # Deserialize the transaction
    tx = PSBT()
    tx.deserialize(psbt)
    return client.sign_tx(tx)

def getxpub(client: 'HardwareWalletClient', path: str) -> Dict[str, str]:
    """
    Get the master public key at a path from a client

    :param client: The client to interact with
    :param path: The derivation path for the public key to retrieve
    :return: A dictionary containing the public key at the ``bip32_path``.
        Returned as ``{"xpub": <xpub string>}``.
    """
    return client.get_pubkey_at_path(path)

def signmessage(client: 'HardwareWalletClient', message: Union[str, bytes], path: str) -> Dict[str, str]:
    """
    Sign a message using the key at the derivation path with the client.

    The message will be signed using the Bitcoin signed message standard used by Bitcoin Core.
    The message can be either a string which is then encoded to bytes, or bytes.

    :param client: The client to interact with
    :param message: The message to sign
    :param path: The derivation path for the key to sign with
    :return: A dictionary containing the signature.
        Returned as ``{"signature": <base64 signature string>}``.
    """
    return client.sign_message(message, path)

def getkeypool_inner(
    client: 'HardwareWalletClient',
    path: str,
    start: int,
    end: int,
    internal: bool = False,
    keypool: bool = True,
    account: int = 0,
    addr_type: 'AddressType' = AddressType.WPKH
) -> Sequence[KeypoolDict]:
    """
    :meta private:

    Construct a single dictionary that specifies a single descriptor and the extra fields needed for ``importmulti`` or ``importdescriptors`` to import it.

    :param path: The derivation path for the key in the descriptor
    :param start: The start index of the range, inclusive
    :param end: The end index of the range, inclusive
    :param internal: Whether to specify this import is change
    :param keypool: Whether to specify this import should be added to the keypool
    :param account: The BIP 44 account to use if ``path`` is not specified
    :param addr_type: The type of address the descriptor should create
    """
    master_fpr = client.get_master_fingerprint_hex()

    desc = getdescriptor(client, master_fpr, client.is_testnet, path, internal, addr_type, account, start, end)

    this_import: Dict[str, Union[Sequence[int], str, bool]] = {}

    this_import['desc'] = desc.to_string()
    this_import['range'] = [start, end]
    this_import['timestamp'] = 'now'
    this_import['internal'] = internal
    this_import['keypool'] = keypool
    this_import['active'] = keypool
    this_import['watchonly'] = True
    return [this_import]

def getdescriptor(
    client: 'HardwareWalletClient',
    master_fpr: str,
    testnet: bool = False,
    path: Optional[str] = None,
    internal: bool = False,
    addr_type: 'AddressType' = AddressType.WPKH,
    account: int = 0,
    start: Optional[int] = None,
    end: Optional[int] = None
) -> 'Descriptor':
    """
    Get a descriptor from the client.

    :param client: The client to interact with
    :param master_fpr: The hex string for the master fingerprint of the device to use in the descriptor
    :param testnet: Whether to use a testnet xpub
    :param path: The derivation path for the xpub from which additional keys will be derived.
    :param internal: Whether the dictionary should indicate that the descriptor should be for change addresses
    :param addr_type: The type of address the descriptor should create
    :param account: The BIP 44 account to use if ``path`` is not specified
    :param start: The start of the range to import, inclusive
    :param end: The end of the range to import, inclusive
    :return: The descriptor constructed given the above arguments and key fetched from the device
    :raises: BadArgumentError: if an argument is malformed or missing.
    """
    testnet = client.is_testnet

    is_wpkh = addr_type is AddressType.WPKH
    is_sh_wpkh = addr_type is AddressType.SH_WPKH

    parsed_path: Sequence[int] = []
    if not path:
        new_path = []
        # Purpose
        if is_wpkh:
            new_path.append(H_(84))
        elif is_sh_wpkh:
            new_path.append(H_(49))
        else:
            assert addr_type == AddressType.PKH
            new_path.append(H_(44))

        # Coin type
        if testnet:
            new_path.append(H_(1))
        else:
            new_path.append(H_(0))

        # Account
        new_path.append(H_(account))

        # Receive or change
        if internal:
            new_path.append(1)
        else:
            new_path.append(0)
        parsed_path = new_path
    else:
        if path[0] != "m":
            raise BadArgumentError("Path must start with m/")
        if path[-1] != "*":
            raise BadArgumentError("Path must end with /*")
        parsed_path = parse_path(path[:-2])

    # Find the last hardened derivation:
    for i, p in zip(count(len(parsed_path) - 1, -1), reversed(parsed_path)):
        if is_hardened(p):
            break
    i += 1

    origin = KeyOriginInfo(binascii.unhexlify(master_fpr), parsed_path[:i])
    path_base = origin.get_derivation_path()

    path_suffix = ""
    for p in parsed_path[i:]:
        hardened = is_hardened(p)
        p &= ~HARDENED_FLAG
        path_suffix += "/{}{}".format(p, "h" if hardened else "")
    path_suffix += "/*"

    # Get the key at the base
    if client.xpub_cache.get(path_base) is None:
        client.xpub_cache[path_base] = client.get_pubkey_at_path(path_base)['xpub']

    pubkey = PubkeyProvider(origin, client.xpub_cache[path_base], path_suffix)
    if is_wpkh:
        return WPKHDescriptor(pubkey)
    elif is_sh_wpkh:
        return SHDescriptor(WPKHDescriptor(pubkey))
    else:
        return PKHDescriptor(pubkey)

def getkeypool(
    client: 'HardwareWalletClient',
    path: str,
    start: int,
    end: int,
    internal: bool = False,
    keypool: bool = True,
    account: int = 0,
    sh_wpkh: bool = False,
    wpkh: bool = True,
    addr_all: bool = False
) -> Sequence[KeypoolDict]:
    """
    Get a dictionary which can be passed to Bitcoin Core's ``importmulti`` or ``importdescriptors`` RPCs to import a watchonly wallet based on the client.
    By default, a descriptor for legacy addresses is returned.

    :param client: The client to interact with
    :param path: The derivation path for the xpub from which additional keys will be derived.
    :param start: The start of the range to import, inclusive
    :param end: The end of the range to import, inclusive
    :param internal: Whether the dictionary should indicate that the descriptor should be for change addresses
    :param keypool: Whether the dictionary should indicate that the dsecriptor should be added to the Bitcoin Core keypool/addresspool
    :param account: The BIP 44 account to use if ``path`` is not specified
    :param sh_wpkh: Whether to return a descriptor specifying p2sh-segwit addresses
    :param wpkh: Whether to return a descriptor specifying native segwit addresses
    :param addr_all: Whether to return a multiple descriptors for every address type
    :return: The dictionary containing the descriptor and all of the arguments for ``importmulti`` or ``importdescriptors``
    :raises: BadArgumentError: if an argument is malformed or missing.
    """
    if sh_wpkh:
        addr_types = [AddressType.SH_WPKH]
    elif wpkh:
        addr_types = [AddressType.WPKH]
    elif addr_all:
        addr_types = list(AddressType)
    else:
        addr_types = [AddressType.PKH]

    # When no specific path or internal-ness is specified, create standard types
    chains: MutableSequence[KeypoolDict] = []
    if path is None and not internal:
        for addr_type in addr_types:
            for internal_addr in [False, True]:
                chains = chains + getkeypool_inner(client, None, start, end, internal_addr, keypool, account, addr_type)

        # Report the first error we encounter
        for chain in chains:
            if 'error' in chain:
                return chain
        # No errors, return pair
        return chains
    else:
        assert len(addr_types) == 1
        return getkeypool_inner(client, path, start, end, internal, keypool, account, addr_types[0])


def getdescriptors(client: 'HardwareWalletClient', account: int = 0) -> Dict[str, MutableSequence[str]]:
    """
    Get descriptors from the client.

    :param client: The client to interact with
    :param account: The BIP 44 account to use
    :return: Multiple descriptors from the device matching the BIP 44 standard paths and the given ``account``.
    :raises: BadArgumentError: if an argument is malformed or missing.
    """
    master_fpr = client.get_master_fingerprint_hex()

    result = {}

    for internal in [False, True]:
        descriptors: MutableSequence[str] = []
        desc1 = getdescriptor(client, master_fpr=master_fpr, testnet=client.is_testnet, internal=internal, addr_type=AddressType.PKH, account=account)
        desc2 = getdescriptor(client, master_fpr=master_fpr, testnet=client.is_testnet, internal=internal, addr_type=AddressType.SH_WPKH, account=account)
        desc3 = getdescriptor(client, master_fpr=master_fpr, testnet=client.is_testnet, internal=internal, addr_type=AddressType.WPKH, account=account)
        for desc in [desc1, desc2, desc3]:
            descriptors.append(desc.to_string())
        if internal:
            result["internal"] = descriptors
        else:
            result["receive"] = descriptors

    return result

def displayaddress(
    client: 'HardwareWalletClient',
    path: Optional[str] = None,
    desc: Optional[str] = None,
    sh_wpkh: bool = False,
    wpkh: bool = False,
    redeem_script: Optional[str] = None
) -> Dict[str, str]:
    """
    Display an address on the device for client.
    The address can be specified by the path with additional parameters, or by a descriptor.

    :param client: The client to interact with
    :param path: The path of the address to display. Mutually exclusive with ``desc``
    :param desc: The descriptor to display the address for. Mutually exclusive with ``path``
    :param sh_wpkh: Whether the address should be p2sh-segwit. Only works with ``path``
    :param wpkh: Whether the address should be native segwit. Only works with ``path``
    :param redeem_script: The redeemScript for a multisig address to display. Only works with ``path``
    :return: A dictionary containing the address displayed.
        Returend as ``{"address": <base58 or bech32 address string>}``.
    :raises: BadArgumentError: if an argument is malformed, missing, or conflicts.
    """
    if path is not None:
        if sh_wpkh and wpkh:
            raise BadArgumentError("Both `--wpkh` and `--sh_wpkh` can not be selected at the same time.")
        return client.display_address(path, sh_wpkh, wpkh, redeem_script=redeem_script)
    elif desc is not None:
        if sh_wpkh or wpkh:
            raise BadArgumentError("`--wpkh` and `--sh_wpkh` can not be combined with --desc")
        if redeem_script:
            raise BadArgumentError("`--redeem_script` can not be combined with --desc")
        descriptor = parse_descriptor(desc)
        is_sh = isinstance(descriptor, SHDescriptor)
        is_wsh = isinstance(descriptor, WSHDescriptor)
        if is_sh or is_wsh:
            assert descriptor.subdescriptor is not None
            descriptor = descriptor.subdescriptor
            if isinstance(descriptor, WSHDescriptor):
                is_wsh = True
                assert descriptor.subdescriptor is not None
                descriptor = descriptor.subdescriptor
            if isinstance(descriptor, MultisigDescriptor):
                path = ''
                redeem_script = format(80 + int(descriptor.thresh), 'x')
                xpubs_descriptor = False
                for p in descriptor.pubkeys:
                    if p.origin:
                        path += p.origin.to_string()
                    if not p.deriv_path:
                        redeem_script += format(len(p.pubkey) // 2, 'x')
                        redeem_script += p.pubkey
                    else:
                        path += p.deriv_path
                        xpubs_descriptor = True
                    path += ','
                path = path[0:-1]
                redeem_script += format(80 + len(descriptor.pubkeys), 'x') + 'ae'
                return client.display_address(path, is_sh and is_wsh, not is_sh and is_wsh, redeem_script, descriptor=descriptor if xpubs_descriptor else None)
        is_wpkh = isinstance(descriptor, WPKHDescriptor)
        if isinstance(descriptor, PKHDescriptor) or is_wpkh:
            pubkey = descriptor.pubkeys[0]
            if pubkey.origin is None:
                raise BadArgumentError("Descriptor missing origin info: " + desc)
            if pubkey.origin.get_fingerprint_hex() != client.get_master_fingerprint_hex():
                raise BadArgumentError("Descriptor fingerprint does not match device: " + desc)
            xpub = client.get_pubkey_at_path(pubkey.origin.get_derivation_path())['xpub']
            if pubkey.pubkey != xpub and pubkey.pubkey != xpub_to_pub_hex(xpub):
                raise BadArgumentError("Key in descriptor does not match device: " + desc)
            return client.display_address(pubkey.origin.get_derivation_path(), is_sh and is_wpkh, not is_sh and is_wpkh)
    raise BadArgumentError("One of path or desc must not be None")

def setup_device(client: 'HardwareWalletClient', label: str = '', backup_passphrase: str = '') -> Dict[str, Union[str, int]]:
    """
    Setup a device that has not yet been initialized.

    :param client: The client to interact with
    :param label: The label to apply to the newly setup device
    :param backup_passphrase: The passphrase to use for the backup, if backups are encrypted for that device
    :return: A dictionary with the "success" key.
    """
    return client.setup_device(label, backup_passphrase)

def wipe_device(client: 'HardwareWalletClient') -> Dict[str, Union[str, int]]:
    """
    Wipe a device

    :param client: The client to interact with
    :return: A dictionary with the "success" key.
    """
    return client.wipe_device()

def restore_device(client: 'HardwareWalletClient', label: str = '', word_count: int = 24) -> Dict[str, Union[str, int]]:
    """
    Restore a backup to a device that has not yet been initialized.

    :param client: The client to interact with
    :param label: The label to apply to the newly setup device
    :param word_count: The number of words in the recovery phrase
    :return: A dictionary with the "success" key.
    """
    return client.restore_device(label, word_count)

def backup_device(client: 'HardwareWalletClient', label: str = '', backup_passphrase: str = '') -> Dict[str, Union[str, int]]:
    """
    Create a backup of the device

    :param client: The client to interact with
    :param label: The label to apply to the newly setup device
    :param backup_passphrase: The passphrase to use for the backup, if backups are encrypted for that device
    :return: A dictionary with the "success" key.
    """
    return client.backup_device(label, backup_passphrase)

def prompt_pin(client: 'HardwareWalletClient') -> Dict[str, Union[str, int]]:
    """
    Trigger the device to show the setup for PIN entry.

    :param client: The client to interact with
    :return: A dictionary with the "success" key.
    """
    return client.prompt_pin()

def send_pin(client: 'HardwareWalletClient', pin: str) -> Dict[str, Union[str, int]]:
    """
    Send a PIN to the device after :func:`prompt_pin` has been called.

    :param client: The client to interact with
    :param pin: The PIN to send
    :return: A dictionary with the "success" key.
    """
    return client.send_pin(pin)

def toggle_passphrase(client: 'HardwareWalletClient') -> Dict[str, Union[str, int]]:
    """
    Toggle whether the device is using a BIP 39 passphrase.

    :param client: The client to interact with
    :return: A dictionary with the "success" key.
    """
    return client.toggle_passphrase()

def install_udev_rules(source: str, location: str) -> Dict[str, Union[str, int]]:
    """
    Install the udev rules to the local machine.
    The rules will be copied from the source to the location.
    ``udevadm`` will also be triggered and the rules reloaded so that the devices can be plugged in and used immediately.
    A ``plugdev`` group will also be created if it does not exist and the user will be added to it.

    The recommended source location is ``hwilib/udev``. The recommended destination location is ``/etc/udev/rules.d``

    This function is equivalent to::

        sudo cp hwilib/udev/*rules /etc/udev/rules.d/
        sudo udevadm trigger
        sudo udevadm control --reload-rules
        sudo groupadd plugdev
        sudo usermod -aG plugdev `whoami`

    :param source: The directory containing the udev rules to install
    :param location: The directory to install the udev rules to
    :return: A dictionary with the "success" key.
    :raises: NotImplementedError: if udev rules cannot be installed on this system, i.e. it is not linux.
    """
    if platform.system() == "Linux":
        from .udevinstaller import UDevInstaller
        return UDevInstaller.install(source, location)
    raise NotImplementedError("udev rules are not needed on your platform")
