#! /usr/bin/env python3

import argparse
import json
import logging
import pprint
import sys

from . import commands, __version__
from .cli import HWIArgumentParser
from .errors import BadArgumentError, handle_errors, DEVICE_CONN_ERROR, DEVICE_NOT_INITIALIZED, NO_DEVICE_TYPE
from .hwwclient import DeviceFeature

from .devices.trezor import PassphraseUI
from .devices.trezorlib import exceptions
from .devices.trezorlib.ui import PIN_CONFIRM, PIN_CURRENT, PIN_NEW, PLAIN_WORD_REQ

try:
    from .ui.ui_devicemandialog import Ui_DeviceManDialog
    from .ui.ui_displayaddressdialog import Ui_DisplayAddressDialog
    from .ui.ui_getxpubdialog import Ui_GetXpubDialog
    from .ui.ui_getkeypooloptionsdialog import Ui_GetKeypoolOptionsDialog
    from .ui.ui_mainwindow import Ui_MainWindow
    from .ui.ui_sendpindialog import Ui_SendPinDialog
    from .ui.ui_setpassphrasedialog import Ui_SetPassphraseDialog
    from .ui.ui_setupdevicedialog import Ui_SetupDeviceDialog
    from .ui.ui_signmessagedialog import Ui_SignMessageDialog
    from .ui.ui_signpsbtdialog import Ui_SignPSBTDialog
except ImportError:
    print('Could not import UI files, did you run contrib/generate-ui.sh')
    exit(-1)

from mnemonic import Mnemonic
from PySide2.QtGui import QRegExpValidator
from PySide2.QtWidgets import QApplication, QDialog, QDialogButtonBox, QInputDialog, QLineEdit, QMessageBox, QMainWindow
from PySide2.QtCore import QRegExp, Signal, Slot

def do_command(f, *args, **kwargs):
    result = {}
    with handle_errors(result=result):
        result = f(*args, **kwargs)
    if 'error' in result:
        msg = 'Error: {}\nCode:{}'.format(result['error'], result['code'])
        QMessageBox.critical(None, "An Error Occurred", msg)
        return None
    return result

class SetPassphraseDialog(QDialog):
    def __init__(self):
        super(SetPassphraseDialog, self).__init__()
        self.ui = Ui_SetPassphraseDialog()
        self.ui.setupUi(self)
        self.setWindowTitle('Set Passphrase')

        self.ui.passphrase_lineedit.setFocus()
        self.ui.passphrase_lineedit.setEchoMode(QLineEdit.Password)

class PinDialog(QDialog):
    def __init__(self):
        super(PinDialog, self).__init__()
        self.ui = Ui_SendPinDialog()
        self.ui.setupUi(self)
        self.ui.pin_lineedit.setFocus()
        self.ui.pin_lineedit.setValidator(QRegExpValidator(QRegExp("[1-9]+"), None))
        self.ui.pin_lineedit.setEchoMode(QLineEdit.Password)
        self.setWindowTitle('Enter Pin')

        self.ui.p1_button.clicked.connect(self.button_clicked(1))
        self.ui.p2_button.clicked.connect(self.button_clicked(2))
        self.ui.p3_button.clicked.connect(self.button_clicked(3))
        self.ui.p4_button.clicked.connect(self.button_clicked(4))
        self.ui.p5_button.clicked.connect(self.button_clicked(5))
        self.ui.p6_button.clicked.connect(self.button_clicked(6))
        self.ui.p7_button.clicked.connect(self.button_clicked(7))
        self.ui.p8_button.clicked.connect(self.button_clicked(8))
        self.ui.p9_button.clicked.connect(self.button_clicked(9))

        self.accepted.connect(self.sendpindialog_accepted)
        self.F = bool(do_command(commands.prompt_pin, self.client))

    def button_clicked(self, number):
        @Slot()
        def button_clicked_num():
            self.ui.pin_lineedit.setText(self.ui.pin_lineedit.text() + str(number))
        return button_clicked_num

class SendPinDialog(PinDialog):
    pin_sent_success = Signal()

    def __init__(self, client):
        super(SendPinDialog, self).__init__(client)
        self.setWindowTitle('Send Pin')

        self.accepted.connect(self.sendpindialog_accepted)
        do_command(commands.prompt_pin, self.client)

    @Slot()
    def sendpindialog_accepted(self):
        pin = self.ui.pin_lineedit.text()

        # Send the pin
        res = do_command(commands.send_pin, self.client, pin)
        self.client.close()
        self.client = None
        if res is None:
            self.reject()
        self.pin_sent_success.emit()

    def exec_(self):
        if self.prompt_success:
            return super().exec_()
        else:
            self.reject()
            return QDialog.Rejected

class TrezorQtUI(PassphraseUI):
    def __init__(self, passphrase):
        super(TrezorQtUI, self).__init__(passphrase)

    def get_pin(self, code=None):
        if not self.interactive:
            raise NotImplementedError('get_pin is not needed')

        if code == PIN_CURRENT:
            desc = "Enter your current PIN"
        elif code == PIN_NEW:
            desc = "Enter a new PIN"
        elif code == PIN_CONFIRM:
            desc = "Enter the new PIN again"
        else:
            desc = "Enter your PIN"

        dialog = PinDialog()
        dialog.ui.pin_desc_label.setText(desc)
        resp = dialog.exec_()
        if resp == QDialog.Accepted:
            return dialog.ui.pin_lineedit.text()
        else:
            raise exceptions.Cancelled()

    def mnemonic_words(expand=False, language="english"):
        if expand:
            wordlist = Mnemonic(language).wordlist
        else:
            wordlist = set()

        def expand_word(word):
            if not expand:
                return word
            if word in wordlist:
                return word
            matches = [w for w in wordlist if w.startswith(word)]
            if len(matches) == 1:
                return word
            QDialog.information("Choose one of: " + ", ".join(matches))
            raise KeyError(word)

        def get_word(type):
            assert type == PLAIN_WORD_REQ
            while True:
                try:
                    word, ok = QInputDialog().getText(None, "Enter Mnemonic Words", "Enter one word of mnemonic")
                    if ok and word:
                        return expand_word(word)
                    else:
                        raise exceptions.Cancelled()
                except KeyError:
                    pass

        return get_word

class GetXpubDialog(QDialog):
    def __init__(self, client):
        super(GetXpubDialog, self).__init__()
        self.ui = Ui_GetXpubDialog()
        self.ui.setupUi(self)
        self.setWindowTitle('Get xpub')
        self.client = client

        self.ui.path_lineedit.setValidator(QRegExpValidator(QRegExp("m(/[0-9]+['Hh]?)+"), None))
        self.ui.path_lineedit.setFocus()
        self.ui.buttonBox.button(QDialogButtonBox.Close).setAutoDefault(False)

        self.ui.getxpub_button.clicked.connect(self.getxpub_button_clicked)
        self.ui.buttonBox.clicked.connect(self.accept)

    @Slot()
    def getxpub_button_clicked(self):
        path = self.ui.path_lineedit.text()
        res = do_command(commands.getxpub, self.client, path)
        self.ui.xpub_lineedit.setText(res['xpub'])

class SignPSBTDialog(QDialog):
    def __init__(self, client):
        super(SignPSBTDialog, self).__init__()
        self.ui = Ui_SignPSBTDialog()
        self.ui.setupUi(self)
        self.setWindowTitle('Sign PSBT')
        self.client = client

        self.ui.psbt_in_textedit.setFocus()

        self.ui.sign_psbt_button.clicked.connect(self.sign_psbt_button_clicked)
        self.ui.buttonBox.clicked.connect(self.accept)

    @Slot()
    def sign_psbt_button_clicked(self):
        psbt_str = self.ui.psbt_in_textedit.toPlainText()
        res = do_command(commands.signtx, self.client, psbt_str)
        self.ui.psbt_out_textedit.setPlainText(res['psbt'])

class SignMessageDialog(QDialog):
    def __init__(self, client):
        super(SignMessageDialog, self).__init__()
        self.ui = Ui_SignMessageDialog()
        self.ui.setupUi(self)
        self.setWindowTitle('Sign Message')
        self.client = client

        self.ui.path_lineedit.setValidator(QRegExpValidator(QRegExp("m(/[0-9]+['Hh]?)+"), None))
        self.ui.msg_textedit.setFocus()

        self.ui.signmsg_button.clicked.connect(self.signmsg_button_clicked)
        self.ui.buttonBox.clicked.connect(self.accept)

    @Slot()
    def signmsg_button_clicked(self):
        msg_str = self.ui.msg_textedit.toPlainText()
        path = self.ui.path_lineedit.text()
        res = do_command(commands.signmessage, self.client, msg_str, path)
        self.ui.sig_textedit.setPlainText(res['signature'])

class DisplayAddressDialog(QDialog):
    def __init__(self, client):
        super(DisplayAddressDialog, self).__init__()
        self.ui = Ui_DisplayAddressDialog()
        self.ui.setupUi(self)
        self.setWindowTitle('Display Address')
        self.client = client

        self.ui.path_lineedit.setValidator(QRegExpValidator(QRegExp("m(/[0-9]+['Hh]?)+"), None))
        self.ui.path_lineedit.setFocus()

        self.ui.go_button.clicked.connect(self.go_button_clicked)
        self.ui.buttonBox.clicked.connect(self.accept)

    @Slot()
    def go_button_clicked(self):
        path = self.ui.path_lineedit.text()
        res = do_command(commands.displayaddress, self.client, path, sh_wpkh=self.ui.sh_wpkh_radio.isChecked(), wpkh=self.ui.wpkh_radio.isChecked())
        self.ui.address_lineedit.setText(res['address'])

class GetKeypoolOptionsDialog(QDialog):
    def __init__(self, opts):
        super(GetKeypoolOptionsDialog, self).__init__()
        self.ui = Ui_GetKeypoolOptionsDialog()
        self.ui.setupUi(self)
        self.setWindowTitle('Set getkeypool options')

        self.ui.start_spinbox.setValue(opts['start'])
        self.ui.end_spinbox.setValue(opts['end'])
        self.ui.internal_checkbox.setChecked(opts['internal'])
        self.ui.keypool_checkbox.setChecked(opts['keypool'])
        self.ui.account_spinbox.setValue(opts['account'])
        self.ui.path_lineedit.setValidator(QRegExpValidator(QRegExp("m(/[0-9]+['Hh]?)+"), None))
        if opts['account_used']:
            self.ui.account_radio.setChecked(True)
            self.ui.path_radio.setChecked(False)
            self.ui.path_lineedit.setEnabled(False)
            self.ui.account_spinbox.setEnabled(True)
            self.ui.account_spinbox.setValue(opts['account'])
        else:
            self.ui.account_radio.setChecked(False)
            self.ui.path_radio.setChecked(True)
            self.ui.path_lineedit.setEnabled(True)
            self.ui.account_spinbox.setEnabled(False)
            self.ui.path_lineedit.setText(opts['path'])
        self.ui.sh_wpkh_radio.setChecked(opts['sh_wpkh'])
        self.ui.wpkh_radio.setChecked(opts['wpkh'])

        self.ui.account_radio.toggled.connect(self.toggle_account)

    @Slot()
    def toggle_account(self, checked):
        if checked:
            self.ui.path_lineedit.setEnabled(False)
            self.ui.account_spinbox.setEnabled(True)
        else:
            self.ui.path_lineedit.setEnabled(True)
            self.ui.account_spinbox.setEnabled(False)

class BitboxPassphraseQtUI:
    def get_passphrase(self):
        dialog = SetPassphraseDialog()
        dialog.setWindowTitle('Enter Passphrase')
        dialog.ui.passphrase_desc_label.setText('Enter a passphrase to protect the backup')
        res = dialog.exec_()

        if res != QDialog.Accepted:
            raise BadArgumentError('Passphrase entry canceled')

        password = dialog.ui.passphrase_lineedit.text()

        dialog = SetPassphraseDialog()
        dialog.setWindowTitle('Confirm Passphrase')
        dialog.ui.passphrase_desc_label.setText('Confirm passphrase')
        res = dialog.exec_()

        if res != QDialog.Accepted:
            raise BadArgumentError('Passphrase entry canceled')

        conf_pass = dialog.ui.passphrase_lineedit.text()

        if password != conf_pass:
            raise BadArgumentError('Passphrases don\'t match')
        return password

    def get_label(self):
        label, ok = QInputDialog().getText(None, "Backup Device", "Label for Backup:")
        if ok and label:
            return label
        raise BadArgumentError('Canceled')

class SetupDeviceDialog(QDialog):
    passphrase_changed = Signal(str)

    def __init__(self, client):
        super(SetupDeviceDialog, self).__init__()
        self.client = client
        self.ui = Ui_SetupDeviceDialog()
        self.ui.setupUi(self)
        self.setWindowTitle('Setup A New Device')

        self.accepted.connect(self.handle_accepted)
        self.ui.device_passphrase_checkbox.stateChanged.connect(self.ui.dev_passphrase_lineedit.setEnabled)

        self.ui.dev_passphrase_lineedit.setEchoMode(QLineEdit.Password)

    @Slot()
    def handle_accepted(self):
        password = ''
        if self.ui.device_passphrase_checkbox.isChecked():
            password = self.ui.dev_passphrase_lineedit.text()
        self.client.set_passphrase(password)
        self.passphrase_changed.emit(password)

        label = self.ui.device_label_lineedit.text()
        do_command(commands.setup_device, self.client, label)

class DeviceManDialog(QDialog):
    wipe_success = Signal()
    passphrase_changed = Signal(str)

    def __init__(self, client):
        super(DeviceManDialog, self).__init__()
        self.ui = Ui_DeviceManDialog()
        self.ui.setupUi(self)
        self.setWindowTitle('Device Management')
        self.client = client

        features = self.client.get_features()
        if features['wipe'] == DeviceFeature.SUPPORTED:
            self.ui.wipe_button.setEnabled(True)
            self.ui.wipe_button.setToolTip('')
        elif features['wipe'] == DeviceFeature.NOT_SUPPORTED:
            self.ui.wipe_button.setToolTip('HWI does not support wiping for this device yet.')
        self.ui.wipe_button.clicked.connect(self.handle_wipe)

        if features['setup'] == DeviceFeature.SUPPORTED:
            self.ui.setup_button.setEnabled(True)
            self.ui.setup_button.setToolTip('')
        elif features['setup'] == DeviceFeature.NOT_SUPPORTED:
            self.ui.setup_button.setToolTip('HWI does not support stting up for this device yet.')
        self.ui.setup_button.clicked.connect(self.handle_setup)

        if features['recover'] == DeviceFeature.SUPPORTED:
            self.ui.recover_button.setEnabled(True)
            self.ui.recover_button.setToolTip('')
        elif features['recover'] == DeviceFeature.NOT_SUPPORTED:
            self.ui.recover_button.setToolTip('HWI does not support recovering for this device yet.')
        self.ui.recover_button.clicked.connect(self.handle_recover)

        if features['backup'] == DeviceFeature.SUPPORTED:
            self.ui.backup_button.setEnabled(True)
            self.ui.backup_button.setToolTip('')
        elif features['backup'] == DeviceFeature.NOT_SUPPORTED:
            self.ui.backup_button.setToolTip('HWI does not support backing up for this device yet.')
        self.ui.backup_button.clicked.connect(self.handle_backup)

    @Slot()
    def handle_wipe(self):
        response = QMessageBox.question(self, 'Confirm Wipe', 'Are you sure you want to Wipe this device?')
        if response == QMessageBox.Yes:
            do_command(commands.wipe_device, self.client)
            self.wipe_success.emit()
            self.accept()

    @Slot()
    def update_passphrase(self, passphrase):
        self.passphrase_changed.emit(passphrase)

    @Slot()
    def handle_setup(self):
        dialog = SetupDeviceDialog(self.client)
        dialog.passphrase_changed.connect(self.update_passphrase)
        dialog.exec_()
        self.wipe_success.emit()

    @Slot()
    def handle_recover(self):
        label, ok = QInputDialog().getText(self, "Recover Device", "Device Label:")
        if ok and label:
            do_command(commands.restore_device, self.client, label)
            self.wipe_success.emit()
            self.accept()

    @Slot()
    def handle_backup(self):
        do_command(commands.backup_device, self.client)
        self.wipe_success.emit()
        self.accept()

class HWIQt(QMainWindow):
    def __init__(self):
        super(HWIQt, self).__init__()
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)
        self.setWindowTitle('HWI Qt')

        self.devices = []
        self.client = None
        self.device_info = {}
        self.passphrase = ''
        self.current_dialog = None
        self.getkeypool_opts = {
            'start': 0,
            'end': 1000,
            'account': 0,
            'internal': False,
            'keypool': True,
            'sh_wpkh': True,
            'wpkh': False,
            'path': None,
            'account_used': True
        }

        self.ui.enumerate_refresh_button.clicked.connect(self.refresh_clicked)
        self.ui.setpass_button.clicked.connect(self.show_setpassphrasedialog)
        self.ui.sendpin_button.clicked.connect(self.show_sendpindialog)
        self.ui.getxpub_button.clicked.connect(self.show_getxpubdialog)
        self.ui.signtx_button.clicked.connect(self.show_signpsbtdialog)
        self.ui.signmsg_button.clicked.connect(self.show_signmessagedialog)
        self.ui.display_addr_button.clicked.connect(self.show_displayaddressdialog)
        self.ui.getkeypool_opts_button.clicked.connect(self.show_getkeypooloptionsdialog)
        self.ui.device_man_button.clicked.connect(self.show_devicemandialog)

        self.ui.enumerate_combobox.currentIndexChanged.connect(self.get_client_and_device_info)

    def clear_info(self):
        self.ui.getxpub_button.setEnabled(False)
        self.ui.signtx_button.setEnabled(False)
        self.ui.signmsg_button.setEnabled(False)
        self.ui.display_addr_button.setEnabled(False)
        self.ui.getkeypool_opts_button.setEnabled(False)
        self.ui.device_man_button.setEnabled(False)
        self.ui.keypool_textedit.clear()
        self.ui.desc_textedit.clear()

    @Slot()
    def update_passphrase(self, passphrase):
        self.passphrase = passphrase

    @Slot()
    def refresh_clicked(self):
        if self.client:
            self.client.close()
            self.client = None

        self.devices = commands.enumerate(self.passphrase)
        self.ui.enumerate_combobox.currentIndexChanged.disconnect()
        self.ui.enumerate_combobox.clear()
        self.ui.enumerate_combobox.addItem('')
        for dev in self.devices:
            fingerprint = 'none'
            if 'fingerprint' in dev:
                fingerprint = dev['fingerprint']
            dev_str = '{} fingerprint:{} path:{}'.format(dev['model'], fingerprint, dev['path'])
            self.ui.enumerate_combobox.addItem(dev_str)
        self.ui.enumerate_combobox.currentIndexChanged.connect(self.get_client_and_device_info)
        self.clear_info()

    @Slot()
    def show_setpassphrasedialog(self):
        self.current_dialog = SetPassphraseDialog()
        self.current_dialog.accepted.connect(self.setpassphrasedialog_accepted)
        self.current_dialog.exec_()

    @Slot()
    def setpassphrasedialog_accepted(self):
        self.passphrase = self.current_dialog.ui.passphrase_lineedit.text()
        self.current_dialog = None

    @Slot()
    def get_client_and_device_info(self, index):
        self.ui.sendpin_button.setEnabled(False)
        if index == 0:
            self.clear_info()
            return

        self.ui.getxpub_button.setEnabled(True)
        self.ui.signtx_button.setEnabled(True)
        self.ui.signmsg_button.setEnabled(True)
        self.ui.display_addr_button.setEnabled(True)
        self.ui.getkeypool_opts_button.setEnabled(True)
        self.ui.device_man_button.setEnabled(True)

        # Get the client
        self.device_info = self.devices[index - 1]
        self.client = commands.get_client(self.device_info['model'], self.device_info['path'], self.passphrase)

        # If this is a trezor, set the GuiUi
        if self.device_info['type'] == 'trezor':
            self.client.client.ui = TrezorQtUI(self.passphrase)
        elif self.device_info['type'] == 'digitalbitbox':
            self.client.passphrase_ui = BitboxPassphraseQtUI()

        self.get_device_info()

    def get_device_info(self):
        # Enable the sendpin button if it's a trezor and it needs it
        if self.device_info['needs_pin_sent']:
            self.ui.sendpin_button.setEnabled(True)
            self.clear_info()
            return
        else:
            self.ui.sendpin_button.setEnabled(False)

        # If it isn't initialized, show an error but don't do anything
        if 'code' in self.device_info and self.device_info['code'] == DEVICE_NOT_INITIALIZED:
            self.clear_info()
            QMessageBox.information(None, "Not initialized yet", 'Device is not initalized yet')
            self.ui.device_man_button.setEnabled(True)
            return

        # do getkeypool and getdescriptors
        keypool = do_command(commands.getkeypool, self.client,
                             None if self.getkeypool_opts['account_used'] else self.getkeypool_opts['path'],
                             self.getkeypool_opts['start'],
                             self.getkeypool_opts['end'],
                             self.getkeypool_opts['internal'],
                             self.getkeypool_opts['keypool'],
                             self.getkeypool_opts['account'],
                             self.getkeypool_opts['sh_wpkh'],
                             self.getkeypool_opts['wpkh'])
        descriptors = do_command(commands.getdescriptors, self.client, self.getkeypool_opts['account'])

        self.ui.keypool_textedit.setPlainText(pprint.pformat(keypool))
        self.ui.desc_textedit.setPlainText(pprint.pformat(descriptors))

    @Slot()
    def show_sendpindialog(self):
        self.current_dialog = SendPinDialog(self.client)
        self.current_dialog.pin_sent_success.connect(self.sendpindialog_accepted)
        self.current_dialog.exec_()

    @Slot()
    def sendpindialog_accepted(self):
        self.current_dialog = None

        curr_index = self.ui.enumerate_combobox.currentIndex()
        self.refresh_clicked()
        self.ui.enumerate_combobox.setCurrentIndex(curr_index)

    @Slot()
    def show_getxpubdialog(self):
        self.current_dialog = GetXpubDialog(self.client)
        self.current_dialog.exec_()

    @Slot()
    def show_signpsbtdialog(self):
        self.current_dialog = SignPSBTDialog(self.client)
        self.current_dialog.exec_()

    @Slot()
    def show_signmessagedialog(self):
        self.current_dialog = SignMessageDialog(self.client)
        self.current_dialog.exec_()

    @Slot()
    def show_displayaddressdialog(self):
        self.current_dialog = DisplayAddressDialog(self.client)
        self.current_dialog.exec_()

    @Slot()
    def show_getkeypooloptionsdialog(self):
        self.current_dialog = GetKeypoolOptionsDialog(self.getkeypool_opts)
        self.current_dialog.accepted.connect(self.getkeypooloptionsdialog_accepted)
        self.current_dialog.exec_()

    @Slot()
    def getkeypooloptionsdialog_accepted(self):
        self.getkeypool_opts['start'] = self.current_dialog.ui.start_spinbox.value()
        self.getkeypool_opts['end'] = self.current_dialog.ui.end_spinbox.value()
        self.getkeypool_opts['internal'] = self.current_dialog.ui.internal_checkbox.isChecked()
        self.getkeypool_opts['keypool'] = self.current_dialog.ui.keypool_checkbox.isChecked()
        self.getkeypool_opts['sh_wpkh'] = self.current_dialog.ui.sh_wpkh_radio.isChecked()
        self.getkeypool_opts['wpkh'] = self.current_dialog.ui.wpkh_radio.isChecked()
        if self.current_dialog.ui.account_radio.isChecked():
            self.getkeypool_opts['account'] = self.current_dialog.ui.account_spinbox.value()
            self.getkeypool_opts['account_used'] = True
        else:
            self.getkeypool_opts['path'] = self.current_dialog.ui.path_lineedit.text()
            self.getkeypool_opts['account_used'] = False
        self.current_dialog = None
        self.get_device_info()

    @Slot()
    def show_devicemandialog(self):
        self.current_dialog = DeviceManDialog(self.client)
        self.current_dialog.wipe_success.connect(self.refresh_clicked)
        self.current_dialog.passphrase_changed.connect(self.update_passphrase)
        self.current_dialog.exec_()

def pinentry_handler(args, client):
    dialog = SendPinDialog(client)
    ret = dialog.exec_()
    return {'success': ret == QDialog.Accepted}

def process_gui_commands(cli_args):
    parser = HWIArgumentParser(description='Hardware Wallet Interface Qt, version {}.\nInteractively access and send commands to a hardware wallet device with a GUI. Responses are in JSON format.'.format(__version__))
    parser.add_argument('--device-path', '-d', help='Specify the device path of the device to connect to')
    parser.add_argument('--device-type', '-t', help='Specify the type of device that will be connected. If `--device-path` not given, the first device of this type enumerated is used.')
    parser.add_argument('--password', '-p', help='Device password if it has one (e.g. DigitalBitbox)', default='')
    parser.add_argument('--stdinpass', help='Enter the device password on the command line', action='store_true')
    parser.add_argument('--testnet', help='Use testnet prefixes', action='store_true')
    parser.add_argument('--debug', help='Print debug statements', action='store_true')
    parser.add_argument('--fingerprint', '-f', help='Specify the device to connect to using the first 4 bytes of the hash160 of the master public key. It will connect to the first device that matches this fingerprint.')
    parser.add_argument('--version', action='version', version='%(prog)s {}'.format(__version__))
    parser.add_argument('--stdin', help='Enter commands and arguments via stdin', action='store_true')
    parser.add_argument('--interactive', '-i', help='Use some commands interactively. Currently required for all device configuration commands', action='store_true')

    parser.add_argument('--options', '-o', help='The above options but as a JSON object')

    subparsers = parser.add_subparsers(description='Commands', dest='command')

    pinentry_parser = subparsers.add_parser('pinentry', help='Send a PIN to the device')
    pinentry_parser.set_defaults(func=pinentry_handler)

    # Parse arguments again for anything entered over stdin
    args = parser.parse_args(cli_args)

    # Handle options given as JSON in --options. Prefer command line given arguments over JSON ones
    if args.options:
        try:
            opts = json.loads(args.options)
            if not isinstance(opts, dict):
                parser.error('JSON object (dict) needed for --options')
        except json.JSONDecodeError:
            parser.error('Invalid JSON given for --options')

        for k, v in opts.items():
            if not isinstance(v, bool):
                cli_args.insert(0, str(v))
            cli_args.insert(0, '--{}'.format(k))
        args = parser.parse_args(cli_args)

    device_path = args.device_path
    device_type = args.device_type
    password = args.password
    command = args.command
    result = {}

    # Setup debug logging
    logging.basicConfig(level=logging.DEBUG if args.debug else logging.WARNING)

    # Enter the password on stdin
    if args.stdinpass:
        password = getpass.getpass('Enter your device password: ')
        args.password = password

    # Qt setup
    app = QApplication()

    if args.command:
        # Auto detect if we are using fingerprint or type to identify device
        if args.fingerprint or (args.device_type and not args.device_path):
            client = commands.find_device(args.device_path, args.password, args.device_type, args.fingerprint)
            if not client:
                return {'error': 'Could not find device with specified fingerprint', 'code': DEVICE_CONN_ERROR}
        elif args.device_type and args.device_path:
            with handle_errors(result=result, code=DEVICE_CONN_ERROR):
                client = commands.get_client(device_type, device_path, password)
            if 'error' in result:
                return result
        else:
            return {'error': 'You must specify a device type or fingerprint for all commands except enumerate', 'code': NO_DEVICE_TYPE}

        client.is_testnet = args.testnet

        # Do the commands
        with handle_errors(result=result, debug=args.debug):
            result = args.func(args, client)

        with handle_errors(result=result, debug=args.debug):
            client.close()
    else:
        window = HWIQt()

        window.refresh_clicked()

        window.show()
        ret = app.exec_()
        result = {'success': ret == 0}

    return result

def main():
    result = process_gui_commands(sys.argv[1:])
    print(json.dumps(result))
