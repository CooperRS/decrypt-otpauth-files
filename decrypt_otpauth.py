import base64
import click
import getpass
import hashlib

from enum import Enum
from urllib.parse import quote

import pyqrcode

from bpylist2 import archiver
from plistlib import UID

from Crypto.Cipher import AES

from rncryptor import RNCryptor
from rncryptor import bord


class Type(Enum):
    Unknown = 0
    HOTP = 1
    TOTP = 2

    @property
    def uri_value(self):
        if self.value == 0:
            return 'unknown'
        if self.value == 1:
            return 'hotp'
        if self.value == 2:
            return 'totp'


class Algorithm(Enum):
    Unknown = 0
    SHA1 = 1  # Used in case of Unknown
    SHA256 = 2
    SHA512 = 3
    MD5 = 4

    @property
    def uri_value(self):
        if self.value == 0:
            return 'sha1'
        if self.value == 1:
            return 'sha1'
        if self.value == 2:
            return 'sha256'
        if self.value == 3:
            return 'sha512'
        if self.value == 4:
            return 'md5'


class MutableString:

    def decode_archive(archive):
        return archive.decode('NS.string')


class MutableData:

    def decode_archive(archive):
        return bytes(archive.decode('NS.data'))


class OTPFolder:
    name = None
    accounts = None

    def __init__(self, name, accounts):
        self.name = name
        self.accounts = accounts

    def __repr__(self):
        return f'<OTPFolder: {self.name}>'

    def decode_archive(archive):
        name = archive.decode('name')
        accounts = archive.decode('accounts')
        return OTPFolder(name, accounts)


class OTPAccount:
    label = None
    issuer = None
    secret = None
    type = None
    algorithm = None
    digits = None
    counter = None
    period = None
    refDate = None

    def __init__(self, label, issuer, secret, type, algorithm, digits, counter, period, refDate):
        self.label = label
        self.issuer = issuer
        self.secret = secret
        self.type = type
        self.algorithm = algorithm
        self.digits = digits
        self.counter = counter
        self.period = period
        self.refDate = refDate

    def __repr__(self):
        return f'<OTPAccount: {self.issuer} ({self.label})>'

    def decode_archive(archive):
        label = archive.decode("label")
        issuer = archive.decode("issuer")
        secret = bytes(archive.decode("secret"))
        type = Type(archive.decode("type"))
        algorithm = Algorithm(archive.decode("algorithm"))
        digits = archive.decode("digits")
        counter = archive.decode("counter")
        period = archive.decode("period")
        refDate = archive.decode("refDate")
        return OTPAccount(label, issuer, secret, type, algorithm, digits, counter, period, refDate)

    def from_dict(in_dict):
        label = in_dict.get("label")
        issuer = in_dict.get("issuer")
        secret = bytes(in_dict.get("secret"))
        type = Type(in_dict.get("type"))
        algorithm = Algorithm(in_dict.get("algorithm"))
        digits = in_dict.get("digits")
        counter = in_dict.get("counter")
        period = in_dict.get("period")
        refDate = in_dict.get("refDate")
        return OTPAccount(label, issuer, secret, type, algorithm, digits, counter, period, refDate)

    def otp_uri(self):
        otp_type = self.type.uri_value
        otp_label = quote(f'{self.issuer}:{self.label}')
        otp_parameters = {
            'secret': base64.b32encode(self.secret).decode("utf-8").rstrip("="),
            'algorithm': self.algorithm.uri_value,
            'period': self.period,
            'digits': self.digits,
            'issuer': self.issuer,
            'counter': self.counter,
        }
        otp_parameters = '&'.join([f'{str(k)}={quote(str(v))}' for (k, v) in otp_parameters.items() if v])
        return f'otpauth://{otp_type}/{otp_label}?{otp_parameters}'


archiver.update_class_map({'NSMutableData': MutableData})
archiver.update_class_map({'NSMutableString': MutableString})
archiver.update_class_map({'ACOTPFolder': OTPFolder})
archiver.update_class_map({'ACOTPAccount': OTPAccount})


class RawRNCryptor(RNCryptor):

    def post_decrypt_data(self, data):
        """Remove useless symbols which
           appear over padding for AES (PKCS#7)."""
        data = data[:-bord(data[-1])]
        return data


class DangerousUnarchive(archiver.Unarchive):

    def decode_object(self, index):
        if index == 0:
            return None

        obj = self.unpacked_uids.get(index)

        if obj is not None:
            return obj

        raw_obj = self.objects[index]

        # if obj is a (semi-)primitive type (e.g. str)
        if not isinstance(raw_obj, dict):
            return raw_obj

        class_uid = raw_obj.get('$class')
        if not isinstance(class_uid, UID):
            raise archiver.MissingClassUID(raw_obj)

        klass = self.class_for_uid(class_uid)
        obj = klass.decode_archive(archiver.ArchivedObject(raw_obj, self))

        self.unpacked_uids[index] = obj
        return obj


def render_qr_to_terminal(otp_uri, type, issuer, label):
    qr = pyqrcode.create(otp_uri, error="L")
    click.echo("")
    click.echo(f'{type}: {issuer} - {label}')
    click.echo(qr.terminal(quiet_zone=4))
    click.echo("")


@click.group()
def cli():
    pass


@cli.command()
@click.option('--encrypted-otpauth-account',
              help="path to your encrypted OTP Auth account (.otpauth)",
              required=True,
              type=click.File('rb'))
def decrypt_account(encrypted_otpauth_account):
    # Get password from user
    password = getpass.getpass(f'Password for export file {encrypted_otpauth_account.name}: ')

    # Get IV and key for wrapping archive
    iv = bytes(16)
    key = hashlib.sha256('OTPAuth'.encode('utf-8')).digest()

    # Decrypt wrapping archive
    data = AES.new(key, AES.MODE_CBC, iv).decrypt(encrypted_otpauth_account.read())
    data = data[:-data[-1]]

    # Decode wrapping archive
    archive = archiver.Unarchive(data).top_object()

    if archive['Version'] == 1.1:
        account = decrypt_account_11(archive, password)
    elif archive['Version'] == 1.2:
        account = decrypt_account_12(archive, password)
    else:
        click.echo(f'Encountered unknow file version: {archive["Version"]}')
        return

    render_qr_to_terminal(account.otp_uri(), account.type, account.issuer, account.label)


def decrypt_account_11(archive, password):
    # Get IV and key for actual archive
    iv = hashlib.sha1(archive['IV']).digest()[:16]
    salt = archive['Salt']
    key = hashlib.sha256((salt + '-' + password).encode('utf-8')).digest()

    # Decrypt actual archive
    data = AES.new(key, AES.MODE_CBC, iv).decrypt(archive['Data'])
    data = data[:-data[-1]]

    # Decode actual archive
    archive = DangerousUnarchive(data).top_object()

    # Construct OTPAccount object from returned dictionary
    return OTPAccount.from_dict(archive)


def decrypt_account_12(archive, password):
    # Decrypt using RNCryptor
    data = data = RawRNCryptor().decrypt(archive['Data'], password)

    # Decode archive
    archive = DangerousUnarchive(data).top_object()

    # Construct OTPAccount object from returned dictionary
    return OTPAccount.from_dict(archive)


@cli.command()
@click.option('--encrypted-otpauth-backup',
              help="path to your encrypted OTP Auth backup (.otpauthdb)",
              required=True,
              type=click.File('rb'))
def decrypt_backup(encrypted_otpauth_backup):
    # Get password from user
    password = getpass.getpass(f'Password for export file {encrypted_otpauth_backup.name}: ')

    # Get IV and key for wrapping archive
    iv = bytes(16)
    key = hashlib.sha256('Authenticator'.encode('utf-8')).digest()

    # Decrypt wrapping archive
    data = AES.new(key, AES.MODE_CBC, iv).decrypt(encrypted_otpauth_backup.read())
    data = data[:-data[-1]]

    # Decode wrapping archive
    archive = archiver.Unarchive(data).top_object()

    if archive['Version'] == 1.0:
        accounts = decrypt_backup_10(archive, password)
    elif archive['Version'] == 1.1:
        accounts = decrypt_backup_11(archive, password)
    else:
        click.echo(f'Encountered unknow file version: {archive["Version"]}')
        return

    for account in accounts:
        render_qr_to_terminal(account.otp_uri(), account.type, account.issuer, account.label)
        input("Press Enter to continue...")


def decrypt_backup_10(archive, password):
    # Get IV and key for actual archive
    iv = hashlib.sha1(archive['IV'].encode('utf-8')).digest()[:16]
    salt = archive['Salt']
    key = hashlib.sha256((salt + '-' + password).encode('utf-8')).digest()

    # Decrypt actual archive
    data = AES.new(key, AES.MODE_CBC, iv).decrypt(archive['WrappedData'])
    data = data[:-data[-1]]

    # Decode actual archive
    archive = DangerousUnarchive(data).top_object()

    return [account for folder in archive['Folders'] for account in folder.accounts]


def decrypt_backup_11(archive, password):
    # Decrypt using RNCryptor
    data = data = RawRNCryptor().decrypt(archive['WrappedData'], password)

    # Decode archive
    archive = DangerousUnarchive(data).top_object()

    return [account for folder in archive['Folders'] for account in folder.accounts]


if __name__ == '__main__':
    cli()
