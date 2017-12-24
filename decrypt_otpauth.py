import click
import getpass

from enum import Enum

from Crypto.Cipher import AES
import hashlib

from bpylist import archiver
from bpylist.archive_types import uid


class Type(Enum):
    Unknown = 0
    HOTP = 1
    TOTP = 2


class Algorithm(Enum):
    Unknown = 0
    SHA1 = 1  # Used in case of Unknown
    SHA256 = 2
    SHA512 = 3
    MD5 = 4


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


archiver.update_class_map({'NSMutableData': MutableData})
archiver.update_class_map({'NSMutableString': MutableString})
archiver.update_class_map({'ACOTPFolder': OTPFolder})
archiver.update_class_map({'ACOTPAccount': OTPAccount})


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
        if not isinstance(class_uid, uid):
            raise archiver.MissingClassUID(raw_obj)

        klass = self.class_for_uid(class_uid)
        obj = klass.decode_archive(archiver.ArchivedObject(raw_obj, self))

        self.unpacked_uids[index] = obj
        return obj


@click.command()
@click.option('--encrypted-otpauth-backup',
              help="path to your encrypted OTP Auth backup (.otpauthdb)",
              required=True,
              type=click.File('rb'))
def main(encrypted_otpauth_backup):
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

    # Get IV and key for actual archive
    iv = hashlib.sha1(archive['IV'].encode('utf-8')).digest()[:16]
    salt = archive['Salt']
    key = hashlib.sha256((salt + '-' + password).encode('utf-8')).digest()

    # Decrypt actual archive
    data = AES.new(key, AES.MODE_CBC, iv).decrypt(archive['WrappedData'])
    data = data[:-data[-1]]

    # Decode actual archive
    archive = DangerousUnarchive(data).top_object()
    print(archive)


if __name__ == '__main__':
    main()
