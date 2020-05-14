import base64
import click
import getpass
import hashlib
import json
import plistlib
import time
import os

from enum import Enum
from urllib.parse import quote

import pyqrcode

from bpylist import archiver
from bpylist.archive_types import timestamp

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

    data: str

    def __init__(self, data: str) -> None:
        self.data = data
    def decode_archive(archive):
        return archive.decode('NS.string')
    def encode_archive(self, archive):
#        print("encoding NSstring")#debug
        #archive.encode('NS.string', self.data)
#        print("In custom String encode...")#debug
        archive._archive_obj['NS.string'] = self.data
#        print(self.data)#debug
#        print("Finished custom String encode...")#debug
        

class MutableData:

    def decode_archive(archive):
        return bytes(archive.decode('NS.data'))

#so'Mist hier noch... aufräumen... später
class MNSData:
    data: bytes
   
    def __init__(self, data: bytes) -> None:
        self.data = data
    def decode_archive(archive):
        return archive.decode('NS.data')
    def encode_archive(self, archive):
#        print("encoding NSdata")#debug
        archive.encode('NS.data', self)

class MAMutableData:
    data: MNSData
    def __init__(self, data: MNSData) -> None:
        self.data = data
    def decode_archive(archive):
        return archive.decode('NS.data')
    def encode_archive(self, archive):
#        print("encoding NSdata")#debug
        archive.encode('NS.data', bytes(self.data))

class MMutableData:

    def __init__(self, value):
        super(MMutableData, self).__init__()
        key = 'NS.data'
        setattr(self, key, value)

    def __getitem__(self, key):
        return getattr(self, key)

    def __setitem__(self, key, value):
        setattr(self, key, value)


 #   def __init__(self, data: bytes) -> None:
 #       self._dict = {}
 #       self._dict['data'] = data

 #   def __init__(self, data: bytes) -> None:
 #       self.data = data
  ##      self.name = "Nudel"

    def encode_archive(self, archive):
 #       print("encoding NSdata")#debug
        archive.encode('NS.data', self.__getitem__('NS.data'))
#        archive.encode('NS.string', self[key])
	
    def decode_archive(archive):
 #       print("decoding NSdata")#debug
       # return NSMutableData(bytes(archive.decode('NS.data')))
        return bytes(archive.decode('NS.data'))

 #   def __eq__(self, other):
 #       return self.data == other.data

 #   def __repr__(self):
 #       return "NSMutableData(%s bytes)" % (
  #          'null' if self.data is None else len(self.data))



class OTPFolder:
    name = None
    accounts = None
    ID = None
    lastModified = None
    

    def __init__(self, name, accounts, ID, lastModified):
        self.name = name
        self.accounts = accounts
        self.ID = ID
        self.lastModified = lastModified

    def __repr__(self):
        return f'<OTPFolder: {self.name}>'

    def decode_archive(archive):
        name = archive.decode('name')
        accounts = archive.decode('accounts')
        ID = archive.decode('ID')
 #       print('ID :=',ID)#debug
        lastModified = archive.decode('lastModified')
 #       print('lastModified')#debug
 #       print(lastModified)#debug
        return OTPFolder(name, accounts, ID, lastModified)
        
    def encode_archive(self, archive):
        archive.encode('name', self.name)
        archive.encode('accounts', self.accounts)
 #       print('ID enc : = ', self.ID)#debug
        archive.encode('ID', self.ID)
        archive.encode('lastModified', self.lastModified)


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
    hideInWidget = False
    ID = None
    hideInMacWidget = True
    lastModified = None
    icon = None
    macWidgetIndex = None
    widgetIndex = None

    def __init__(self, label, issuer, secret, type, algorithm, digits, counter, period, refDate, hideInWidget, ID, hideInMacWidget, lastModified, icon, macWidgetIndex, widgetIndex):
        self.label = label
        self.issuer = issuer
        self.secret = secret
        self.type = type
        self.algorithm = algorithm
        self.digits = digits
        self.counter = counter
        self.period = period
        self.refDate = refDate
        self.hideInWidget = hideInWidget
        self.ID = ID
        self.hideInMacWidget = hideInMacWidget
        self.lastModified = lastModified
        self.icon = icon
        self.macWidgetIndex = macWidgetIndex
        self.widgetIndex = widgetIndex

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
        hideInWidget = archive.decode("hideInWidget")
        ID = archive.decode("ID")
#        print(ID)#debug
 #       print("Type of ID: ")#debug
      #  print(type(ID))
        hideInMacWidget = archive.decode("hideInMacWidget")
        lastModified = archive.decode("lastModified")
        icon = archive.decode("icon")
        macWidgetIndex = archive.decode("macWidgetIndex")
        widgetIndex = archive.decode("widgetIndex")        
        return OTPAccount(label, issuer, secret, type, algorithm, digits, counter, period, refDate, hideInWidget, ID, hideInMacWidget, lastModified, icon, macWidgetIndex, widgetIndex)

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
        hideInWidget = in_dict.get("hideInWidget")
        ID = in_dict.get("ID")
        hideInMacWidget = in_dict.get("hideInMacWidget")
        lastModified = in_dict.get("lastModified")
        icon = in_dict.get("icon")
        macWidgetIndex = in_dict.get("macWidgetIndex")
        widgetIndex = in_dict.get("widgetIndex")
        return OTPAccount(label, issuer, secret, type, algorithm, digits, counter, period, refDate, hideInWidget, ID, hideInMacWidget, lastModified, icon, macWidgetIndex, widgetIndex)
        
    def from_andOtpJson(andOtpJson):
        label = andOtpJson.get("label")
        issuer = andOtpJson.get("issuer")
        secret = andOtpJson.get("secret")
        secret += "=" * ((8 - len(secret) % 8) % 8)
        secret = base64.b32decode(secret.encode())
        type = Type[andOtpJson.get("type")]
        algorithm = Algorithm[andOtpJson.get("algorithm")]
        digits = andOtpJson.get("digits")
        counter = 0   # andOtpJson.get("counter")  #not in andOtp json backup
        period = andOtpJson.get("period")
        refDate = None   # andOtpJson.get("refDate") #not in andOtp json backup
        hideInWidget = False # andOtpJson.get("hideInWidget")   #not in andOtp json backup
        ID = None #implement ID fkt in for-loop andOtpJson.get("ID") #not in andOtp json backup
        hideInMacWidget = True # andOtpJson.get("hideInMacWidget") #not in andOtp json backup
        lastModified = timestamp(time.time()) # andOtpJson.get("lastModified") #not in andOtp json backup
        icon = None # andOtpJson.get("icon") #not in andOtp json backup
        macWidgetIndex = -1 # andOtpJson.get("macWidgetIndex") #not in andOtp json backup
        widgetIndex = None #implement ID fkt in for-loop? #andOtpJson.get("widgetIndex") #not in andOtp json backup
        return OTPAccount(label, issuer, secret, type, algorithm, digits, counter, period, refDate, hideInWidget, ID, hideInMacWidget, lastModified, icon, macWidgetIndex, widgetIndex)

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
        
    def otp_uri_and(self):
        otp_type = self.type.uri_value
        otp_label = quote(self.label)  #<- Changed that to label only since andotp already has it combined
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

##encode account

    def encode_archive(self, archive):
        archive.encode("label", self.label)
        archive.encode("issuer", self.issuer)
#        print("blaaaaaaaaaaaaaaaaaaa------------------") #debug
#        print(self.type)#debug
        archive.encode("secret", self.secret)
#        print(self.type.value)#debug
        archive.encode("type", self.type.value)
#        print(self.algorithm.value)#debug
        archive.encode("algorithm", self.algorithm.value)
        archive.encode("digits", self.digits)
        archive.encode("counter", self.counter)
        archive.encode("period", self.period)
        archive.encode("refDate", self.refDate)
        archive.encode("hideInWidget", self.hideInWidget)
        archive.encode("ID", self.ID)    
        archive.encode("hideInMacWidget", self.hideInMacWidget)
        archive.encode("lastModified", self.lastModified)
        archive.encode("icon", self.icon)
        archive.encode("macWidgetIndex", self.macWidgetIndex)
        archive.encode("widgetIndex", self.widgetIndex)



archiver.update_class_map({'NSMutableData': MAMutableData})
archiver.update_class_map({'NSMutableString': MutableString})
archiver.update_class_map({'ACOTPFolder': OTPFolder})
archiver.update_class_map({'ACOTPAccount': OTPAccount})
archiver.update_class_map({'NSData': MNSData})


class RawRNCryptor(RNCryptor):

    def post_decrypt_data(self, data):
        """Remove useless symbols which
           appear over padding for AES (PKCS#7)."""
#        print("---RawRNCryptor---")#debug
#        print(data)   #debug
#        print(bord(data[-1]))#debug
        data = data[:-bord(data[-1])]
        
        return data


class DangerousArchive(archiver.Archive):
    primitive_types = [int, float, bool, str, plistlib.UID]
    
    def encode_data(self, obj, archive_obj):
        archiver_uid = self.uid_for_archiver('NSMutableData')
        archive_obj['$class'] = archiver_uid
#        print("In custom Data encode...")#debug
        archive_obj['NS.data'] = obj
#        print("Finish custom Data encode...")#debug
        
    def encode_string(self, obj, archive_obj):
        archiver_uid = self.uid_for_archiver('NSMutableString')
        archive_obj['$class'] = archiver_uid
 #       print("In custom String encode...")#debug
        archive_obj['NS.string'] = obj
        
    
    def encode_top_level(self, obj, archive_obj):
        "Encode obj and store the encoding in archive_obj"
 #       print("In custom generic encode...")#debug
 #       print(obj)#debug
 #       print("custom....................")#debug
        cls = obj.__class__

        if cls == list:
            self.encode_list(obj, archive_obj)

        elif cls == dict:
            self.encode_dict(obj, archive_obj)

        elif cls == set:
            self.encode_set(obj, archive_obj)
            
        elif cls == bytes:
            self.encode_data(obj, archive_obj)

        else:
            parchiver = archiver.ARCHIVE_CLASS_MAP.get(cls)
            if parchiver is None:
                raise archiver.MissingClassMapping(obj, archiver.ARCHIVE_CLASS_MAP)

            archiver_uid = self.uid_for_archiver(parchiver)
            archive_obj['$class'] = archiver_uid

            archive_wrapper = archiver.ArchivingObject(archive_obj, self)
            cls.encode_archive(obj, archive_wrapper)
            
    def archive(self, obj) -> plistlib.UID:
        "Add the encoded form of obj to the archive, returning the UID of obj."

        if obj is None:
            return archiver.NULL_UID

        # the ref_map allows us to avoid infinite recursion caused by
        # cycles in the object graph by functioning as a sort of promise
        ref = self.ref_map.get(id(obj))
        if ref:
            return ref

        index = plistlib.UID(len(self.objects))
        self.ref_map[id(obj)] = index

        cls = obj.__class__
        if cls in self.primitive_types:
            self.objects.append(obj)
            return index

        archive_obj = {}
        self.objects.append(archive_obj)
        self.encode_top_level(obj, archive_obj)

        return index

class DangerousUnarchive(archiver.Unarchive):

    def decode_object(self, index):
        if index == 0:
            return None
            
#        print(f'Index: {index}')#debug

        obj = self.unpacked_uids.get(index)
#        print(obj) #debug

        if obj is not None:
            return obj

        raw_obj = self.objects[index]
#        print(f'RAW: {raw_obj}') #debug

        # if obj is a (semi-)primitive type (e.g. str)
        if not isinstance(raw_obj, dict):
            return raw_obj

        class_uid = raw_obj.get('$class')
        if class_uid is None:
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
    
@cli.command()
@click.option('--encrypted-andotp-backup',
              help="path to your encrypted andOTP backup (.json.aes)",
              required=True,
              type=click.File('rb'))
def decrypt_andotp(encrypted_andotp_backup):
 
    ## Get password from user
    password = getpass.getpass(f'Password for export file {encrypted_andotp_backup.name}: ')

    ## Read binary data file     
    data = encrypted_andotp_backup.read()

    ## Get parts of the message containing decryption information
    iterations=data[:4]    
    iterations=int.from_bytes(iterations, "big") 
    salt=data[4:16] 
    iv=data[16:28]
    tag=data[-16:]
    data = data[28:-16]

    ## Key generation
    dk = hashlib.pbkdf2_hmac('sha1', password.encode('utf-8'), salt, iterations, dklen=32)

    ## Decryption
    cipher = AES.new(dk, AES.MODE_GCM, iv, mac_len=16)    
    try:

        plaintext = cipher.decrypt_and_verify(data,tag)
#        print("The message is authentic:", plaintext)
    except ValueError:
        print("Key incorrect or message corrupted")

    ## Create Json data    
    data= json.loads(plaintext.decode('utf-8'))
    ## Optional Show all account data on Screen (uncomment if desired)
#    print(json.dumps(data, indent = 4, sort_keys=True))
    
    ## Get information to build otp uri, for each account in the json backup
    # Produce Account class array and show QR code
    ID =0
    accounts = []
    for transacc in data:
        transacc = OTPAccount.from_andOtpJson(transacc)
        ID += 1
        transacc.ID = str(ID)
        transacc.widgetIndex = str(ID-1)
        accounts.append(transacc)
    print(accounts)
    ## Render QR Code, and show on screen
    for account in accounts:
        print(account)
        render_qr_to_terminal(account.otp_uri_and(), account.type.uri_value, account.issuer, account.label)
        input("Press Enter to continue...")  
       

@cli.command()
@click.option('--encrypted-andotp-backup',
              help="path to your encrypted OTP Auth backup (.otpauthdb)",
              required=True,
              type=click.File('rb'))
def andotp_to_otpauth(encrypted_andotp_backup):
    ## Derive output file name from input basename
    file_basename = os.path.basename(encrypted_andotp_backup.name)
    filename_without_extension = file_basename.split('.')[0]
    output_filename = filename_without_extension + '.otpauthdb'
  
     ## Get password from user
    password = getpass.getpass(f'Password for export file {encrypted_andotp_backup.name}: ')

    ## Read binary data file     
    data = encrypted_andotp_backup.read()

    ## Get parts of the message containing decryption information
    iterations=data[:4]    
    iterations=int.from_bytes(iterations, "big") 
    salt=data[4:16] 
    iv=data[16:28]
    tag=data[-16:]
    data = data[28:-16]

    ## Key generation
    dk = hashlib.pbkdf2_hmac('sha1', password.encode('utf-8'), salt, iterations, dklen=32)

    ## Decryption
    cipher = AES.new(dk, AES.MODE_GCM, iv, mac_len=16)    
    try:
        plaintext = cipher.decrypt_and_verify(data,tag)
#        print("The message is authentic:", plaintext)
    except ValueError:
        print("Key incorrect or message corrupted")

    ## Create Json data    
    data= json.loads(plaintext.decode('utf-8'))
    ## Optional Show all account data on Screen (uncomment if desired)
#    print(json.dumps(data, indent = 4, sort_keys=True))

    ## Build OTPAccount Array for OTP Auth from andOTP Json File including ID creation
    ID =0
    accounts = []
    for transacc in data:
        transacc = OTPAccount.from_andOtpJson(transacc)
        ID += 1
        transacc.ID = str(ID)
        transacc.widgetIndex = ID-1
        accounts.append(transacc)

    ## Create Archive Dict and Folder List for plist OTP Auth Backup File
    newarchive = {}
    newarchive['Folders'] = [OTPFolder('Accounts',accounts,'1',timestamp(time.time()))]
    newarchive['DeletedAccountIDs'] = []
    newarchive['DeletedFolderIDs'] = []    
 
    ## Achive the inner dict as .plist data
    newarchive = DangerousArchive(newarchive).to_bytes()
  
    ## crypt #1 with user pw from andOTP File
    data = RawRNCryptor().encrypt(newarchive, password)
 
    ## Build and Repack outer Archive to .plist data
    repack = {
        "Version" : 1.1,
        "WrappedData" : data,
    }
    
    repack = DangerousArchive(repack).to_bytes()
 
    ## crypt 2 outer with OTP Auth specific details
    iv = bytes(16)
    key = hashlib.sha256('Authenticator'.encode('utf-8')).digest()
    fill=16-len(repack)%16
    repack += bytes([fill])*fill
    data = AES.new(key, AES.MODE_CBC, iv).encrypt(repack)
    
    ## Write output file. Same filename as input. Different extension
    f = open(output_filename, "wb")
    f.write(bytearray(data))
    f.close
    
    click.echo(f'Conversion finished. Encrypted with same password from andOTP Backup. Output file name: {output_filename}')
    

if __name__ == '__main__':
    cli()
