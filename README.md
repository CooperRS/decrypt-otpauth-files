# decrypt-otpauth-files

This version was forked to add some functions while keeping the excellent original functionality untouched.

This tool allows for decrypting the encrypted backups/account files created by [OTP Auth for iOS](http://cooperrs.de/otpauth.html).  
The tool can now also decrypt the (password protected) backup files from [andOTP for Android](https://play.google.com/store/apps/details?id=org.shadowice.flocke.andotp&hl=en_US) (Open Source on [GitHub](https://github.com/andOTP/andOTP)) in the same way this is still possible for OTP Auth (iPhones).  
To move accounts over from Android to iPhones, there is a function to convert encrypted andOTP files to encrypted OTP Auth backup files. Eliminating the risk of keeping plain files stored somewhere on a disk. Also being independent from cloud storage based OTP services which are available on both plattforms.

If you find problems with the file format (in particular security related issues), do not hesitate and file an issue.

## Changes in this fork
  - Updated to Python 3.8
  - Changed to Cryptodomex 3.9.7 (due to conflics with pycrypto in Py3.8)
  - Changed from byplist to byplist2 (due to ascii encoding error of the plist generator)
  - Added full decode and encode of all original .plist content from Auth OTP backup file
  - Added function to read password encrypted AndOtp Backup Files and print QR codes
  - Added function Read andOTP Accounts (Android) into classes and store as encrypted Auth OTP backup for Iphone

## Known Issues
  - time.clock() error: `AttributeError: module 'time' has no attribute 'clock'`  
    => Solution: Change `time.clock()` to `time.process_time()` in the `Crypto/Random/_UserFriendlyRNG.py` of your virtual environment lib files
  - The source code is a total mess, but "worked on my computer"
  - Usage at your own Risk (maybe don't try it on your single daily phone with all accounts on... :-)
  - Written for my personal use and own requirements - yours might differ
  
Tested on Ubuntu 20.04 with OTP Auth 2.16.2 (711) and andOTP 0.7.0-play

## Requirements

  - [Python 3.8](https://www.python.org/downloads/)
  - [pipenv](https://github.com/pypa/pipenv)
  - An encrypted OTP Auth backup/account file or an andOTP password encrypted backup file

## Usage

1. Clone repository

```
git clone https://github.com/Vascomax/decrypt-otpauth-files.git
cd decrypt-otpauth-files
```

2. Install dependencies

```
pipenv install
```

3. Decrypt your OTP Auth file

```
# Decrypt a full backup file
pipenv run python decrypt_otpauth.py decrypt_backup --encrypted-otpauth-backup <path to your OTP Auth backup>
```

```
# Decrypt a single account export
pipenv run python decrypt_otpauth.py decrypt_account --encrypted-otpauth-account <path to your OTP Auth account>
```

4. Decrypt your andOTP file

```
# Decrypt a full backup file
pipenv run python decrypt_otpauth.py decrypt_andotp --encrypted-andotp-backup <path to your andOTP backup>
```

5. Convert your andOTP file to a OTP Auth file (your password will stay the same)

```
# Convert a full backup file
pipenv run python decrypt_otpauth.py andotp_to_otpauth --encrypted-andotp-backup <path to your andOTP backup>
```

## Demo

The project contains two OTP Auth and one andOTP export for demo purposes:

* `backup.otpauthdb`: A complete OTP Auth backup
* `account.otpauth`: One account exported by OTP Auth
* `andotp-accounts.json.aes`: A complete andOTP backup

The password for all three files is `abc123`.

![example gif](demo.gif)

## Credits

Inspired by [CooperRS](https://github.com/CooperRS) and his [decrypt-otpauth-files](https://github.com/CooperRS/decrypt-otpauth-files) repo, which was inspired by [ewdurbin](https://github.com/ewdurbin) and his [evacuate_2STP](https://github.com/ewdurbin/evacuate_2stp) repo.
