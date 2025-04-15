# decrypt-otpauth-files

This tool allows for decrypting the encrypted backups/account files created by [OTP Auth for iOS](http://cooperrs.de/otpauth.html).

If you find problems with the file format (in particular security related issues), do not hesitate and file an issue.

## Requirements

  - [Docker](https://docs.docker.com/) or [Python 3.13](https://www.python.org/downloads/)
  - An encrypted OTP Auth backup/account file

## Usage

### Docker

1. Clone repository

```
git clone https://github.com/CooperRS/decrypt-otpauth-files.git
cd decrypt-otpauth-files
```

2. Build the container

```
docker build --tag decrypt-otpauth-files:local .
```

3. Decrypt your OTP Auth file

```
# Decrypt a full backup file
docker run -it --rm -v <path to your OTP Auth backup>:/backup.otpauthdb decrypt-otpauth-files:local decrypt-backup
```

```
# Decrypt a single account export
docker run -it --rm -v <path to your OTP Auth account>:/account.otpauth decrypt-otpauth-files:local decrypt-account
```

### Python

1. Clone repository

```
git clone https://github.com/CooperRS/decrypt-otpauth-files.git
cd decrypt-otpauth-files
```

2. Install dependencies

```
python3.13 -m venv venv
./venv/bin/pip install -r requirements.txt
```

3. Decrypt your OTP Auth file

```
# Decrypt a full backup file
./venv/bin/python decrypt_otpauth.py decrypt-backup --encrypted-otpauth-backup <path to your OTP Auth backup>
```

```
# Decrypt a single account export
./venv/bin/python decrypt_otpauth.py decrypt-account --encrypted-otpauth-account <path to your OTP Auth account>
```

## Demo

The project contains two OTP Auth exports for demo purposes:

* `backup.otpauthdb`: A complete OTP Auth backup
* `account.otpauth`: One account exported by OTP Auth

The password for both files is `abc123`.

![example gif](demo.gif)

## Credits

Inspired by [ewdurbin](https://github.com/ewdurbin) and their [evacuate_2STP](https://github.com/ewdurbin/evacuate_2stp) repo.
