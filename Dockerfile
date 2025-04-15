FROM python:3.13.2-slim-bookworm

COPY requirements.txt /tmp/requirements.txt

RUN --mount=type=cache,target=/root/.cache/pip \
    set -x \
    && pip --disable-pip-version-check \
            install --no-deps \
            -r /tmp/requirements.txt

COPY decrypt_otpauth.py /decrypt_otpauth.py

ENTRYPOINT ["python3", "/decrypt_otpauth.py"]
