"""A deliberately safe set of handlers: the false-positive guard of the default pack (E16-03).

Synthetic code. Every handler is the safe form of a class the pack covers, so a scan with the
whole default pack must report nothing here.
"""

import hashlib
import hmac
import json
import os
import secrets
import shlex
import subprocess
from html import escape
from urllib.parse import urlparse

import requests
import yaml
from flask import Flask, g, jsonify, redirect, request, session
from Crypto.Cipher import AES
from werkzeug.utils import secure_filename

app = Flask(__name__)
ALLOWED_HOSTS = {"rates.example.com"}


def require_auth(handler):
    return handler


def find(conn, owner):
    cur = conn.cursor()
    cur.execute("SELECT * FROM accounts WHERE owner = %s", (owner,))
    return cur.fetchone()


def archive(folder, name):
    subprocess.run(["zip", "-r", name, folder], check=True)
    return name


def archive_quoted(folder, name):
    command = "zip -r " + shlex.quote(name) + " " + shlex.quote(folder)
    subprocess.run(command, shell=True, check=True)
    return name


def read_report(name):
    base = os.path.realpath("/srv/reports")
    path = os.path.realpath(os.path.join(base, os.path.basename(name)))
    with open(path, encoding="utf-8") as handle:
        return handle.read()


def save_upload(upload):
    upload.save(os.path.join("/srv/uploads", secure_filename(upload.filename)))


def partner_rate(url):
    host = urlparse(url).hostname
    if host not in ALLOWED_HOSTS:
        raise ValueError("host not allowed")
    return requests.get(url, timeout=5).json()


def load(blob):
    return json.loads(blob)


def load_settings(text):
    return yaml.safe_load(text)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def encrypt(key, nonce):
    return AES.new(key, AES.MODE_GCM, nonce=nonce)


def new_token():
    return secrets.token_hex(16)


def same(supplied, expected):
    return hmac.compare_digest(supplied, expected)


def banner(name):
    return "<b>" + escape(name) + "</b>"


@app.route("/health")
def health():
    return jsonify(status="ok")


@app.route("/api/me/accounts/<account_id>")
@require_auth
def my_account(account_id):
    account = find(g.db, account_id)
    if account is None or account["owner_id"] != g.user["id"]:
        return jsonify(error="not found"), 404
    return jsonify(account)


@app.route("/api/me/close", methods=["POST"])
@require_auth
def close_own():
    session.clear()
    return redirect("/")


@app.route("/login", methods=["POST"])
@require_auth
def login():
    response = jsonify(status="ok")
    response.set_cookie("sid", secrets.token_hex(16), secure=True, httponly=True)
    return response
