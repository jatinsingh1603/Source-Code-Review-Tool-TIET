import os
from flask import Flask, request

app = Flask(__name__)


@app.route('/ping')
def ping():
    os.system('ping ' + request.args['host'])  # PG-VULN-001
