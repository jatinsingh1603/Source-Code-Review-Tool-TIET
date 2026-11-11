import os
from werkzeug.utils import secure_filename


def upload(f):
# ruleid: python.upload.save-client-filename
    f.save(os.path.join("/up", f.filename))


def upload_safe(f):
# ok: python.upload.save-client-filename
    f.save(os.path.join("/up", secure_filename(f.filename)))


def upload_fixed(f):
# ok: python.upload.save-client-filename
    f.save("/up/fixed.bin")
