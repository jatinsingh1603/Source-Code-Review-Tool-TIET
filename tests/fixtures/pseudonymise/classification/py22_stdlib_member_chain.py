import os


def config_path(folder):
    return os.path.join(folder, os.environ.get("CONFIG", "app.ini"))
