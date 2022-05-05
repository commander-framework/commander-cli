import os


class Config(object):
    APP_NAME = os.environ.get("APP_NAME") or "Commander"
    CA_HOSTNAME = os.environ.get("CA_HOSTNAME") or "CAPy.local"
    DB_USER = os.environ.get("DB_USER") or None
    DB_PASS = os.environ.get("DB_PASS") or None
    DB_URI = os.environ.get("DB_URI") or "mongomock://localhost"
    LOG_LEVEL = int(os.environ.get("LOG_LEVEL") or 4)
    JWT_SECRET_KEY = os.environ.get("SECRET_KEY") or "super-secret-default-key"
    REDIS_PASS = os.environ.get("REDIS_PASS") or None
    SECRET_KEY = os.environ.get("SECRET_KEY") or "super-secret-default-key"
    SOCK_SERVER_OPTIONS = {"ping_interval": 25}
    UPLOADS_DIR = os.environ.get("UPLOADS_DIR") or "/opt/commander/library"
    if UPLOADS_DIR[-1] != "/" and UPLOADS_DIR[-1] != "\\":
        UPLOADS_DIR += os.path.sep
