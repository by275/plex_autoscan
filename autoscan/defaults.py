import uuid
from pathlib import Path

base_settings = {
    "config": {
        "argv": "--config",
        "env": "PLEX_AUTOSCAN_CONFIG",
        "default": str(Path.cwd().joinpath("config.json")),
    },
    "logfile": {"argv": "--logfile", "env": "PLEX_AUTOSCAN_LOGFILE", "default": None},
    "loglevel": {
        "argv": "--loglevel",
        "env": "PLEX_AUTOSCAN_LOGLEVEL",
        "default": "INFO",
    },
    "queuefile": {
        "argv": "--queuefile",
        "env": "PLEX_AUTOSCAN_QUEUEFILE",
        "default": str(Path.cwd().joinpath("queue.db")),
    },
    "cachefile": {
        "argv": "--cachefile",
        "env": "PLEX_AUTOSCAN_CACHEFILE",
        "default": str(Path.cwd().joinpath("cache.db")),
    },
}

base_config = {
    "PLEX_USER": "plex",
    "PLEX_SCANNER": "/usr/lib/plexmediaserver/Plex\\ Media\\ Scanner",
    "PLEX_SUPPORT_DIR": "/var/lib/plexmediaserver/Library/Application\\ Support",
    "PLEX_LD_LIBRARY_PATH": "/usr/lib/plexmediaserver/lib",
    "PLEX_DATABASE_PATH": "/var/lib/plexmediaserver/Library/Application Support/Plex Media Server"
    "/Plug-in Support/Databases/com.plexapp.plugins.library.db",
    "PLEX_LOCAL_URL": "http://localhost:32400",
    "PLEX_EMPTY_TRASH": False,
    "PLEX_EMPTY_TRASH_MAX_FILES": 100,
    "PLEX_EMPTY_TRASH_CONTROL_FILES": [],
    "PLEX_EMPTY_TRASH_ZERO_DELETED": False,
    "PLEX_WAIT_FOR_EXTERNAL_SCANNERS": True,
    "PLEX_ANALYZE_TYPE": "basic",
    "PLEX_ANALYZE_DIRECTORY": True,
    "PLEX_FIX_MISMATCHED": False,
    "PLEX_FIX_MISMATCHED_LANG": "en",
    "PLEX_TOKEN": "",
    "PLEX_CHECK_BEFORE_SCAN": False,
    "SERVER_IP": "0.0.0.0",
    "SERVER_PORT": 3467,
    "SERVER_PASS": uuid.uuid4().hex,
    "SERVER_PATH_MAPPINGS": {},
    "SERVER_SCAN_DELAY": 180,
    "SERVER_MAX_FILE_CHECKS": 10,
    "SERVER_FILE_CHECK_DELAY": 60,
    "SERVER_FILE_EXIST_PATH_MAPPINGS": {},
    "SERVER_ALLOW_MANUAL_SCAN": False,
    "SERVER_IGNORE_LIST": [],
    "SERVER_USE_SQLITE": False,
    "SERVER_SCAN_PRIORITIES": {},
    "SERVER_SCAN_FOLDER_ON_FILE_EXISTS_EXHAUSTION": False,
    "RCLONE": {
        "RC_CACHE_REFRESH": {"ENABLED": False, "FILE_EXISTS_TO_REMOTE_MAPPINGS": {}, "RC_URL": "http://localhost:5572"},
        "BINARY": "/usr/bin/rclone",
        "CRYPT_MAPPINGS": {},
        "CONFIG": "",
    },
    "DOCKER_NAME": "plex",
    "RUN_COMMAND_BEFORE_SCAN": "",
    "RUN_COMMAND_AFTER_SCAN": "",
    "USE_DOCKER": False,
    "USE_SUDO": True,
    "GOOGLE": {
        "ENABLED": False,
        "CLIENT_ID": "",
        "CLIENT_SECRET": "",
        "ALLOWED": {
            "FILE_PATHS": [],
            "FILE_EXTENSIONS": False,
            "FILE_EXTENSIONS_LIST": [],
            "MIME_TYPES": False,
            "MIME_TYPES_LIST": [],
        },
        "POLL_INTERVAL": 120,
        "TEAMDRIVE": False,
        "TEAMDRIVES": [],
        "SHOW_CACHE_LOGS": True,
    },
}

base_config["PLEX_ASSET_EXTENSIONS"] = ["smi", "srt", "idx", "sub", "ass", "ssa"]
base_config["PLEX_EXTRA_DIRS"] = [
    "Behind The Scenes",
    "Deleted Scenes",
    "Featurettes",
    "Interviews",
    "Scenes",
    "Shorts",
    "Trailers",
    "Other",
]

base_config["GOOGLE"].pop("CLIENT_ID")
base_config["GOOGLE"].pop("CLIENT_SECRET")
base_config["GOOGLE"].pop("TEAMDRIVE")
base_config["GOOGLE"].pop("TEAMDRIVES")
base_config["GOOGLE"]["SERVICE_ACCOUNT_FILE"] = ""
base_config["GOOGLE"]["DRIVES"] = {
    "MY_DRIVE": True,
    "SHARED_DRIVES": False,
    "SHARED_DRIVES_LIST": [],
}
