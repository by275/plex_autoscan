import json
import logging
import os
import sys
import time
from pathlib import Path

from flask import Flask, abort, jsonify, request
from google_auth_oauthlib.flow import InstalledAppFlow

# Get config
from autoscan.config import Config, setup_root_logger
from autoscan.threads import PriorityLock, Thread

############################################################
# INIT
############################################################

# Logging
setup_root_logger()

# Load initial config
conf = Config()

if conf.settings["logfile"] is not None:
    from logging.handlers import RotatingFileHandler

    # File logger
    fileHandler = RotatingFileHandler(conf.settings["logfile"], maxBytes=2 * 1024**2, backupCount=5, encoding="utf-8")
    setup_root_logger(handler=fileHandler)

# Set configured log level
logging.getLogger().setLevel(conf.settings["loglevel"])
# Load config file
conf.load()

# Scan logger
logger = logging.getLogger("MAIN")

# Multiprocessing
thread = Thread()
scan_lock = PriorityLock()
resleep_paths = []

# local imports
from autoscan import plex, rclone, utils
from autoscan.db import ScanItem
from autoscan.drive import Cache, GoogleDriveManager

manager = None


############################################################
# QUEUE PROCESSOR
############################################################


def queue_processor():
    logger.info("Starting queue processor in 10 seconds...")
    time.sleep(10)
    try:
        logger.info("Queue processor started.")
        items = 0
        for scan_item in ScanItem.select().dicts():
            for key in ["id", "created_at"]:
                scan_item.pop(key)
            thread.start(plex.scan, args=[conf.configs, scan_lock, resleep_paths], kwargs=scan_item)
            items += 1
            time.sleep(2)
        logger.info("Restored %d scan request(s) from Autoscan database.", items)
    except Exception:
        logger.exception("Exception while processing scan requests from Autoscan database.")


############################################################
# FUNCS
############################################################


def start_scan(path: str, request_from: str, event_type: str) -> bool:
    """entrypoint for starting scan thread"""
    path = utils.map_pushed_path(conf.configs, path)

    ignored, ignored_by = utils.is_server_ignored(conf.configs, path, request_from)
    if ignored:
        logger.info("Ignored scan request for '%s' because '%s' was matched from SERVER_IGNORE_LIST", path, ignored_by)
        return False
    ignored, plexignore = utils.is_plex_ignored(path)
    if ignored:
        logger.info("Ignored scan request for '%s' because of plexignore '%s'.", path, plexignore)
        return False
    section_id = plex.get_section_id(conf.configs, path)
    if section_id <= 0:
        logger.info("Ignored scan request for '%s' as associated plex sections not found.", path)
        return False

    scan_item = {"path": path, "request_from": request_from, "section_id": section_id, "event_type": event_type}
    is_added, db_item = ScanItem.get_or_add(**scan_item)
    if is_added:
        logger.debug("Added '%s' to Autoscan database.", path)
    elif db_item:
        logger.info(
            "Already processing '%s' from same folder. Skip adding extra scan request to the queue.", db_item.path
        )
        resleep_paths.append(db_item.path)
        return False

    logger.debug("Proceeding with Section ID '%s' for '%s'...", section_id, path)
    thread.start(plex.scan, args=[conf.configs, scan_lock, resleep_paths], kwargs=scan_item)

    return True


class KnownException(Exception):
    pass


############################################################
# GOOGLE DRIVE
############################################################


def process_google_changes(items_added: dict):
    """process items added"""
    if not items_added:
        return True

    new_files = []
    for item_paths in items_added.values():
        new_files.extend(x for x in item_paths if x not in new_files)

    # remove files that already exist in the plex database
    removed_exists = plex.remove_files_already_in_plex(conf.configs, new_files)

    if removed_exists:
        logger.info("Rejected %d file(s) from Google Drive changes for already being in Plex.", removed_exists)

    # remove files that have common parents
    removed_common = utils.remove_files_having_common_parent(new_files)

    if removed_common:
        logger.info("Rejected %d file(s) from Google Drive changes for having common parent.", removed_common)

    # process the new_files list
    if new_files:
        logger.info("Proceeding with scan of %d file(s) from Google Drive changes: %s", len(new_files), new_files)

        # loop each file, remapping and starting a scan thread
        for file_path in new_files:
            start_scan(file_path, "Google Drive", "Download")

    return True


def thread_google_monitor():
    global manager

    # initialize crypt_decoder to None
    crypt_decoder = None

    # load rclone client if crypt being used
    if conf.configs["RCLONE"]["CRYPT_MAPPINGS"]:
        logger.info("Crypt mappings have been defined. Initializing Rclone Crypt Decoder...")
        crypt_decoder = rclone.RcloneDecoder(
            conf.configs["RCLONE"]["BINARY"],
            conf.configs["RCLONE"]["CRYPT_MAPPINGS"],
            conf.configs["RCLONE"]["CONFIG"],
        )

    # load google drive manager
    manager = GoogleDriveManager(
        conf.settings["cachefile"],
        drive_config=conf.configs["GOOGLE"]["DRIVES"],
        service_account_file=conf.configs["GOOGLE"]["SERVICE_ACCOUNT_FILE"],
        allowed_config=conf.configs["GOOGLE"]["ALLOWED"],
        show_cache_logs=conf.configs["GOOGLE"]["SHOW_CACHE_LOGS"],
        crypt_decoder=crypt_decoder,
    )

    # set callbacks
    manager.set_callbacks({"items_added": process_google_changes})

    logger.info("Starting Google Drive monitoring in 30 seconds...")
    time.sleep(30)

    try:
        logger.info("Google Drive monitoring started.")
        while True:
            # poll for changes
            manager.get_changes()
            # sleep before polling for changes again
            time.sleep(conf.configs["GOOGLE"]["POLL_INTERVAL"])

    except Exception:
        logger.exception("Fatal Exception occurred while monitoring Google Drive for changes: ")


############################################################
# SERVER
############################################################

app = Flask("AUTOSCAN")
app.config["JSON_AS_ASCII"] = False


@app.route(f"/api/{conf.configs['SERVER_PASS']}", methods=["GET", "POST"])
def api_call():
    try:
        if request.content_type == "application/json":
            data = request.get_json(silent=True)
        elif request.method == "POST":
            data = request.form.to_dict()
        else:
            data = request.args.to_dict()

        cmd = data.get("cmd", "").lower()
        logger.info("Client %s API call from %r, cmd: %s", request.method, request.remote_addr, cmd)

        # process cmds
        if cmd == "queue_count":
            return jsonify({"success": True, "queue_count": ScanItem.count()})
        if cmd == "reset_page_token":
            if manager is None:
                return jsonify({"success": False, "msg": "Google Drive monitoring is not enabled"})
            manager.reset_page_token()
            return jsonify({"success": True})
        if cmd == "clear_drive_cache":
            if manager is None:
                return jsonify({"success": False, "msg": "Google Drive monitoring is not enabled"})
            manager.clear_cache()
            return jsonify({"success": True})
        # unknown cmd
        return jsonify({"success": False, "msg": f"Unknown cmd: {cmd}"})

    except Exception:
        logger.exception("Exception parsing %s API call from %r:", request.method, request.remote_addr)
        return jsonify({"success": False, "msg": "Unexpected error occurred, check logs..."})


@app.route(f"/{conf.configs['SERVER_PASS']}", methods=["POST"])
def client_pushed():
    if request.content_type == "application/json":
        data = request.get_json(silent=True)
    else:
        data = request.form.to_dict()

    if not data:
        logger.error("Invalid scan request from: %r", request.remote_addr)
        abort(400)
    logger.debug(
        "Client %r request dump:\n%s",
        request.remote_addr,
        json.dumps(data, indent=4, sort_keys=True),
    )

    event = data.get("eventType", "")
    upgrade = "Upgrade" if data.get("isUpgrade", False) else event

    if event == "Test":
        logger.info("Client %r made a test request, event: '%s'", request.remote_addr, event)

    elif event == "Manual" and data.get("filepath", ""):
        path = data["filepath"]
        logger.info("Client %r made a manual scan request for: '%s'", request.remote_addr, path)
        if not start_scan(path, event, event):
            return "Something went wrong. Check the logs for more details..."

    elif event == "Watcher" and data.get("pipe", ""):
        isfile, action, paths = utils.parse_watcher_event(data["pipe"])
        if isfile and action in ("CREATE", "MOVE", "REMOVE"):
            for path in paths:
                start_scan(path, event, action)

    elif "series" in data and event == "Rename" and "path" in data["series"]:
        # sonarr Rename webhook
        path = data["series"]["path"]
        logger.info("Client %r scan request for series: '%s', event: '%s'", request.remote_addr, path, upgrade)
        start_scan(path, "Sonarr", upgrade)

    elif "movie" in data and event == "Rename" and "folderPath" in data["movie"]:
        # radarr Rename webhook
        path = data["movie"]["folderPath"]
        logger.info("Client %r scan request for movie: '%s', event: '%s'", request.remote_addr, path, upgrade)
        start_scan(path, "Radarr", upgrade)

    elif data.get("movie", {}).get("folderPath", "") and data.get("movieFile", {}).get("relativePath", ""):
        # radarr download/upgrade webhook
        path = os.path.join(data["movie"]["folderPath"], data["movieFile"]["relativePath"])
        logger.info("Client %r scan request for movie: '%s', event: '%s'", request.remote_addr, path, upgrade)
        start_scan(path, "Radarr", upgrade)

    elif "series" in data and "episodeFile" in data:
        # sonarr download/upgrade webhook
        path = os.path.join(data["series"]["path"], data["episodeFile"]["relativePath"])
        logger.info("Client %r scan request for series: '%s', event: '%s'", request.remote_addr, path, upgrade)
        start_scan(path, "Sonarr", upgrade)

    elif "artist" in data:
        # Lidarr download/upgrade webhook
        for track in data.get("trackFiles", []):
            if "path" not in track and "relativePath" not in track:
                continue

            path = track["path"] if "path" in track else os.path.join(data["artist"]["path"], track["relativePath"])
            logger.info("Client %r scan request for album track: '%s', event: '%s'", request.remote_addr, path, upgrade)
            start_scan(path, "Lidarr", upgrade)

    else:
        logger.error("Unknown scan request from: %r", request.remote_addr)
        abort(400)

    return "OK"


def start_server(config: dict) -> None:
    if plex.get_plex_server(config, num_retries=6) is None:
        raise KnownException("Unable to establish connection to Plex. Check above logs for details.")

    if not Path(config["PLEX_DATABASE_PATH"]).exists():
        raise KnownException(f"Unable to locate Plex DB file: PLEX_DATABASE_PATH={config['PLEX_DATABASE_PATH']}")

    if config["PLEX_ANALYZE_TYPE"].lower() != "off":
        rc = plex.run_plex_scanner(config)
        if rc is None or rc:
            raise KnownException("Unable to run 'Plex Media Scanner' binary. Check your config again.")

    if ScanItem.count():
        thread.start(queue_processor, name="Queue")

    if config["GOOGLE"]["ENABLED"]:
        thread.start(thread_google_monitor, name="Drive")

    logger.info("Starting server: http://%s:%d/%s", config["SERVER_IP"], config["SERVER_PORT"], config["SERVER_PASS"])
    app.run(host=config["SERVER_IP"], port=config["SERVER_PORT"], debug=False, use_reloader=False)
    logger.info("Server stopped")


############################################################
# MAIN
############################################################


def process_menu(cmd: str) -> None:
    if cmd == "sections":
        plex.show_plex_sections(conf.configs)
    elif cmd == "sections+":
        plex.show_plex_sections(conf.configs, detailed=True)
    elif cmd == "update_config":
        return
    elif cmd == "authorize":
        if not conf.configs["GOOGLE"]["ENABLED"]:
            raise KnownException("You must enable the GOOGLE section in config.")
        while True:
            user_input = input("Enter a path to 'client secrets file' (q to quit): ")
            user_input = user_input.strip()
            if user_input:
                if user_input == "q":
                    return
                if Path(user_input).exists():
                    client_secrets_file = user_input
                    break
                print(f"\tInvalid answer: {user_input}")
        print("")

        settings = Cache(conf.settings["cachefile"]).get_cache("settings", autocommit=True)
        flow = InstalledAppFlow.from_client_secrets_file(
            client_secrets_file, scopes=["https://www.googleapis.com/auth/drive"]
        )
        port = utils.get_free_port()
        logger.info(
            "Running a local server at port %d which will be waiting for authorization code redirected from google. If Autoscan is not running on the same host you are about to opening the following link, consider using SSH tunneling: ssh -L %d:127.0.0.1:%d username@to-this-host\n",
            port,
            port,
            port,
        )
        flow.run_local_server(port=port, open_browser=False)
        auth_info = json.loads(flow.credentials.to_json())
        settings["auth_info"] = auth_info
        logger.info("Authorization Successful!:\n\n%s\n", json.dumps(auth_info, indent=2))

    elif cmd == "server":
        ScanItem.init(conf.settings["queuefile"])
        start_server(conf.configs)
    elif cmd == "build_caches":
        logger.info("Building caches")
        # load google drive manager
        gdm = GoogleDriveManager(
            conf.settings["cachefile"],
            drive_config=conf.configs["GOOGLE"]["DRIVES"],
            service_account_file=conf.configs["GOOGLE"]["SERVICE_ACCOUNT_FILE"],
            allowed_config=conf.configs["GOOGLE"]["ALLOWED"],
            show_cache_logs=conf.configs["GOOGLE"]["SHOW_CACHE_LOGS"],
        )
        # build cache
        gdm.build_caches()
        logger.info("Finished building all caches.")
    else:
        raise KnownException(f"Unknown command: {cmd}")


def main():
    try:
        process_menu(conf.args["cmd"])
    except KnownException as e:
        logger.error(e)
        sys.exit(1)


if __name__ == "__main__":
    main()
