import json
import logging
import sys
import time
from pathlib import Path

from flask import Flask, abort, jsonify, request

# Get config
from autoscan.config import Config
from autoscan.threads import Thread, PriorityLock


############################################################
# INIT
############################################################

# Logging
log_fmt = "%(asctime)-15s %(levelname)-5.5s %(name)-8.8s [%(threadName)-10.10s]: %(message)s"
formatter = logging.Formatter(log_fmt, datefmt="%Y/%m/%d %H:%M:%S")
rootLogger = logging.getLogger()
rootLogger.setLevel(logging.INFO)

# Decrease modules logging
logging.getLogger("requests").setLevel(logging.ERROR)
logging.getLogger("werkzeug").setLevel(logging.ERROR)
logging.getLogger("peewee").setLevel(logging.ERROR)
logging.getLogger("urllib3.connectionpool").setLevel(logging.ERROR)
logging.getLogger("sqlitedict").setLevel(logging.ERROR)
logging.getLogger("googleapiclient.discovery").setLevel(logging.ERROR)
logging.getLogger("google_auth_httplib2").setLevel(logging.ERROR)
logging.getLogger("requests_oauthlib").setLevel(logging.ERROR)

# Console logger, log to stdout instead of stderr
consoleHandler = logging.StreamHandler(sys.stdout)
consoleHandler.setFormatter(formatter)
rootLogger.addHandler(consoleHandler)

# Load initial config
conf = Config()

if conf.settings["logfile"] is not None:
    from logging.handlers import RotatingFileHandler

    # File logger
    fileHandler = RotatingFileHandler(
        conf.settings["logfile"],
        maxBytes=1024 * 1024 * 2,
        backupCount=5,
        encoding="utf-8",
    )
    fileHandler.setFormatter(formatter)
    rootLogger.addHandler(fileHandler)

# Set configured log level
rootLogger.setLevel(conf.settings["loglevel"])
# Load config file
conf.load()

# Scan logger
logger = rootLogger.getChild("AUTOSCAN")

# Multiprocessing
thread = Thread()
scan_lock = PriorityLock()
resleep_paths = []

# local imports
from autoscan import db, plex, utils, rclone
from autoscan.drive import GoogleDriveManager

manager = None


############################################################
# QUEUE PROCESSOR
############################################################


def queue_processor():
    logger.info("Starting queue processor in 10 seconds...")
    try:
        time.sleep(10)
        logger.info("Queue processor started.")
        db_scan_requests = db.get_all_items()
        items = 0
        for db_item in db_scan_requests:
            thread.start(
                plex.scan,
                args=[
                    conf.configs,
                    scan_lock,
                    db_item["scan_path"],
                    db_item["scan_for"],
                    db_item["scan_section"],
                    db_item["scan_type"],
                    resleep_paths,
                ],
            )
            items += 1
            time.sleep(2)
        logger.info("Restored %d scan request(s) from Autoscan database.", items)
    except Exception:
        logger.exception("Exception while processing scan requests from Autoscan database.")


############################################################
# FUNCS
############################################################


def start_scan(path, scan_for, scan_type):
    ignored, plexignore = utils.is_plex_ignored(path)
    if ignored:
        logger.info("Ignored scan request for '%s' because of plexignore", path)
        logger.debug(">> Plexignore: '%s'", plexignore)
        return False
    section = plex.get_section_id(conf.configs, path)
    if section <= 0:
        logger.info("Ignored scan request for '%s' as associated plex sections not found.", path)
        return False
    logger.info("Using Section ID '%s' for '%s':", section, path)

    if conf.configs["SERVER_USE_SQLITE"]:
        db_exists, db_file = db.exists_file_root_path(path)
        if not db_exists and db.add_item(path, scan_for, section, scan_type):
            logger.info(">> Added to Autoscan database.")
        else:
            logger.debug(">> Already processing '%s' from same folder.", db_file)
            logger.info(">> Skip adding extra scan request to the queue.")
            resleep_paths.append(db_file)
            return False

    logger.info("Proceeding with scan...")
    thread.start(
        plex.scan,
        args=[conf.configs, scan_lock, path, scan_for, section, scan_type, resleep_paths],
    )
    return True


############################################################
# GOOGLE DRIVE
############################################################


def process_google_changes(items_added):
    new_file_paths = []

    # process items added
    if not items_added:
        return True

    for _, file_paths in items_added.items():
        for file_path in file_paths:
            if file_path in new_file_paths:
                continue
            new_file_paths.append(file_path)

    # remove files that already exist in the plex database
    removed_exists = utils.remove_files_already_in_plex(conf.configs, new_file_paths)

    if removed_exists:
        logger.info("Rejected %d file(s) from Google Drive changes for already being in Plex.", removed_exists)

    # remove files that have common parents
    removed_common = utils.remove_files_having_common_parent(new_file_paths)

    if removed_common:
        logger.info("Rejected %d file(s) from Google Drive changes for having common parent.", removed_common)

    # process the file_paths list
    if new_file_paths:
        logger.info("Proceeding with scan of %d file(s) from Google Drive changes:", len(new_file_paths))
        for file_path in new_file_paths:
            logger.info(f">> '{file_path}'")

        # loop each file, remapping and starting a scan thread
        for file_path in new_file_paths:
            final_path = utils.map_pushed_path(conf.configs, file_path)
            start_scan(final_path, "Google Drive", "Download")

    return True


def thread_google_monitor():
    global manager

    # initialize crypt_decoder to None
    crypt_decoder = None

    # load rclone client if crypt being used
    if conf.configs["RCLONE"]["CRYPT_MAPPINGS"] != {}:
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
            # queue count
            if not conf.configs["SERVER_USE_SQLITE"]:
                # return error if SQLITE db is not enabled
                return jsonify({"success": False, "msg": "SERVER_USE_SQLITE must be enabled"})
            return jsonify({"success": True, "queue_count": db.get_queue_count()})
        if cmd == "reset_page_token":
            if manager is None:
                return jsonify({"success": False, "msg": "Google Drive monitoring is not enabled"})
            manager.reset_page_token()
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
    if event == "Test":
        logger.info("Client %r made a test request, event: '%s'", request.remote_addr, event)
    elif event == "Manual" and data.get("filepath", ""):
        logger.info(
            "Client %r made a manual scan request for: '%s'",
            request.remote_addr,
            data["filepath"],
        )
        final_path = utils.map_pushed_path(conf.configs, data["filepath"])
        # ignore this request?
        ignored, ignored_by = utils.is_server_ignored(conf.configs, final_path)
        if ignored:
            logger.info(
                "Ignored scan request for '%s' because '%s' was matched from SERVER_IGNORE_LIST",
                final_path,
                ignored_by,
            )
            return f"Ignoring scan request because {ignored_by} was matched from your SERVER_IGNORE_LIST"
        if not start_scan(final_path, event, event):
            return f"Already been added to the scan queue.: {final_path}"
    elif event == "Watcher" and data.get("pipe", ""):
        isfile, action, paths = utils.parse_watcher_event(data["pipe"])
        if isfile and action in ("CREATE", "MOVE", "REMOVE"):
            for path in paths:
                final_path = utils.map_pushed_path(conf.configs, path)
                # ignore this request?
                ignored, ignored_by = utils.is_server_ignored(conf.configs, final_path)
                if ignored:
                    logger.info(
                        "Ignored scan request for '%s' because '%s' was matched from SERVER_IGNORE_LIST",
                        final_path,
                        ignored_by,
                    )
                    continue
                start_scan(final_path, event, event)
    else:
        logger.error("Unknown scan request from: %r", request.remote_addr)
        abort(400)

    return "OK"


############################################################
# MAIN
############################################################

if __name__ == "__main__":
    if conf.args["cmd"] == "sections":
        plex.show_plex_sections(conf.configs)
        sys.exit(0)
    elif conf.args["cmd"] == "sections+":
        plex.show_plex_sections(conf.configs, detailed=True)
        sys.exit(0)
    elif conf.args["cmd"] == "update_config":
        sys.exit(0)
    elif conf.args["cmd"] == "authorize":
        if not conf.configs["GOOGLE"]["ENABLED"]:
            logger.error("You must enable the GOOGLE section in config.")
            sys.exit(1)
        while True:
            user_input = input("Enter the path to 'client secrets file' (q to quit): ")
            user_input = user_input.strip()
            if user_input:
                if user_input == "q":
                    sys.exit(0)
                elif Path(user_input).exists():
                    client_secrets_file = user_input
                    break
                else:
                    print(f"\tInvalid answer: {user_input}")
        print("")
        from autoscan.drive import Cache
        from google_auth_oauthlib.flow import InstalledAppFlow

        settings = Cache(conf.settings["cachefile"]).get_cache("settings", autocommit=True)
        flow = InstalledAppFlow.from_client_secrets_file(
            client_secrets_file, scopes=["https://www.googleapis.com/auth/drive"]
        )
        flow.run_console()
        auth_info = json.loads(flow.credentials.to_json())
        settings["auth_info"] = auth_info
        logger.info(f"Authorization Successful!:\n\n{json.dumps(auth_info, indent=2)}\n")
        sys.exit(0)

    elif conf.args["cmd"] == "server":
        if conf.configs["SERVER_USE_SQLITE"]:
            thread.start(queue_processor)

        if conf.configs["GOOGLE"]["ENABLED"]:
            thread.start(thread_google_monitor)

        logger.info(
            "Starting server: http://%s:%d/%s",
            conf.configs["SERVER_IP"],
            conf.configs["SERVER_PORT"],
            conf.configs["SERVER_PASS"],
        )
        app.run(
            host=conf.configs["SERVER_IP"],
            port=conf.configs["SERVER_PORT"],
            debug=False,
            use_reloader=False,
        )
        logger.info("Server stopped")
        sys.exit(0)
    elif conf.args["cmd"] == "build_caches":
        logger.info("Building caches")
        # load google drive manager
        manager = GoogleDriveManager(
            conf.settings["cachefile"],
            drive_config=conf.configs["GOOGLE"]["DRIVES"],
            service_account_file=conf.configs["GOOGLE"]["SERVICE_ACCOUNT_FILE"],
            allowed_config=conf.configs["GOOGLE"]["ALLOWED"],
            show_cache_logs=conf.configs["GOOGLE"]["SHOW_CACHE_LOGS"],
        )
        # build cache
        manager.build_caches()
        logger.info("Finished building all caches.")
        sys.exit(0)
    else:
        logger.error("Unknown command.")
        sys.exit(1)
