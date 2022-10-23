import logging
import os
import re
import shlex
import sqlite3
import time
from contextlib import closing
from copy import copy
from pathlib import Path
from typing import List

from plexapi.exceptions import Unauthorized
from plexapi.server import PlexServer
from tabulate import tabulate

from autoscan import utils
from autoscan.db import ScanItem

logger = logging.getLogger("PLEX")


def scan(config, lock, resleep_paths: list, path: str, request_from: str, section_id: int, event_type: str) -> None:
    scan_path = ""
    scan_delay = config["SERVER_SCAN_DELAY"]

    # sleep for delay
    while True:
        logger.info("Scan request from '%s' for '%s'.", request_from, path)

        if scan_delay:
            logger.info("Sleeping for %d seconds...", scan_delay)
            time.sleep(scan_delay)

        # check if root scan folder for
        if path in resleep_paths:
            logger.info("Another scan request occurred for folder of '%s'.", path)
            logger.info("Sleeping again for %d seconds...", scan_delay)
            while path in resleep_paths:
                resleep_paths.remove(path)
        else:
            break

    # check file exists
    checks = 0
    check_path = utils.map_pushed_path_file_exists(config, path)
    scan_path_is_directory = os.path.isdir(check_path)
    scan_path_is_asset = utils.allowed_scan_extension(check_path, config["PLEX_ASSET_EXTENSIONS"])  # mod
    scan_path_in_extras = Path(check_path).parent.name.lower() in map(str.lower, config["PLEX_EXTRA_DIRS"])  # mod

    while True:
        checks += 1
        if os.path.exists(check_path):
            if checks > 1:
                # less verbose
                logger.info(
                    "File '%s' exists on check %d of %d.",
                    check_path,
                    checks,
                    config["SERVER_MAX_FILE_CHECKS"],
                )
            if not scan_path:
                scan_path = os.path.dirname(path).strip() if not scan_path_is_directory else path.strip()
                # mod - change scan_path to its parent if it's in extras like 'featurettes.'
                if scan_path_in_extras:
                    scan_path = os.path.dirname(scan_path)
            break

        if (
            not scan_path_is_directory
            and config["SERVER_SCAN_FOLDER_ON_FILE_EXISTS_EXHAUSTION"]
            and config["SERVER_MAX_FILE_CHECKS"] - checks == 1
        ):
            # penultimate check but SERVER_SCAN_FOLDER_ON_FILE_EXISTS_EXHAUSTION was turned on
            # lets make scan path the folder instead for the final check
            logger.warning(
                "File '%s' reached the penultimate file check. Changing scan path to '%s'. Final check commences "
                "in %s seconds...",
                check_path,
                os.path.dirname(path),
                config["SERVER_FILE_CHECK_DELAY"],
            )
            check_path = os.path.dirname(check_path).strip()
            scan_path = os.path.dirname(path).strip()
            scan_path_is_directory = os.path.isdir(check_path)
            time.sleep(config["SERVER_FILE_CHECK_DELAY"])
            # send Rclone cache clear if enabled
            if config["RCLONE"]["RC_CACHE_REFRESH"]["ENABLED"]:
                utils.rclone_rc_clear_cache(config, check_path)

        elif checks >= config["SERVER_MAX_FILE_CHECKS"]:
            logger.warning("File '%s' exhausted all available checks. Aborting scan request.", check_path)
            # remove item from database
            ScanItem.delete_by_path(path)
            return

        else:
            logger.info(
                "File '%s' did not exist on check %d of %d. Checking again in %s seconds...",
                check_path,
                checks,
                config["SERVER_MAX_FILE_CHECKS"],
                config["SERVER_FILE_CHECK_DELAY"],
            )
            time.sleep(config["SERVER_FILE_CHECK_DELAY"])
            # send Rclone cache clear if enabled
            if config["RCLONE"]["RC_CACHE_REFRESH"]["ENABLED"]:
                utils.rclone_rc_clear_cache(config, check_path)

    # invoke plex scanner
    priority = utils.get_priority(config, scan_path)
    logger.debug("Waiting for turn in the scan request backlog with priority '%d'...", priority)

    lock.acquire(priority)
    try:
        logger.info("Scan request is now being processed...")
        # wait for existing scanners being ran by Plex
        if config["PLEX_WAIT_FOR_EXTERNAL_SCANNERS"] and not wait_plex_scanner(config):
            # remove item from database
            ScanItem.delete_by_path(path)
            return

        # run external command before scan if supplied
        if len(config["RUN_COMMAND_BEFORE_SCAN"]) > 2:
            logger.info("Running external command: %r", config["RUN_COMMAND_BEFORE_SCAN"])
            utils.run_command(config["RUN_COMMAND_BEFORE_SCAN"])
            logger.info("Finished running external command.")

        # wait for Plex to become responsive (if PLEX_CHECK_BEFORE_SCAN is enabled)
        if config.get("PLEX_CHECK_BEFORE_SCAN", False):
            try:
                plex_username = get_plex_server(config, num_retries=10).account().username
                logger.info("Plex is available for media scanning - (Server Account: '%s')", plex_username)
            except Exception:
                logger.error("Plex is unavailable for media scanning. Aborting scan request for '%s'", path)
                ScanItem.delete_by_path(path)
                return

        # begin scan
        logger.info("Sending scan request for '%s'", scan_path)
        scan_plex_section(config, str(section_id), scan_path=scan_path)
        logger.debug("Finished scan!")

        # empty trash if configured
        if config["PLEX_EMPTY_TRASH"] and config["PLEX_TOKEN"] and config["PLEX_EMPTY_TRASH_MAX_FILES"]:
            logger.info("Checking deleted items count in 10 seconds...")
            time.sleep(10)

            # check deleted item count, don't proceed if more than this value
            deleted_items = get_deleted_count(config)
            if deleted_items > config["PLEX_EMPTY_TRASH_MAX_FILES"]:
                logger.warning(
                    "There were %d deleted files. Skip emptying of trash for Section '%s'.",
                    deleted_items,
                    section_id,
                )
            elif deleted_items == -1:
                logger.error("Could not determine deleted item count. Abort emptying of trash.")
            elif not config["PLEX_EMPTY_TRASH_ZERO_DELETED"] and not deleted_items and event_type != "Upgrade":
                logger.debug("Skipping emptying trash as there were no deleted items.")
            else:
                logger.info("Emptying trash to clear %d deleted items...", deleted_items)
                empty_trash_plex_section(config, str(section_id))

        # analyze movie/episode
        if (
            config["PLEX_ANALYZE_TYPE"].lower() != "off"
            and not scan_path_is_directory
            and not scan_path_is_asset
            and not scan_path_in_extras
        ):
            logger.info("Starting '%s' analysis in 10 seconds...", config["PLEX_ANALYZE_TYPE"].lower())
            time.sleep(10)
            logger.debug("Sending analysis request...")
            metadata_item_ids = get_file_metadata_ids(config, path)
            if metadata_item_ids:
                analyze_plex_item(config, metadata_item_ids)
            else:
                logger.warning(
                    "Aborting analysis of '%s' because could not find any 'metadata_item_id' for it.",
                    path,
                )

        # mod - run smi2srt for check_path where scan has just finished
        if config["USE_SMI2SRT"]:
            processed_subtitles = utils.process_subtitle(check_path)
            if processed_subtitles:
                logger.info("Processed subtitles: %s", processed_subtitles)

        # mod - refresh to properly add assets to media item
        if not scan_path_in_extras:
            pattern = re.compile(r"\.(ko|kor|en|eng)(\.(sdh|cc))?(\.forced)?$", flags=re.IGNORECASE)
            for asset in Path(check_path).parent.glob("*.*"):
                if asset.suffix[1:].lower() not in map(str.lower, config["PLEX_ASSET_EXTENSIONS"]):
                    continue
                asset_path = Path(path).parent.joinpath(asset.name)  # from local to plex path
                path_like = re.sub(pattern, "", asset_path.stem)
                path_like = asset_path.parent.joinpath(path_like)
                metadata_item_id = get_file_metadata_id(config, str(path_like) + "%", file_like=True)
                if metadata_item_id is None:
                    logger.debug(
                        "Aborting refresh of '%s' as could not find 'metadata_item_id'.",
                        asset_path,
                    )
                    continue
                if metadata_item_id == get_stream_metadata_id(config, str(asset_path)):
                    logger.debug("Skipping refresh of '%s' as already registered.", asset_path)
                else:
                    refresh_plex_item(config, int(metadata_item_id))
                    time.sleep(10)

        # run external command after scan if supplied
        if len(config["RUN_COMMAND_AFTER_SCAN"]) > 2:
            logger.info("Running external command: %r", config["RUN_COMMAND_AFTER_SCAN"])
            utils.run_command(config["RUN_COMMAND_AFTER_SCAN"])
            logger.info("Finished running external command.")

    except Exception:
        logger.exception("Unexpected exception occurred while processing: '%s'", scan_path)
    finally:
        # remove item from Plex database
        if ScanItem.delete_by_path(path, loglevel=logging.DEBUG):
            logger.info("There are %d scan item(s) remaining.", ScanItem.count())
        lock.release()
    return


############################################################
# db query - direct access to local plex db
############################################################


class PlexSQLite:
    def __init__(self, config: dict):
        self.config = config
        self.conn = None

    def __enter__(self):
        self.conn = sqlite3.connect(self.config["PLEX_DATABASE_PATH"])
        self.conn.row_factory = sqlite3.Row
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.conn.close()

    def queryone(self, *args, **kwargs) -> sqlite3.Row:
        with closing(self.conn.cursor()) as c:
            return c.execute(*args, **kwargs).fetchone()

    def queryall(self, *args, **kwargs) -> List[sqlite3.Row]:
        with closing(self.conn.cursor()) as c:
            return c.execute(*args, **kwargs).fetchall()


# mod
def get_file_metadata_id(config: dict, file_path: str, file_like: bool = False) -> int:
    qstr = "SELECT metadata_item_id FROM media_items WHERE id = (SELECT media_item_id FROM media_parts WHERE file=?)"
    if file_like:
        qstr = qstr.replace("file=?", "file LIKE ?")
    try:
        with PlexSQLite(config) as plexdb:
            return plexdb.queryone(qstr, (file_path,))[0]
    except TypeError:
        logger.debug("Could not find 'metadata_item_id' for '%s' using '%s'", file_path, qstr)
    except Exception:
        logger.exception("Exception finding 'metadata_item_id' for '%s': ", file_path)
    return None


# mod
def get_stream_metadata_id(config: dict, file_path: str) -> int:
    qstr = "SELECT metadata_item_id FROM media_items WHERE id = (SELECT media_item_id FROM media_streams WHERE url=?)"
    url_path = "file://" + file_path.replace("%", "%25").replace(" ", "%20")
    try:
        with PlexSQLite(config) as plexdb:
            return plexdb.queryone(qstr, (url_path,))[0]
    except TypeError:
        logger.debug("Could not find 'metadata_item_id' for '%s' using '%s'", url_path, qstr)
    except Exception:
        logger.exception("Exception finding 'metadata_item_id' for '%s': ", url_path)
    return None


def get_file_metadata_ids(config: dict, file_path: str) -> List[int]:
    """for analyze_plex_item()"""
    results = []
    metadata_item_id = None

    try:
        for x in range(5):
            metadata_item_id = get_file_metadata_id(config, file_path)
            if metadata_item_id:
                logger.debug(
                    "Found row in 'metadata_item_id' where 'file' = '%s' after %d of 5 tries.", file_path, x + 1
                )
                break
            logger.error(
                "Could not locate record in 'metadata_item_id' where 'file' = '%s' in %d of 5 attempts...",
                file_path,
                x + 1,
            )
            time.sleep(10)

        if not metadata_item_id:
            logger.error("Could not locate record in 'metadata_item_id' where 'file' = '%s' after 5 tries", file_path)
            return None

        if not config["PLEX_ANALYZE_DIRECTORY"]:
            # user had PLEX_ANALYZE_DIRECTORY as False - lets just scan the single metadata_item_id
            return [int(metadata_item_id)]

        with PlexSQLite(config) as plexdb:
            try:
                # query db to find parent_id of metadata_item_id
                parent_id = plexdb.queryone("SELECT parent_id FROM metadata_items WHERE id=?", (metadata_item_id,))[0]
                logger.debug("Found 'parent_id' for '%s': %d", file_path, parent_id)
            except Exception:
                # could not find parent_id of this item, likely its a movie...
                # lets just return the metadata_item_id
                return [int(metadata_item_id)]

            # if mode is basic, single parent_id is enough
            if config["PLEX_ANALYZE_TYPE"].lower() == "basic":
                return [int(parent_id)]

            # lets find all metadata_item_id's with this parent_id for use with deep analysis
            metadata_items = plexdb.queryall("SELECT * FROM metadata_items WHERE parent_id=?", (int(parent_id),))
            if not metadata_items:
                # could not find any results, lets just return metadata_item_id
                return [int(metadata_item_id)]

            for row in metadata_items:
                if row["id"] and int(row["id"]) and int(row["id"]) not in results:
                    results.append(int(row["id"]))

            logger.debug("Found 'media_item_id' for '%s': %s", file_path, results)
            logger.info("Found %d 'media_item_id' to deep analyze for: '%s'", len(results), file_path)

    except Exception:
        logger.exception("Exception finding metadata_item_id for '%s': ", file_path)
    return results


def get_deleted_count(config: dict) -> int:
    """for empty_trash_plex_section()"""
    try:
        with PlexSQLite(config) as plexdb:
            deleted_metadata = plexdb.queryone("SELECT count(*) FROM metadata_items WHERE deleted_at IS NOT NULL")[0]
            deleted_media_parts = plexdb.queryone("SELECT count(*) FROM media_parts WHERE deleted_at IS NOT NULL")[0]

        return int(deleted_metadata) + int(deleted_media_parts)

    except Exception:
        logger.exception("Exception retrieving deleted item count from Plex DB: ")
    return -1


def get_section_id(config: dict, path: str) -> int:
    try:
        with PlexSQLite(config) as plexdb:
            # check if file exists in plex
            logger.debug("Checking if root folder path '%s' matches Plex Library root path in the Plex DB.", path)
            section_data = plexdb.queryall("SELECT library_section_id,root_path FROM section_locations")
            for section_id, root_path in section_data:
                if path.startswith(root_path + os.sep):
                    logger.debug(
                        "Plex Library Section ID '%d' matching root folder '%s' was found in the Plex DB.",
                        section_id,
                        root_path,
                    )
                    return int(section_id)
            logger.debug("Unable to map '%s' to a Section ID.", path)

    except Exception:
        logger.exception("Exception while trying to map '%s' to a Section ID in the Plex DB: ", path)
    return -1


def remove_files_already_in_plex(config: dict, file_paths: list) -> int:
    removed_items = 0
    try:
        with PlexSQLite(config) as plexdb, closing(plexdb.conn.cursor()) as c:
            for file_path in copy(file_paths):
                # check if file exists in plex
                file_name = os.path.basename(file_path)
                file_path_plex = utils.map_pushed_path(config, file_path)
                logger.debug("Checking to see if '%s' exists in Plex DB", file_path_plex)
                try:
                    file_size_plex = c.execute(
                        "SELECT size FROM media_parts WHERE file LIKE ? AND deleted_at IS NULL",
                        ("%" + file_path_plex,),
                    ).fetchone()[0]
                    # check if file sizes match in plex
                    file_path_local = utils.map_pushed_path_file_exists(config, file_path_plex)
                    file_size_local = os.path.getsize(file_path_local)
                    logger.debug("'%s' was found in the Plex DB media_parts table.", file_name)
                    logger.debug(
                        "Checking to see if the file size of '%s' matches the existing file size of '%s' in the Plex DB.",
                        file_size_local,
                        file_size_plex,
                    )
                    if file_size_local == file_size_plex:
                        logger.debug("'%s' size matches size found in the Plex DB.", file_size_local)
                        logger.debug("Removing path from scan queue: '%s'", file_path)
                        file_paths.remove(file_path)
                        removed_items += 1
                except Exception:
                    continue

    except Exception:
        logger.exception("Exception checking if %s exists in the Plex DB: ", file_paths)
    return removed_items


############################################################
# api request - plexapi
############################################################


def _get_plex_server(config: dict) -> PlexServer:
    url = config.get("PLEX_LOCAL_URL", "")
    token = config.get("PLEX_TOKEN", "")
    try:
        if not url or not token:
            raise Unauthorized
        return PlexServer(url, token)
    except Exception as e:
        try:
            url = "http://localhost:32400"
            token, pref = utils.get_token_from_pref()
            if token is not None:
                server = PlexServer(url, token)
                logger.warning(
                    "****** FALLBACK PLEX CONNECTION: Unable to check if Plex was ready using 'PLEX_LOCAL_URL' and 'PLEX_TOKEN' in config. Instead, we will use a local server connection to '%s' with 'PLEX_TOKEN' found in '%s' for the current runtime. You may want to consider update config and suppress this warning message.",
                    url,
                    pref,
                )
                config["PLEX_LOCAL_URL"] = url
                config["PLEX_TOKEN"] = token
                return server
        except Exception:
            pass
        raise e


def get_plex_server(config: dict, num_retries: int = 0) -> PlexServer:
    """Getting a PlexServer instance multiple times while handling errors"""
    server = None
    exception = None
    for retry_num in range(num_retries + 1):
        if retry_num > 0:
            # sleep before retrying
            sleep_sec = min(60, 2**retry_num)
            logger.warning(
                "Sleeping %.2f seconds before retry %d of %d for getting PlexServer instance after %s",
                sleep_sec,
                retry_num,
                num_retries,
                str(exception.__class__.__name__) if exception else "exception",
            )
            time.sleep(sleep_sec)

        # catch exception to handle
        try:
            exception = None
            server = _get_plex_server(config)
        except Unauthorized:
            logger.error(
                "You are unauthorized to access Plex Server. Check if 'PLEX_LOCAL_URL' and/or 'PLEX_TOKEN' are valid in config."
            )
            break  # no need to retry
        except Exception as e:
            exception = e
            if retry_num == num_retries:
                logger.exception("Exception while getting a PlexServer instance")
        else:
            break

    return server


def refresh_plex_item(config: dict, metadata_item_id: int) -> None:
    svr = get_plex_server(config)
    if svr is None:
        return
    try:
        item = svr.fetchItem(metadata_item_id)
        item.refresh()
    except Exception:
        logger.exception("Exception refreshing 'metadata_item' %d: ", metadata_item_id)


def show_plex_sections(config: dict, detailed: bool = False) -> None:
    svr = get_plex_server(config)
    if svr is None:
        return
    try:
        tbl_headers = ["key", "title", "type"]
        if detailed:
            tbl_headers += ["items", "size", "lang", "locations"]
        tbl_rows = []
        for section in svr.library.sections():
            row = [section.key, section.title, section.type]
            if detailed:
                row += [
                    section.totalSize,
                    f"{section.totalStorage/float(1024**4):5.2f}T",
                    section.language,
                    "\n".join("- " + l for l in section.locations),
                ]
            tbl_rows += [row]
        print(tabulate(tbl_rows, headers=tbl_headers))
    except Exception:
        logger.exception("Issue encountered when attempting to list sections info.")


def scan_plex_section(config: dict, section_id: str, scan_path: str = None) -> None:
    svr = get_plex_server(config)
    if svr is None:
        return
    try:
        section = svr.library.sectionByID(int(section_id))
        section.update(path=scan_path)

        # wait for scan finished
        for i in range(40):
            time.sleep(min(15, 2**i))
            section.reload()
            if not section.refreshing:
                break
    except Exception:
        logger.exception("Exception while making a scan request:")


def empty_trash_plex_section(config: dict, section_id: str) -> None:
    control_files = config.get("PLEX_EMPTY_TRASH_CONTROL_FILES", [])
    if control_files:
        logger.info("Control file(s) are specified.")

        for control in control_files:
            if not os.path.exists(control):
                logger.info("Skip emptying of trash as control file is not present: '%s'", control)
                return

        logger.info("Commence emptying of trash as control file(s) are present.")

    svr = get_plex_server(config)
    if svr is None:
        return

    for x in range(5):
        try:
            section = svr.library.sectionByID(int(section_id))
            section.emptyTrash()
            break
        except Exception:
            logger.exception(
                "Exception sending empty trash for Section '%s' in %d of 5 attempts: ",
                section_id,
                x + 1,
            )
            time.sleep(10)
    return


############################################################
# external scanner cli
############################################################


def analyze_plex_item(config: dict, metadata_item_ids: List[int]) -> None:
    item_ids = ",".join(str(x) for x in metadata_item_ids)
    analyze_type = config["PLEX_ANALYZE_TYPE"].lower()  # basic, deep, loudness
    arg = "--analyze"
    if analyze_type == "deep":
        arg += "-deeply"
    elif analyze_type == "loudness":
        arg += "-loudness"
    scanner_args = [arg, "--item", item_ids]

    logger.debug("Starting '%s' analysis of 'metadata_item': %s", analyze_type, item_ids)
    run_plex_scanner(config, args=scanner_args)
    logger.info("Finished '%s' analysis of 'metadata_item': %s", analyze_type, item_ids)


def run_plex_scanner(config: dict, args: List[str] = None) -> int:
    if args is None:
        args = []

    if os.name == "nt":
        final_cmd = " ".join(['"' + config["PLEX_SCANNER"] + '"'] + args)
    else:
        cmd = "export LD_LIBRARY_PATH=" + config["PLEX_LD_LIBRARY_PATH"] + ";"
        cmd += "export PLEX_MEDIA_SERVER_APPLICATION_SUPPORT_DIR=" + config["PLEX_SUPPORT_DIR"] + ";"
        cmd += " ".join([config["PLEX_SCANNER"]] + args)

        if config["USE_DOCKER"]:
            final_cmd = ["docker", "exec", "-u", config["PLEX_USER"], "-t", config["DOCKER_NAME"], "bash", "-c", cmd]
        elif config["USE_SUDO"]:
            final_cmd = ["sudo", "-u", config["PLEX_USER"], "bash", "-c", cmd]
        else:
            final_cmd = ["bash", "-c", cmd]

    return utils.run_command(final_cmd)[0]


def wait_plex_scanner(config: dict) -> bool:
    try:
        scanner_name = os.path.basename(config["PLEX_SCANNER"])
        if os.name != "nt":
            scanner_name = scanner_name.replace("\\", "")
        use_docker = config["USE_DOCKER"]
        plex_container = shlex.quote(config["DOCKER_NAME"])
        if not use_docker or not plex_container:
            plex_container = None
        process = utils.get_process_by_name(scanner_name, plex_container)
        while process is not None:
            logger.info(
                "'%s' is running, pid: %d, container: %s, cmdline: %r. Checking again in 60 seconds...",
                process.name(),
                process.pid,
                plex_container,
                process.cmdline(),
            )
            time.sleep(60)
            process = utils.get_process_by_name(scanner_name, plex_container)
        logger.debug("No '%s' processes were found.", scanner_name)
        return True
    except Exception:
        logger.warning(
            "There was a problem waiting for existing '%s' process(s) to finish. Aborting scan.",
            scanner_name,
        )
        return False
