import logging
import os
import sqlite3
import subprocess
from contextlib import closing
from copy import copy
from urllib.parse import urljoin
from pathlib import Path
from typing import Tuple, Union
import re

import psutil
import requests

from autoscan.smi2srt import SMI2SRTHandle

logger = logging.getLogger("UTILS")


def map_pushed_path(config: dict, path: str) -> str:
    for mapped_path, mappings in config["SERVER_PATH_MAPPINGS"].items():
        for mapping in mappings:
            if path.startswith(mapping):
                logger.debug("Mapping server path '%s' to '%s'.", mapping, mapped_path)
                return path.replace(mapping, mapped_path)
    return path


def map_pushed_path_file_exists(config: dict, path: str) -> str:
    for mapped_path, mappings in config["SERVER_FILE_EXIST_PATH_MAPPINGS"].items():
        for mapping in mappings:
            if path.startswith(mapping):
                logger.debug("Mapping file check path '%s' to '%s'.", mapping, mapped_path)
                return path.replace(mapping, mapped_path)
    return path


# For Rclone dir cache clear request
def map_file_exists_path_for_rclone(config: dict, path: str) -> str:
    for mapped_path, mappings in config["RCLONE"]["RC_CACHE_REFRESH"]["FILE_EXISTS_TO_REMOTE_MAPPINGS"].items():
        for mapping in mappings:
            if path.startswith(mapping):
                logger.debug("Mapping Rclone file check path '%s' to '%s'.", mapping, mapped_path)
                return path.replace(mapping, mapped_path)
    return path


def is_server_ignored(config: dict, file_path: str) -> Tuple[bool, str]:
    for item in config["SERVER_IGNORE_LIST"]:
        if item.lower() in file_path.lower():
            return True, item
    return False, None


def get_priority(config: dict, scan_path: str) -> int:
    try:
        for priority, paths in config["SERVER_SCAN_PRIORITIES"].items():
            for path in paths:
                if path.lower() in scan_path.lower():
                    logger.debug("Using priority '%d' for path '%s'", int(priority), scan_path)
                    return int(priority)
        logger.debug("Using default priority '0' for path '%s'", scan_path)
    except Exception:
        logger.exception("Exception determining priority to use for '%s': ", scan_path)
    return 0


def rclone_rc_clear_cache(config: dict, scan_path: str) -> bool:
    try:
        rclone_rc_forget_url = urljoin(config["RCLONE"]["RC_CACHE_REFRESH"]["RC_URL"], "vfs/forget")
        rclone_rc_refresh_url = urljoin(config["RCLONE"]["RC_CACHE_REFRESH"]["RC_URL"], "vfs/refresh")

        cache_clear_path = map_file_exists_path_for_rclone(config, scan_path).lstrip(os.path.sep)
        logger.debug("Top level cache_clear_path: '%s'", cache_clear_path)

        while True:
            last_clear_path = cache_clear_path
            cache_clear_path = os.path.dirname(cache_clear_path)
            if cache_clear_path == last_clear_path or not cache_clear_path:
                # is the last path we tried to clear, the same as this path, if so, abort
                logger.error(
                    "Aborting Rclone dir cache clear request for '%s' due to directory level exhaustion, last level: '%s'",
                    scan_path,
                    last_clear_path,
                )
                return False
            last_clear_path = cache_clear_path

            # send Rclone VFS cache clear request
            logger.info("Sending Rclone VFS cache clear request for: '%s'", cache_clear_path)
            try:
                # try cache clear
                resp = requests.post(rclone_rc_forget_url, json={"dir": cache_clear_path}, timeout=120)
                data = resp.json()
                if "error" in data:
                    # try to vfs/refresh as fallback
                    resp = requests.post(rclone_rc_refresh_url, json={"dir": cache_clear_path}, timeout=120)
                    data = resp.json()
                    if "result" in data and data["result"].get(cache_clear_path, "") == "OK":
                        # successfully vfs refreshed
                        logger.info(
                            "Successfully refreshed Rclone VFS cache for '%s'",
                            cache_clear_path,
                        )
                        return True

                    logger.info(
                        "Failed to clear Rclone VFS cache for '%s': %s", cache_clear_path, data.get("error", data)
                    )
                    continue
                if cache_clear_path in data.get("forgotten", []):
                    logger.info("Successfully cleared Rclone VFS cache for '%s'", cache_clear_path)
                    return True

                # abort on unexpected response (no json response, no error/status & message in returned json
                logger.error(
                    "Unexpected Rclone RC response from %s while trying to clear '%s': %s",
                    rclone_rc_forget_url,
                    cache_clear_path,
                    resp.text,
                )
                break

            except Exception:
                logger.exception(
                    "Exception sending Rclone VFS cache clear request to %s for '%s': ",
                    rclone_rc_forget_url,
                    cache_clear_path,
                )
                break

    except Exception:
        logger.exception("Exception clearing Rclone VFS cache for '%s': ", scan_path)
    return False


def remove_files_already_in_plex(config: dict, file_paths: list) -> int:
    removed_items = 0
    try:
        with sqlite3.connect(config["PLEX_DATABASE_PATH"]) as conn:
            conn.row_factory = sqlite3.Row
            with closing(conn.cursor()) as c:
                for file_path in copy(file_paths):
                    # check if file exists in plex
                    file_name = os.path.basename(file_path)
                    file_path_plex = map_pushed_path(config, file_path)
                    logger.debug("Checking to see if '%s' exists in Plex DB", file_path_plex)
                    found_item = c.execute(
                        "SELECT size FROM media_parts WHERE file LIKE ?",
                        ("%" + file_path_plex,),
                    ).fetchone()
                    file_path_actual = map_pushed_path_file_exists(config, file_path_plex)
                    if found_item and os.path.isfile(file_path_actual):
                        # check if file sizes match in plex
                        file_size = os.path.getsize(file_path_actual)
                        logger.debug("'%s' was found in the Plex DB media_parts table.", file_name)
                        logger.debug(
                            "Checking to see if the file size of '%s' matches the existing file size of '%s' in the Plex DB.",
                            file_size,
                            found_item[0],
                        )
                        if file_size == found_item[0]:
                            logger.debug("'%s' size matches size found in the Plex DB.", file_size)
                            logger.debug("Removing path from scan queue: '%s'", file_path)
                            file_paths.remove(file_path)
                            removed_items += 1

    except Exception:
        logger.exception("Exception checking if %s exists in the Plex DB: ", file_paths)
    return removed_items


def allowed_scan_extension(file_path: str, extensions: list) -> bool:
    check_path = file_path.lower()
    for ext in extensions:
        if check_path.endswith(ext.lower()):
            logger.debug("'%s' had allowed extension: %s", file_path, ext)
            return True
    logger.debug("'%s' did not have an allowed extension.", file_path)
    return False


# mod
def process_subtitle(file_path: str) -> list:
    result = SMI2SRTHandle.start(
        os.path.dirname(file_path),
        remake=False,
        recursive=False,
        no_remove_smi=True,
        no_append_ko=False,
        no_change_ko_srt=True,
    )
    processed = []
    for res in result.get("list", []):
        if res.get("ret", "fail") == "success":
            logger.info("'%s' to SRT", Path(res["smi_file"]).name)
            for srt in res.get("srt_list", []):
                processed.append(srt["srt_file"])
        else:
            logger.warning(res)
    return processed


# mod
def remove_files_having_common_parent(file_paths: list) -> int:
    removed_items = 0
    seen_parents = []
    for file_path in sorted(copy(file_paths)):
        parent = Path(file_path).parent
        if parent in seen_parents:
            file_paths.remove(file_path)
            removed_items += 1
        else:
            seen_parents.append(parent)
    return removed_items


# mod
def is_plex_ignored(file_path: Union[str, Path]) -> Tuple[bool, Path]:
    """determine whether given file path is ignored by .plexignore"""
    file_path = Path(file_path)
    current_path = file_path
    while True:
        if current_path == current_path.parent:
            break
        current_path = current_path.parent
        if not current_path.is_dir():
            break
        plexignore = current_path.joinpath(".plexignore")
        if not plexignore.is_file():
            continue
        try:
            with open(plexignore, "r", encoding="utf-8") as fp:
                lines = (l.strip() for l in fp.readlines())
                ignores = [i for i in lines if i and not i.startswith("#")]
        except Exception:
            ignores = []
        relative_path = file_path.relative_to(current_path)
        absolute_path = Path("/").joinpath(relative_path)
        if any(absolute_path.match("/" + x.lstrip("/")) for x in ignores):
            return True, plexignore
    return False, None


# mod
def parse_watcher_event(pipe: str) -> Tuple[bool, str, list]:
    pattern = re.compile(r'^(?P<type>[A-Z]+) "(?P<name>[^"]+)" (?P<action>[A-Z]+) \[(?P<path>.+)\]$')
    try:
        m = pattern.match(pipe)
        isfile = m.group("type") == "FILE"  # FILE or DIRECTORY
        action = m.group("action")
        paths = m.group("path").split(" -> ")
        return isfile, action, paths
    except Exception:
        logger.exception("Exception while parsing watcher event '%s': ", pipe)
    return False, None, None


############################################################
# functions using psutil and subprocess
############################################################


def get_container_name_by_pid(pid: int) -> str:
    container_id = None
    pattern = re.compile(r"[A-z0-9]{64}")
    with open(f"/proc/{pid}/cgroup", "r", encoding="utf-8") as f:
        for line in f.readlines():
            matched = pattern.search(line)
            if matched:
                container_id = matched.group(0)
                break
    if container_id is None:
        return None

    cmd = f"docker inspect --format '{{{{.Name}}}}' {container_id} | cut -c2-"
    return run_command(cmd, get_output=True)


def is_process_running(process_name: str, container_name: str = None) -> Tuple[bool, psutil.Process, str]:
    try:
        for process in psutil.process_iter():
            if process.name().lower() == process_name.lower():
                if not container_name:
                    return True, process, container_name
                # container_name was not None
                # we need to check if this processes is from the container we are interested in
                container_name_by_pid = get_container_name_by_pid(process.pid)
                logger.debug("Docker Container for PID %s: %r", process.pid, container_name_by_pid)
                if container_name_by_pid is None:
                    continue
                if isinstance(container_name_by_pid, str):
                    container_name_by_pid = container_name_by_pid.strip()
                    if container_name_by_pid.lower() == container_name.lower():
                        return True, process, container_name_by_pid

        return False, None, container_name
    except psutil.ZombieProcess:
        return False, None, container_name
    except Exception:
        logger.exception("Exception checking for process: '%s': ", process_name)
        return False, None, container_name


def run_command(command: str, get_output: bool = False) -> Union[str, int]:
    logger.debug("Executing command: '%s'", command)
    output_lines = []
    with subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT) as proc:
        while proc.poll() is None:
            output = proc.stdout.readline().decode(errors="ignore").rstrip()
            if not get_output:
                logger.info(output)
            else:
                output_lines.append(output)

        # drop empty lines at the end
        if output_lines and not output_lines[-1]:
            output_lines.pop()

        rc = proc.poll()  # returncode
        output = os.linesep.join(output_lines)
        if rc:
            logger.error("Error occurred while executing command: '%s'\n%s", command, output)
        return output if get_output else rc
