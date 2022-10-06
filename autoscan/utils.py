import logging
import os
import subprocess
from contextlib import closing
from copy import copy
from urllib.parse import urljoin
from pathlib import Path
from typing import Tuple, Union
import re
import shlex
import xml.etree.ElementTree as ET
import socket

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


def is_server_ignored(config: dict, file_path: str, request_from: str) -> Tuple[bool, str]:
    if request_from not in ["Manual", "Watcher"]:
        return False, None
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


def get_token_from_pref() -> Tuple[str, Path]:
    known_pms_dirs = [
        "/config/Library/Application Support/Plex Media Server/",
        "/var/lib/plexmediaserver/Library/Application Support/Plex Media Server/",
    ]
    try:
        for pms_dir in known_pms_dirs:
            pref_file = Path(pms_dir).joinpath("Preferences.xml")
            if not pref_file.exists():
                continue
            pref = ET.parse(pref_file).getroot().attrib
            return pref["PlexOnlineToken"], pref_file
    except Exception:
        return None, None


def get_free_port() -> int:
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
        s.bind(("", 0))
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        return s.getsockname()[1]


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

    cmd = f"docker inspect --format '{{{{.Name}}}}' {container_id}"
    rc, output = run_command(shlex.split(cmd))
    if not rc and output:
        return output.lstrip("/")
    return None


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
                container_name_by_pid = container_name_by_pid.strip()
                if container_name_by_pid.lower() == container_name.lower():
                    return True, process, container_name_by_pid

        return False, None, container_name
    except psutil.ZombieProcess:
        return False, None, container_name
    except Exception:
        logger.exception("Exception checking for process: '%s': ", process_name)
        return False, None, container_name


def run_command(command: Union[str, list], shell: bool = False) -> Tuple[int, str]:
    # If shell is True, it is recommended to pass args as a string rather than as a sequence.
    try:
        logger.debug("Executing command: %s", command)
        output_lines = []
        with subprocess.Popen(command, shell=shell, stdout=subprocess.PIPE, stderr=subprocess.STDOUT) as proc:
            while proc.poll() is None:
                for line in iter(proc.stdout.readline, b""):
                    output_lines.append(line.decode(errors="ignore").rstrip())

            rc = proc.returncode
        output = os.linesep.join(output_lines)
        if rc:
            # non-zero returncode
            logger.error("Process terminated with exit code: %s\n%s", rc, output)
        return rc, output
    except Exception:
        logger.exception("Exception occurred while executing command: %s", command)
        return None, None
