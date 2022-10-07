import json
import logging
import os
import sys
from copy import copy

from google.oauth2 import credentials, service_account
from googleapiclient.discovery import build
from sqlitedict import SqliteDict

logger = logging.getLogger("DRIVE")


class Cache:
    def __init__(self, cache_path):
        self.cache_path = cache_path
        self.caches = {}

    def get_cache(self, cache_name, autocommit=False):
        if cache_name not in self.caches:
            self.caches[cache_name] = SqliteDict(
                self.cache_path,
                tablename=cache_name,
                encode=json.dumps,
                decode=json.loads,
                autocommit=autocommit,
            )
        return self.caches[cache_name]


class GoogleDriveManager:
    def __init__(
        self,
        cache_path,
        drive_config,
        service_account_file=None,
        allowed_config=None,
        show_cache_logs=True,
        crypt_decoder=None,
    ):
        cache_manager = Cache(cache_path)
        self.settings = cache_manager.get_cache("settings", autocommit=True)

        self.load_service(service_account_file=service_account_file)

        self.cache = cache_manager.get_cache("cache")
        self.allowed_config = {} if not allowed_config else allowed_config
        self.show_cache_logs = show_cache_logs
        self.crypt_decoder = crypt_decoder

        self.load_drives(drive_config)

    def load_service(self, service_account_file=None):
        if service_account_file:
            try:
                cred = service_account.Credentials.from_service_account_file(service_account_file)
                logger.info("Credentials loaded from service account file:")
            except Exception:
                try:
                    cred = service_account.Credentials.from_service_account_info(service_account_file)
                    logger.info("Credentials loaded from service account info:")
                except Exception:
                    logger.exception("Failed to load credentials from service account:")
                    sys.exit(1)
        else:
            if "auth_info" not in self.settings:
                logger.error("Authorization required. Use 'authorize' command.")
                sys.exit(1)
            cred = credentials.Credentials.from_authorized_user_info(self.settings["auth_info"])
            logger.info("Credentials loaded from authorized user info:")
        try:
            # pylint: disable=no-member
            svc = build("drive", "v3", credentials=cred, cache_discovery=False)
            res = svc.about().get(fields="user(displayName,emailAddress)").execute(num_retries=10)
            logger.info(res["user"])
            self.svc = svc
        except Exception:
            logger.exception("Exception while validating google drive service client: ")
            sys.exit(1)

    def load_drives(self, drive_config):
        drives = []
        if drive_config.get("MY_DRIVE", False):
            drives.append({"id": None, "name": "My Drive"})

        if drive_config.get("SHARED_DRIVES", False):
            # pylint: disable=no-member
            res = self.svc.drives().list(pageSize=100, fields="drives(id,name)").execute(num_retries=10)
            allowed_drives = drive_config.get("SHARED_DRIVES_LIST", [])
            drives.extend([x for x in res["drives"] if x["name"] in allowed_drives])

        if drives:
            logger.info("Loading %d drive(s)...", len(drives))
            self.drives = []
            for drv in drives:
                self.drives.append(
                    GoogleDrive(
                        drv["name"],
                        self.svc,
                        self.cache,
                        self.settings,
                        drive_id=drv["id"],
                        crypt_decoder=self.crypt_decoder,
                        allowed_config=self.allowed_config,
                        show_cache_logs=self.show_cache_logs,
                    )
                )
                logger.info("GoogleDrive instance: %s: '%s'", drv["id"], drv["name"])
        else:
            logger.error("No drives are configured. Check your config.")
            sys.exit(1)

    def get_changes(self):
        for drv in self.drives:
            logger.debug("Retrieving changes from drive: %s", drv.name)
            drv.get_changes()
        logger.debug("Finished retrieving changes from all loaded drives")

    def set_callbacks(self, callbacks):
        for drv in self.drives:
            drv.set_callbacks(callbacks)

    def build_caches(self):
        for drv in self.drives:
            logger.info("Building cache for drive: %s", drv.name)
            drv.show_cache_logs = False
            drv.get_changes(page_token="1")
            logger.info("Finished building cache for drive: %s", drv.name)

    def reset_page_token(self):
        for drv in self.drives:
            logger.info("Resetting page token for drive: %s", drv.name)
            drv.pop_setting("page_token")
        logger.debug("Finished resetting page token for all loaded drives")

    def clear_cache(self):
        self.cache.conn.commit()
        self.cache.conn.execute(f'DELETE FROM "{self.cache.tablename}";')
        self.cache.conn.commit()
        self.cache.conn.execute("VACUUM")
        self.cache.conn.commit()
        logger.debug("Finished clearing drive cache")


class GoogleDrive:
    def __init__(
        self,
        name,
        svc,
        cache,
        settings,
        drive_id=None,
        allowed_config=None,
        show_cache_logs=True,
        crypt_decoder=None,
    ):
        self.name = name
        self.svc = svc
        self.cache = cache
        self.settings = settings
        self.drive_id = drive_id
        self.callbacks = {}
        self.allowed_config = {} if not allowed_config else allowed_config
        self.show_cache_logs = show_cache_logs
        self.crypt_decoder = crypt_decoder

        self.set_setting("name", name)

    ############################################################
    # CORE CLASS METHODS
    ############################################################

    def get_setting(self, key=None):
        drive_key = "My Drive" if self.drive_id is None else self.drive_id
        drive_setting = self.settings.get(drive_key, {})
        if key is None:
            return drive_setting
        return drive_setting.get(key)

    def set_setting(self, key, val):
        drive_key = "My Drive" if self.drive_id is None else self.drive_id
        drive_setting = self.get_setting()
        drive_setting.update({key: val})
        self.settings[drive_key] = drive_setting

    def pop_setting(self, key):
        drive_key = "My Drive" if self.drive_id is None else self.drive_id
        drive_setting = self.get_setting()
        drive_setting.pop(key, None)
        self.settings[drive_key] = drive_setting

    def set_callbacks(self, callbacks=None):
        if callbacks is None:
            callbacks = {}
        for callback_type, callback_func in callbacks.items():
            self.callbacks[callback_type] = callback_func

    ############################################################
    # DRIVE FUNCTIONS
    ############################################################

    def get_start_page_token(self):
        try:
            params = {
                "driveId": self.drive_id,
                "supportsAllDrives": True,
            }
            req = self.svc.changes().getStartPageToken(**params)
            res = req.execute(num_retries=10)
            return res.get("startPageToken")
        except Exception:
            logger.exception("Fatal Error while getting start page token for changes")
            return None

    def get_changes(self, page_token=None):
        # get page token
        if page_token is None:
            page_token = self.get_setting("page_token")
        if page_token is None:
            page_token = self.get_start_page_token()
        if page_token is None:
            logger.error("Failed to determine a page_token to use...")
            return

        # https://stackoverflow.com/a/50707508/9689068
        file_fields = "file(md5Checksum,mimeType,modifiedTime,name,parents,driveId,trashed)"
        fields = [
            "newStartPageToken",
            "nextPageToken",
            f"changes({file_fields},fileId,removed,drive(id,name),driveId)",
        ]
        params = {
            "pageToken": page_token,
            "pageSize": 100,
            "spaces": "drive",
            "fields": ",".join(fields),
            "driveId": self.drive_id,
            "supportsAllDrives": True,
            "includeItemsFromAllDrives": True,
        }
        changes = []
        req = self.svc.changes().list(**params)
        while req is not None:
            res = req.execute(num_retries=10)
            changes = changes + res.get("changes", [])
            req = self.svc.changes().list_next(req, res)

        # for the next time
        self.set_setting("page_token", res.get("newStartPageToken"))

        if changes:
            logger.debug("Processing %d changes...", len(changes))
            self._process_changes(changes)
        else:
            logger.debug("There were no changes to process")
            return

    ############################################################
    # CACHE
    ############################################################

    def get_id_metadata(self, item_id, drive_id=None):
        # return cache from metadata if available
        cached_metadata = self.cache.get(item_id)
        if cached_metadata:
            return True, cached_metadata

        try:
            # does item_id match drive_id?
            if drive_id and item_id == drive_id:
                res = self.svc.drives().get(driveId=drive_id).execute(num_retries=10)
                res["mimeType"] = "application/vnd.google-apps.folder"
                self._do_callback("drive_added", res)
            else:
                # retrieve file metadata
                params = {
                    "fileId": item_id,
                    "supportsAllDrives": True,
                    "fields": "id,md5Checksum,mimeType,modifiedTime,name,parents,trashed,driveId",
                }
                req = self.svc.files().get(**params)
                res = req.execute(num_retries=10)
            return True, res
        except Exception:
            logger.exception("Exception retrieving metadata for item '%s': ", item_id)
            return False, None

    def get_paths_by_id(self, item_id, drive_id=None):
        file_paths = []
        added_to_cache = 0

        try:

            def get_item_paths(obj_id, path, paths, new_cache_entries, drive_id=None):
                success, obj = self.get_id_metadata(obj_id, drive_id)
                if not success:
                    return new_cache_entries

                drive_id = obj.get("driveId", drive_id)

                # add item object to cache if we know its not from cache
                if "mimeType" in obj:
                    # we know this is a new item fetched from the api, because the cache does not store this field
                    self.add_item_to_cache(
                        obj["id"],
                        obj["name"],
                        obj.get("parents", []),
                        obj.get("md5Checksum"),
                    )
                    new_cache_entries += 1

                path = os.path.join(obj["name"], path) if path.strip() else obj["name"]

                for parent in obj.get("parents", []):
                    new_cache_entries += get_item_paths(parent, path, paths, new_cache_entries, drive_id)

                if (not obj or not obj.get("parents", [])) and len(path):
                    paths.append(path)
                    return new_cache_entries
                return new_cache_entries

            added_to_cache += get_item_paths(item_id, "", file_paths, added_to_cache, drive_id)
            if added_to_cache:
                logger.debug("Dumping cache due to new entries!")
                self.cache.commit()

            if file_paths:
                return True, file_paths
            return False, file_paths

        except Exception:
            logger.exception("Exception retrieving filepaths for '%s': ", item_id)

        return False, []

    def add_item_to_cache(self, item_id, item_name, parents, md5checksum, paths=None):
        if paths is None:
            paths = []

        if self.show_cache_logs and item_id not in self.cache:
            logger.info("Added '%s' to cache: %s", item_id, item_name)

        if not paths:
            cached_item = self.get_item_from_cache(item_id)
            if cached_item:
                paths = cached_item.get("paths", [])
        self.cache[item_id] = {
            "name": item_name,
            "parents": parents,
            "md5Checksum": md5checksum,
            "paths": paths,
        }

    def remove_item_from_cache(self, item_id):
        if self.cache.pop(item_id, None):
            return True
        return False

    def get_item_from_cache(self, item_id):
        try:
            return self.cache.get(item_id)
        except Exception:
            pass
        return None

    ############################################################
    # INTERNALS
    ############################################################

    def _remove_unwanted_paths(self, paths_list, mime_type):
        removed_file_paths = []
        # remove paths that were not allowed - this is always enabled
        if "FILE_PATHS" in self.allowed_config:
            for item_path in copy(paths_list):
                allowed_path = False
                for allowed_file_path in self.allowed_config["FILE_PATHS"]:
                    if item_path.lower().startswith(allowed_file_path.lower()):
                        allowed_path = True
                        break
                if not allowed_path:
                    logger.debug("Ignoring '%s' because its not an allowed path.", item_path)
                    removed_file_paths.append(item_path)
                    paths_list.remove(item_path)
                    continue

        # remove unallowed extensions
        if (
            self.allowed_config.get("FILE_EXTENSIONS", False)
            and self.allowed_config.get("FILE_EXTENSIONS_LIST", [])
            and len(paths_list)
        ):
            for item_path in copy(paths_list):
                allowed_file = False
                for allowed_extension in self.allowed_config["FILE_EXTENSIONS_LIST"]:
                    if item_path.lower().endswith(allowed_extension.lower()):
                        allowed_file = True
                        break
                if not allowed_file:
                    logger.debug("Ignoring '%s' because it was not an allowed extension.", item_path)
                    removed_file_paths.append(item_path)
                    paths_list.remove(item_path)

        # remove unallowed mimes
        if (
            self.allowed_config.get("MIME_TYPES", False)
            and self.allowed_config.get("MIME_TYPES_LIST", [])
            and len(paths_list)
        ):
            allowed_file = False
            for allowed_mime in self.allowed_config["MIME_TYPES_LIST"]:
                if allowed_mime.lower() in mime_type.lower():
                    if "video" in mime_type.lower():
                        # we want to validate this is not a .sub file, which for some reason, google shows as video/MP2G
                        double_checked_allowed = True
                        for item_path in paths_list:
                            if item_path.lower().endswith(".sub"):
                                double_checked_allowed = False
                        if double_checked_allowed:
                            allowed_file = True
                            break
                    else:
                        allowed_file = True
                        break

            if not allowed_file:
                logger.debug("Ignoring '%s' because it was not an allowed mime: '%s'", paths_list, mime_type)
                for item_path in copy(paths_list):
                    removed_file_paths.append(item_path)
                    paths_list.remove(item_path)
        return removed_file_paths

    def _process_changes(self, changes):
        unwanted_file_paths = []
        added_file_paths = {}
        ignored_file_paths = {}
        renamed_file_paths = {}
        moved_file_paths = {}
        removes = 0

        # process changes
        for change in changes:
            if "file" in change and "fileId" in change:
                file = change["file"]
                file_id = change["fileId"]
                # dont consider trashed/removed events for processing
                if file.get("trashed", False) or change.get("removed", False):
                    if self.remove_item_from_cache(file_id) and self.show_cache_logs:
                        logger.info("Removed '%s' from cache: %s", file_id, file["name"])
                    removes += 1
                    continue

                # retrieve item from cache
                cached_item = self.get_item_from_cache(file_id)

                # we always want to add changes to the cache so renames etc can be reflected inside the cache
                self.add_item_to_cache(
                    file_id,
                    file["name"],
                    file.get("parents", []),
                    file.get("md5Checksum"),
                )

                # get this files paths
                success, item_paths = self.get_paths_by_id(file_id, file.get("driveId"))
                if success:
                    # save item paths
                    self.add_item_to_cache(
                        file_id,
                        file["name"],
                        file.get("parents", []),
                        file.get("md5Checksum"),
                        paths=item_paths,
                    )

                # check if decoder is present
                if self.crypt_decoder:
                    decoded = self.crypt_decoder.decode_path(item_paths[0])
                    if decoded:
                        item_paths = decoded

                # dont process folder events
                if "vnd.google-apps.folder" in file.get("mimeType", ""):
                    # ignore this change as we dont want to scan folders
                    logger.debug("Ignoring %s because it is a folder", item_paths)
                    if file_id in ignored_file_paths:
                        ignored_file_paths[file_id].extend(item_paths)
                    else:
                        ignored_file_paths[file_id] = item_paths
                    continue

                # remove unwanted paths
                if success and item_paths:
                    unwanted_paths = self._remove_unwanted_paths(item_paths, file.get("mimeType", "Unknown"))
                    if isinstance(unwanted_paths, list) and unwanted_paths:
                        unwanted_file_paths.extend(unwanted_paths)

                # was this an existing item?
                if cached_item is not None and (success and item_paths):
                    # this was an existing item, and we are re-processing it again
                    # we need to determine if this file has changed (md5Checksum)
                    if "md5Checksum" in file and "md5Checksum" in cached_item:
                        # compare this changes md5Checksum and the existing cache item
                        if file["md5Checksum"] != cached_item["md5Checksum"]:
                            # the file was modified
                            if file_id in added_file_paths:
                                added_file_paths[file_id].extend(item_paths)
                            else:
                                added_file_paths[file_id] = item_paths
                        else:
                            if ("name" in file and "name" in cached_item) and file["name"] != cached_item["name"]:
                                logger.debug("md5Checksum matches but file was server-side renamed: %s", item_paths)
                                if file_id in added_file_paths:
                                    added_file_paths[file_id].extend(item_paths)
                                else:
                                    added_file_paths[file_id] = item_paths

                                if file_id in renamed_file_paths:
                                    renamed_file_paths[file_id].extend(item_paths)
                                else:
                                    renamed_file_paths[file_id] = item_paths
                            elif "paths" in cached_item and not self._list_matches(item_paths, cached_item["paths"]):
                                logger.debug(
                                    "md5Checksum matches but file was server-side moved: %s",
                                    item_paths,
                                )

                                if file_id in added_file_paths:
                                    added_file_paths[file_id].extend(item_paths)
                                else:
                                    added_file_paths[file_id] = item_paths

                                if file_id in moved_file_paths:
                                    moved_file_paths[file_id].extend(item_paths)
                                else:
                                    moved_file_paths[file_id] = item_paths

                            else:
                                logger.debug(
                                    "Ignoring %r because the md5Checksum was the same as cache: %s",
                                    item_paths,
                                    cached_item["md5Checksum"],
                                )
                                if file_id in ignored_file_paths:
                                    ignored_file_paths[file_id].extend(item_paths)
                                else:
                                    ignored_file_paths[file_id] = item_paths
                    else:
                        logger.error("No md5Checksum for cache item:\n%s", cached_item)

                elif success and item_paths:
                    # these are new paths/files that were not already in the cache
                    if file_id in added_file_paths:
                        added_file_paths[file_id].extend(item_paths)
                    else:
                        added_file_paths[file_id] = item_paths

            elif "driveId" in change:
                # this is a drive change
                # dont consider trashed/removed events for processing
                if change.get("removed", False):
                    # remove item from cache
                    if self.remove_item_from_cache(change["driveId"]):
                        if self.show_cache_logs and "name" in change.get("drive", {}):
                            drive_name = change["drive"]["name"]
                            logger.info("Removed drive '%s' from cache: %s", change["driveId"], drive_name)

                        self._do_callback("drive_removed", change)

                    removes += 1
                    continue

                if "drive" in change and "id" in change["drive"] and "name" in change["drive"]:
                    # we always want to add changes to the cache so renames etc can be reflected inside the cache
                    if change["drive"]["id"] not in self.cache:
                        self._do_callback("drive_added", change)

                    self.add_item_to_cache(change["drive"]["id"], change["drive"]["name"], [], None)
                    continue

        # always dump the cache after running changes
        self.cache.commit()

        # display logging
        processed_paths = [
            ["Added", added_file_paths],
            ["Unwanted", unwanted_file_paths],
            ["Ignored", ignored_file_paths],
            ["Renamed", renamed_file_paths],
            ["Moved", moved_file_paths],
        ]
        for x in processed_paths:
            logger.debug("%s: %s", x[0], x[1])

        stats = [f"{len(x[1]):d} {x[0].lower()}" for x in processed_paths]
        logger.debug(" / ".join(stats))

        # call further callbacks
        self._do_callback("items_added", added_file_paths)
        self._do_callback("items_unwanted", unwanted_file_paths)
        self._do_callback("items_ignored", ignored_file_paths)

    def _do_callback(self, callback_type, callback_data):
        if callback_type in self.callbacks and callback_data:
            self.callbacks[callback_type](callback_data)

    @staticmethod
    def _list_matches(list_master, list_check):
        try:
            for item in list_master:
                if item not in list_check:
                    return False
            return True
        except Exception:
            logger.exception("Exception checking if lists match: ")
        return False
