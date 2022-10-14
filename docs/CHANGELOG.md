# Changelog

Tracking changes in Plex Autoscan between versions.

## master

[View commits](https://github.com/by275/plex_autoscan/compare/v0.2.0...master)

## v0.2.0

### Summary

#### API instead of CLI

As of Plex Media Server v1.28.1,

```log
(Scanner) Mark ‘scan’ and ‘refresh’ CLI actions as deprecated (#13700)
```

and start printing

```log
The '--scan' operation is deprecated and will be removed in future versions of Plex Media Server.
```

whenever you perform a scan/refresh action.

In this version, we stop using CLI action for scan/refresh and use [plexapi](https://github.com/pkkid/python-plexapi) for everyone's convenience.

#### Database migration

Table name is changed from `queueitemmodel` to `scan_item`, which is a peewee's new standard. Fields are changes as follows:

|legacy|v1||
|------|---|---|
|scan_path|path||
|scan_for|request_from||
|scan_section|section_id||
|scan_type|event_type||
||created_at|new field|

Variables across functions and threads are also renamed to match with above fields.

### Important Changes

* `scan` and `refresh` now use API instead of CLI. https://github.com/by275/plex_autoscan/pull/4
  * `analyze` still depends on Scanner binary.
* New dependencies: `plexapi` `tabulate[widechars]` https://github.com/by275/plex_autoscan/pull/4
* Queue DB migration (backward-incompatible). https://github.com/by275/plex_autoscan/pull/12
* Restrict `peewee>=3.8.0` [4424a5a](https://github.com/by275/plex_autoscan/commit/4424a5aeb98b30c71ff2df49f762a921fe1905bd)

### Added

* New option `loudness` to `PLEX_ANALYZE_TYPE` in `config.json`. https://github.com/by275/plex_autoscan/pull/4
* Add *-arrs back. https://github.com/by275/plex_autoscan/pull/5
* Colour formatter to console log. https://github.com/by275/plex_autoscan/pull/13
  * Automatically detects shell type and enables colour schemes. [e4dcb9d](https://github.com/by275/plex_autoscan/commit/e4dcb9d7f0a5665a61716840c639e464a37b63b8)
* New API command `clear_drive_cache` for clearing drive cache with vacuum. https://github.com/by275/plex_autoscan/pull/14

### Removed

* Drop features related to `PLEX_FIX_MISMATCHED` and `PLEX_FIX_MISMATCHED_LANG`. https://github.com/by275/plex_autoscan/pull/4
* Deprecated `SERVER_USE_SQLITE`. https://github.com/by275/plex_autoscan/pull/12
  * The feature is always enabled. Explicitly set `--queuefile` arg in CLI to use a persistent queue. Otherwise, it will use an in-memory database.

### Fixed/Improved

* Generate better default `config.json` when PAS is installed in Plex docker. https://github.com/by275/plex_autoscan/pull/4
* Add support for fallback connection when obtaining plexapi instance. https://github.com/by275/plex_autoscan/pull/4
* Add checks for connection to PMS via plexapi on `start_server()`. https://github.com/by275/plex_autoscan/pull/4
* Add checks for existence of Plex DB file on `start_server()`. https://github.com/by275/plex_autoscan/pull/4
* Add checks for availability of Scanner binary on `start_server()`. https://github.com/by275/plex_autoscan/pull/4
* Fix/update `authorize` menu to work after OOB Oauth flow deprecation. https://github.com/by275/plex_autoscan/pull/4
* Fix entrypoint when installing PIP. https://github.com/by275/plex_autoscan/pull/4
* Improve shell-related operations with psutil and subprocess. https://github.com/by275/plex_autoscan/pull/4
* Implement retry features for getting PlexServer instance. https://github.com/by275/plex_autoscan/pull/6
* Recognize sdh/cc and forced keyword for subtitle naming convention while processing assets. [4b7a875](https://github.com/by275/plex_autoscan/commit/4b7a87505a63f0a3f5c12a832a668247f60e6028)
* Use proper ENV dirs when running scanner binary inside docker. https://github.com/by275/plex_autoscan/pull/9
* Refactor PlexDB-accessing functions. https://github.com/by275/plex_autoscan/pull/10
* A thread restoring queue on restart will not be initiated anymore if there's nothing to restore. https://github.com/by275/plex_autoscan/pull/12
* Initialize queue DB from main module for administration purpose. https://github.com/by275/plex_autoscan/pull/12

[View commits](https://github.com/by275/plex_autoscan/compare/v0.1.0...v0.2.0)

## v0.1.0

First release since [l3uddz's last commit](https://github.com/by275/plex_autoscan/tree/4e31fb19d81ca9d7ff0fc2f362f9accfff979bc4).

### Important Changes

* Drop support for Python 2.7 (requires Python 3.8 or higher).
* Module implementation.
* Rewrite drive.py (formerly google.py) using google-api-python-client.
  * Use 'client secrets file' for authorization.
  * Support 'service account file'.
* Updated dependencies: `peewee>=3`, `google-api-python-client`, `google-auth-httplib2`, `google-auth-oauthlib`

### Added

* New `PLEX_ASSET_EXTENSIONS` and `PLEX_EXTRA_DIRS` in `config.json` for better handling of assets and extras.
* Integrated SMI2SRT for Korean users.
* Add support for processing scan requests from Watcher.
* Respect `.plexignore` files when `start_scan()`.
* Add support for installation with PIP.

### Removed

* Drop support for connection with *-arrs. (Added back in v0.2.0)
* Removed WebUI for manual scan.
  * Deprecated `SERVER_ALLOW_MANUAL_SCAN` in `config.json`.
  * Use POST requests which is always enabled.

### Fixed/Improved

* Compact logging format.
* Reject changes from Google drives having common parent.
* Use `vfs/forget` to clear Rclone dir cache instead of `cahce/expire`.
* Refactor db.py to support peewee v3.

[View commits](https://github.com/by275/plex_autoscan/compare/4e31fb19d81ca9d7ff0fc2f362f9accfff979bc4...v0.1.0)
