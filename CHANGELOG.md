# Changelog

Tracking changes in Plex Autoscan between versions. For a complete view of all the
releases, visit GitHub:

<https://github.com/by275/plex_autoscan/releases>

## master

[View commits](https://github.com/by275/plex_autoscan/compare/v0.1.0...master)

## v0.1.0

### Important Changes

* Drop support for Python 2.7. (required Python 3.8+)
* Module implementation.
* Rewrite drive.py (formarly google.py) using google-api-python-client.
  * Use client secrets file for authorization.
  * Support service account file.

### Added

* Better handling of assets and extras using `PLEX_ASSET_EXTENSIONS` and `PLEX_EXTRA_DIRS` in `config.json`.
* Integrated SMI2SRT for Korean users.
* Add support for processing scan requests from Watcher.
* Respect `.plexignore` files when `start_scan()`.
* Add support for installation with pip.

### Removed

* Drop support for connection with *-arrs.
* Removed webui for manual scan.
  * Deprecate `SERVER_ALLOW_MANUAL_SCAN` in `config.json`.
  * Allow HTTP POST request only.

### Fixed/Improved

* Compact logging format.
* Reject changes from Google drives having common parent.
* Use `vfs/forget` to clear Rclone dir cache instead of `cahce/expire`.
* Refactor db.py to support peewee 3+.

[View commits](https://github.com/by275/plex_autoscan/compare/4e31fb19d81ca9d7ff0fc2f362f9accfff979bc4...v0.1.0)
