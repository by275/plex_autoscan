
# Configuration Guide

_Note: Changes to config file require a restart of the Plex Autoscan._

## Example

[config.default.json](config.default.json)

## Basics

```json
"USE_SUDO": true
```

`USE_SUDO` - This option is typically used in conjunction with `PLEX_USER` (e.g. `sudo -u plex`). Default is `true`.

- The user that runs Plex Autoscan needs to be able to sudo without a password, otherwise it cannot execute the `PLEX_SCANNER` command as `plex`. If the user cannot sudo without password, set this option to `false`.
- If the user that runs Plex Autoscan is able to run the `PLEX_SCANNER` command without sudo or is installed with the same user account (e.g. `plex`), you can set this to `false`.

## Docker

Docker specific options.

_Note: Some of the Docker examples used below are based on the image by [plexinc/pms-docker](https://hub.docker.com/r/plexinc/pms-docker/), with `/config/` in the container path mapped to `/opt/plex/` on the host. Obvious differences are mentioned between PlexInc and LSIO images._

```json
"USE_DOCKER": false,
"DOCKER_NAME": "plex",
```

`USE_DOCKER` - Set to `true` when Plex is in a Docker container. Default is `false`.

`DOCKER_NAME` - Name of the Plex docker container. Default is `"plex"`.

## Plex Media Server

Plex Media Server options.

### Plex Basics

```json
"PLEX_USER": "plex",
"PLEX_TOKEN": "",
"PLEX_LOCAL_URL": "http://localhost:32400",
"PLEX_CHECK_BEFORE_SCAN": false,
"PLEX_WAIT_FOR_EXTERNAL_SCANNERS": true,
"PLEX_ANALYZE_TYPE": "basic",
"PLEX_ANALYZE_DIRECTORY": true,
"PLEX_FIX_MISMATCHED": false,
"PLEX_FIX_MISMATCHED_LANG": "en",
```

`PLEX_USER` - User account that Plex runs as. This only gets used when either `USE_SUDO` or `USE_DOCKER` is set to `true`. Default is `"plex"`.

- Native Install: User account (on the host) that Plex runs as.
- Docker Install: User account within the container. Depends on the Docker image being used.
  - [plexinc/pms-docker](https://github.com/plexinc/pms-docker): `"plex"`
  - [linuxserver/plex](https://github.com/linuxserver/docker-plex): `"abc"`

`PLEX_TOKEN` - [Plex Access Token](https://support.plex.tv/hc/en-us/articles/204059436-Finding-an-authentication-token-X-Plex-Token). This is used for checking Plex's status, emptying trash, or analyzing media.

`PLEX_LOCAL_URL` - URL of the Plex Media Server. Can be localhost or http/https address. For example,

- `"http://localhost:32400"` (native install; docker with port 32400 exposed)
- `"https://plex.domain.com"` (custom domain with reverse proxy enabled)

`PLEX_CHECK_BEFORE_SCAN` - When set to `true`, check and wait for Plex to respond before processing a scan request. Default is `false`.

`PLEX_WAIT_FOR_EXTERNAL_SCANNERS` - When set to `true`, wait for other Plex Media Scanner processes to finish, before launching a new one. Default is `true`.

- For hosts running a single Plex Docker instance, this can be left as `true`.
- For multiple Plex Docker instances on a host, set this as `false`.

`PLEX_ANALYZE_TYPE` - How Plex will analyze the media files that are scanned. Options are `off`, `basic`, `deep`, `loudness`. `off` will disable analyzing. Default is `basic`.

> _Changed in v0.2.0_: The `loudness` option is new.

`PLEX_ANALYZE_DIRECTORY` - When set to `true`, Plex will analyze all the media files in the parent folder (e.g. movie folder, season folder) vs just the newly added file. Default is `true`.

`PLEX_FIX_MISMATCHED` - When set to `true`, Plex Autoscan will attempt to fix an incorrectly matched item in Plex. Default is `false`.

> _Deprecated since v0.2.0_

- Plex Autoscan will compare the TVDBID/TMDBID/IMDBID sent by Sonarr/Radarr with what Plex has matched with, and if this match is incorrect, it will autocorrect the match on the item (movie file or TV episode). If the incorrect match is a duplicate entry in Plex, it will auto split the original entry before correcting the match on the new item.
- This only works when 1) requests come from Sonarr/Radarr, 2) season folders are being used, and 3) all movies and TV shows have their own unique paths.

`PLEX_FIX_MISMATCHED_LANG` - What language to use for TheTVDB agent in Plex. Default is `"en"`.

> _Deprecated since v0.2.0_

### Plex File Locations

_Note: Verify the settings below by running the Plex Section IDs command._

```json
"PLEX_LD_LIBRARY_PATH": "/usr/lib/plexmediaserver/lib",
"PLEX_SCANNER": "/usr/lib/plexmediaserver/Plex\\ Media\\ Scanner",
"PLEX_SUPPORT_DIR": "/var/lib/plexmediaserver/Library/Application\\ Support",
"PLEX_DATABASE_PATH": "/var/lib/plexmediaserver/Library/Application Support/Plex Media Server/Plug-in Support/Databases/com.plexapp.plugins.library.db",
```

`PLEX_LD_LIBRARY_PATH`

- Native Install: `"/usr/lib/plexmediaserver/lib"`
- Docker Install: Path within the container. `"/usr/lib/plexmediaserver/lib"`

`PLEX_SCANNER` - Location of Plex Media Scanner binary.

- Native Install: `"/usr/lib/plexmediaserver/Plex\\ Media\\ Scanner"`
- Docker Install: Path within the container. `"/usr/lib/plexmediaserver/Plex\\ Media\\ Scanner"`

`PLEX_SUPPORT_DIR` - Location of Plex "Application Support" path.

- Native Install: `"/var/lib/plexmediaserver/Library/Application\\ Support"`
- Docker Install: Path within the container. `"/config/Library/Application\\ Support"`

`PLEX_DATABASE_PATH` - Location of Plex library database.

- Native Install: `"/var/lib/plexmediaserver/Library/Application Support/Plex Media Server/Plug-in Support/Databases/com.plexapp.plugins.library.db"`
- Docker Install: If Plex Autoscan is running directly on the host, this will be the path on the host. If Plex Autoscan is running inside a Plex container, this will be a path within the container.

### Plex Emptying Trash

When media is upgraded by Sonarr/Radarr/Lidarr, the previous files are then deleted. When Plex gets the scan request after the upgrade, the new media is added in to the library, but the previous media files would still be listed there but labeled as "unavailable".

To remedy this, a trash emptying command needs to be sent to Plex to get rid of these missing files from the library. The options below enable that to happen.

```json
"PLEX_EMPTY_TRASH": false,
"PLEX_EMPTY_TRASH_CONTROL_FILES": [
  "/mnt/unionfs/mounted.bin"
],
"PLEX_EMPTY_TRASH_MAX_FILES": 100,
"PLEX_EMPTY_TRASH_ZERO_DELETED": false,
```

`PLEX_EMPTY_TRASH` - When set to `true`, empty trash of a section after a scan.

`PLEX_EMPTY_TRASH_CONTROL_FILES` - Only empty trash when this file exists. Useful when media files, located elsewhere, is mounted on the Plex Server host. Can be left blank if not needed.

`PLEX_EMPTY_TRASH_MAX_FILES` - The maximum amount of missing files to remove from Plex at one emptying trash request. If there are more missing files than the number listed, the emptying trash request is aborted. This is particularly useful when externally mounted media temporarily dismounts and a ton of files go "missing" in Plex. Default is `100`.

`PLEX_EMPTY_TRASH_ZERO_DELETED` - When set to `true`, Plex Autoscan will always empty the trash on the scanned section, even if there are 0 missing files. If `false`, trash will only be emptied when the database returns more than 0 deleted items. Default is `false`.

### Plex Assets and Extras

> _New in v0.1.0_

```json
"PLEX_ASSET_EXTENSIONS": [
  "smi",
  "srt",
  "idx",
  "sub",
  "ass",
  "ssa",
  "vtt"
],
"PLEX_EXTRA_DIRS": [
  "Behind The Scenes",
  "Deleted Scenes",
  "Featurettes",
  "Interviews",
  "Scenes",
  "Shorts",
  "Trailers",
  "Other"
],
```

Let us define assets as files with extensions listed in `PLEX_ASSET_EXTENSIONS`, which is mostly subtitle for now. Also we will call extras as files in one of folders with name specified in `PLEX_EXTRA_DIRS`. Please find more information for extras:

- <https://support.plex.tv/articles/local-files-for-trailers-and-extras/>
- <https://support.plex.tv/articles/local-files-for-tv-show-trailers-and-extras/>

In this fork, scan requests for extras will be upgraded to their grand parent so that plex can see the whole changes occurred in shows(or seasons) or movies with a correct hieararchy.

Assets will be refreshed only if

- they are **NOT** in extras folder.
- they have parent items (recognized by filenames) already registered so that we can find metadata_id in plex db.
- they are not registered previously.

Assets and extras will no more be analyzed.

## Plex Autoscan Server

### Server Basics

```json
"SERVER_IP": "0.0.0.0",
"SERVER_PASS": "9c4b81fe234e4d6eb9011cefe514d915",
"SERVER_PORT": 3467,
"SERVER_SCAN_DELAY": 180,
"SERVER_USE_SQLITE": true
```

`SERVER_IP` - Server IP that Plex Autoscan will listen on. Default is `0.0.0.0`.

- `0.0.0.0` - Allow remote access (e.g. Sonarr/Radarr/Lidarr running on another/remote server).
- `127.0.0.1` - Local access only.

`SERVER_PORT` - Port that Plex Autoscan will listen on. Default is `3467`.

`SERVER_PASS` - Plex Autoscan password. Used to authenticate requests from Sonarr/Radarr/Lidarr. Default is a random 32 character string generated during config build.

- Your webhook URL will look like: `http://ipaddress:3468/server_pass` (or `http://localhost:3468/server_pass` if local only).

`SERVER_SCAN_DELAY` - How long (in seconds) Plex Autoscan will wait before sending a scan request to Plex.

- This is useful, for example, when you want Plex Autoscan to wait for more episodes of the same TV show to come in before scanning the season folder, resulting in less work for Plex to do by not scanning the same folder multiple times. This works especially well with `SERVER_USE_SQLITE` enabled.

`SERVER_USE_SQLITE` - Option to enable a database to store queue requests. Default is `true`.

> _Deprecated since v0.2.0_: This is always enabled. Explicitly set `--queuefile` arg in CLI to use a persistent queue. Otherwise, it will use an in-memory database.

- The benefits to using this are:

  1. Queue will be restored on Plex Autoscan restart, and

  2. Multiple requests to the same folder can be merged into a single folder scan.

- Example log:

  ```shell
  Already processing '/data/TV/TV-Anime/Persona 5 the Animation/Season 1/Persona 5 the Animation - s01e01 - I am thou, thou art I.mkv' from same folder, aborting adding an extra scan request to the queue.
  Scan request from Sonarr for '/data/TV/TV-Anime/Persona 5 the Animation/Season 1/Persona 5 the Animation - s01e01 - I am thou, thou art I.mkv', sleeping for 180 seconds...
  ```

  The `180` seconds in the example above are from the `SERVER_SCAN_DELAY`, if any more requests come in during this time, the scan request will be delayed by another `180` seconds.

### Server Path Mappings

List of paths that will be remapped before being scanned by Plex.

This is particularly useful when receiving scan requests, from a remote Sonarr/Radarr/Lidarr installation, that has different paths for the media.

- Native Install

  Format:

  ```json
  "SERVER_PATH_MAPPINGS": {
      "/path/on/local/plex/host/": [  <--- Plex Library path
          "/path/on/sonarr/host/"  <--- Sonarr root path
      ]
  },
  ```

  _Note: This format is used regardless of whether Sonarr is on the same server as Plex or not._

  Example:

  ```json
  "SERVER_PATH_MAPPINGS": {
      "/mnt/unionfs/": [
          "/home/seed/media/fused/"
      ]
  },
  ```

- Docker Install

  Format:

  ```json
  "SERVER_PATH_MAPPINGS": {
      "/path/in/plex/container/": [  <--- Plex Library path
          "/path/from/sonarr/container/"  <--- Sonarr root path
      ]
  },
  ```

  Example:

  ```json
  "SERVER_PATH_MAPPINGS": {
    "/data/Movies/": [
      "/movies/"
    ]
  }
  ```

  If the filepath that was reported to Plex Autoscan by Radarr was `/home/seed/media/fused/Movies/Die Hard/Die Hard.mkv` then the path that would be scanned by Plex would be `/mnt/unionfs/Movies/Die Hard/Die Hard.mkv`.

You can also have more than one folder paths pointing to a single one.

Example:

```json
"SERVER_PATH_MAPPINGS": {
  "/data/Movies/": [
    "/media/movies/",
    "/local/movies/"
  ]
}
```

### Server File Checks

After a `SERVER_SCAN_DELAY`, Plex Autoscan will check to see if file exists before sending a scan request to Plex.

```json
"SERVER_MAX_FILE_CHECKS": 10,
"SERVER_FILE_CHECK_DELAY": 60,
"SERVER_SCAN_FOLDER_ON_FILE_EXISTS_EXHAUSTION": false,
```

`SERVER_MAX_FILE_CHECKS` - The number specifies how many times this check will occur, before giving up. If set to `0`, this check will not occur, and Plex Autoscan will simply send the scan request after the `SERVER_SCAN_DELAY`. Default is `10`.

`SERVER_FILE_CHECK_DELAY` - Delay in seconds between two file checks. Default is `60`.

`SERVER_SCAN_FOLDER_ON_FILE_EXISTS_EXHAUSTION` - Plex Autoscan will scan the media folder when the file exist checks (as set above) are exhausted. Default is `false`.

### Server File Exists Path Mappings

List of paths that will be remapped before file exist checks are done.

This is particularly useful when using Docker, since the folder being scanned by the Plex container, may be different to the path on the host system running Plex Autoscan.

Format:

```json
"SERVER_FILE_EXIST_PATH_MAPPINGS": {
    "/actual/path/on/host/": [
        "/path/from/plex/container/"
    ]
},
```

Example:

```json
"SERVER_FILE_EXIST_PATH_MAPPINGS": {
    "/mnt/unionfs/media/": [
        "/data/"
    ]
},
```

You can leave this empty if it is not required:

```json
"SERVER_FILE_EXIST_PATH_MAPPINGS": {
},
```

### Server Manual Scan

To send a manual scan, initiate a request via HTTP (e.g. curl):

```shell
curl -X POST -d "eventType=Manual&filepath=/mnt/unionfs/Media/Movies/Shut In (2016)/Shut In (2016) - Bluray-1080p.x264.DTS-GECKOS.mkv" http://ipaddress:3468/0c1fa3c9867e48b1bb3aa055cb86`
```

It is safer to escape `filepath` using `--data-urlencode`:

```shell
curl -X POST -d "eventType=Manual" --data-urlencode "filepath=/mnt/unionfs/Media/Movies/Shut In (2016)/Shut In (2016) - Bluray-1080p.x264.DTS-GECKOS.mkv" http://ipaddress:3468/0c1fa3c9867e48b1bb3aa055cb86`
```

### Misc

```json
"RUN_COMMAND_BEFORE_SCAN": "",
"RUN_COMMAND_AFTER_SCAN": "",
"SERVER_ALLOW_MANUAL_SCAN": false,
"SERVER_IGNORE_LIST": [
  "/.grab/",
  ".DS_Store",
  "Thumbs.db"
],
"SERVER_SCAN_PRIORITIES": {
  "1": [
    "/Movies/"
  ],
  "2": [
    "/TV/"
  ]
},
"USE_SMI2SRT": false,
```

`RUN_COMMAND_BEFORE_SCAN` - If a command is supplied, it is executed before the Plex Media Scanner command.

`RUN_COMMAND_AFTER_SCAN` - If a command is supplied, it is executed after the Plex Media Scanner, Empty Trash and Analyze commands.

`SERVER_ALLOW_MANUAL_SCAN` - When enabled, allows GET requests to the webhook URL to allow manual scans on a specific filepath. Default is `false`.

> _Deprecated since v0.1.0_: WebUI is also removed. Instead, use POST requests which is always enabled.

`SERVER_IGNORE_LIST` - List of paths or filenames to ignore when a requests is sent to Plex Autoscan manually (see above). Case sensitive.

- Example:

  ```bash
  curl -d "eventType=Manual&filepath=/mnt/unionfs/Media/Movies/Thumbs.db" http://ipaddress:3468/0c1fa3c9867e48b1bb3aa055cb86
  ```
  
  This would be ignored if `Thumbs.db` was in the ignore list.

`SERVER_SCAN_PRIORITIES` - What paths are picked first when multiple scan requests are being processed.

- Format:

  ```json
  "SERVER_SCAN_PRIORITIES": {
    "PRIORITY LEVEL#": [
      "/path/to/library/in/Plex"
    ],
  },
  ```

`USE_SMI2SRT` - Integrated SMI2SRT for Korean users. Set `true` to automatically convert `.smi` to `.ko.srt`. It will try to convert all .smi files in which folder a scan request has occurred, but not recursively. Default is `false`.

> _New in v0.1.0_

## Google Drive Monitoring

As mentioned earlier, Plex Autoscan can monitor Google Drive for changes. It does this by utilizing a proactive cache (vs building a cache from start to end).

Once a change is detected, the file will be checked against the Plex database to make sure this is not already there. If this match comes back negative, a scan request for the parent folder is added into the process queue, and if that parent folder is already in the process queue, the duplicate request will be ignored.

```json
"GOOGLE": {
  "ENABLED": false,
  "CLIENT_ID": "",
  "CLIENT_SECRET": "",
  "ALLOWED": {
    "FILE_PATHS": [],
    "FILE_EXTENSIONS": true,
    "FILE_EXTENSIONS_LIST": [
      "webm","mkv","flv","vob","ogv","ogg","drc","gif",
      "gifv","mng","avi","mov","qt","wmv","yuv","rm",
      "rmvb","asf","amv","mp4","m4p","m4v","mpg","mp2",
      "mpeg","mpe","mpv","m2v","m4v","svi","3gp","3g2",
      "mxf","roq","nsv","f4v","f4p","f4a","f4b","mp3",
      "flac","ts"
    ],
    "MIME_TYPES": true,
    "MIME_TYPES_LIST": [
      "video"
    ]
  },
  "TEAMDRIVE": false,
  "TEAMDRIVES": [],
  "DRIVES": {
    "MY_DRIVE": true,
    "SHARED_DRIVES": false,
    "SHARED_DRIVES_LIST": []
  },
  "POLL_INTERVAL": 60,
  "SERVICE_ACCOUNT_FILE": "",
  "SHOW_CACHE_LOGS": false
},
"RCLONE": {
  "BINARY": "/usr/bin/rclone",
  "CONFIG": "/home/seed/.config/rclone/rclone.conf",
  "CRYPT_MAPPINGS": {
    "My Drive/encrypt/": [
      "gcrypt:"
    ]
  }
},
```

`ENABLED` - Enable or Disable Google Drive Monitoring. Requires one time authorization, see below.

`CLIENT_ID` - Google Drive API Client ID.

> _Deprecated since v0.1.0_

`CLIENT_SECRET` - Google Drive API Client Secret.

> _Deprecated since v0.1.0_

`ALLOWED` - Specify what paths, extensions, and mime types to whitelist.

- `FILE_PATHS` - What paths to monitor.

  - Example ("My Drive" only):

    ```json
    "FILE_PATHS": [
      "My Drive/Media/Movies/",
      "My Drive/Media/TV/"
    ],
    ```

  - Example ("My Drive" with Shareddrives):

    ```json
    "FILE_PATHS": [
      "My Drive/Media/Movies/",
      "My Drive/Media/TV/",
      "Shared_Movies/Movies/",
      "Shared_Movies/4K_Movies/",
      "Shared_TV/TV/"
    ],
    ```

- `FILE_EXTENSIONS` - To filter files based on their file extensions. Default is `true`.

- `FILE_EXTENSIONS_LIST` - What file extensions to monitor. Requires `FILE_EXTENSIONS` to be enabled.

  - Example:

    ```json
    "FILE_EXTENSIONS_LIST": [
      "webm","mkv","flv","vob","ogv","ogg","drc","gif",
      "gifv","mng","avi","mov","qt","wmv","yuv","rm",
      "rmvb","asf","amv","mp4","m4p","m4v","mpg","mp2",
      "mpeg","mpe","mpv","m2v","m4v","svi","3gp","3g2",
      "mxf","roq","nsv","f4v","f4p","f4a","f4b","mp3",
      "flac","ts"
    ],
    ```

- `MIME_TYPES` - To filter files based on their mime types. Default is `true`.

- `MIME_TYPES_LIST` - What file extensions to monitor. Requires `MIME_TYPES` to be enabled.

  - Example:

    ```json
    "MIME_TYPES_LIST": [
      "video"
    ]
    ```

`TEAMDRIVE` - Enable or Disable monitoring of changes inside Team Drives. Default is `false`.

> _Deprecated since v0.1.0_: Use `DRIVES.SHARED_DRIVES` instead

`TEAMDRIVES` - What Team Drives to monitor. Requires `TEAMDRIVE` to be enabled.

> _Deprecated since v0.1.0_: Use `DRIVES.SHARED_DRIVES_LIST` instead

`DRIVES` - to selectively accept changes from drives associated with an authorized user.

> _New in v0.1.0_

- `MY_DRIVE` - Enable or Disable monitoring changes from My Drive. Default is `true`.

- `SHARED_DRIVES` - Enable or Disable monitoring changes from Shared Drives. Default is `false`.

- `SHARED_DRIVES_LIST` - What Shareddrives to monitor. Requires `SHARED_DRIVES` to be enabled.

  - Format:

    ```json
    "SHARED_DRIVES_LIST": [
      "NAME_OF_SHARED_DRIVE_1",
      "NAME_OF_SHARED_DRIVE_2"
    ],
    ```

  - Example:

    For 2 Shareddrives named `Shared_Movies` and `Shared_TV`.

    ```json
    "SHARED_DRIVES_LIST": [
      "Shared_Movies",
      "Shared_TV"
    ],
    ```

- _Note: This is just a list of Shareddrives, not the specific paths within it._

`POLL_INTERVAL` - How often (in seconds) to check for Google Drive changes.

`SERVICE_ACCOUNT_FILE` - Location of 'service account file' or its contents (JSON formatted string). This will take priority over OAuth 2.0 for authorization.

> _New in v0.1.0_

`SHOW_CACHE_LOGS` - Show cache messages from Google Drive. Default is `false`.

`BINARY` - Path to Rclone binary if not in standard location.

`CONFIG` - Path to Rclone config file containing Rclone Crypt remote configuration. Required for Rclone Crypt decoder.

`CRYPT_MAPPINGS` - Mapping of path (root or subfolder) of Google Drive crypt (`My Drive/` or `Shared Drive Name/`) to Rclone mount name. These values enable Rclone crypt decoder.

- Example: Crypt folder on drive called `encrypt` mapped to Rclone crypt mount called `grypt:`.

  ```json
  "CRYPT_MAPPINGS": {
    "My Drive/encrypt/": [
      "gcrypt:"
    ]
  },
  ```

- Example: Crypt Shareddrive named `Shared_TV` mapped to Rclone crypt mount called `Shared_TV_crypt:`.

  ```json
  "CRYPT_MAPPINGS": {
    "Shared_TV/": [
      "Shared_TV_crypt:"
    ]
  },
  ```

---

To set this up:

1. Edit `config.json` file to enable the Google Drive monitoring.

   ```json
   "ENABLED": true,
   ```

1. Next, download 'client secrets file' from your api console and use its file location while proceeding

   ```shell
   python3 -m autoscan authorize
   ```

1. When authorization is successful, auth info will be stored in `cache.db` file.

1. You will now need to add in your Google Drive paths into `SERVER_PATH_MAPPINGS`. This will tell Plex Autoscan to map Google Drive paths to their local counter part.

    _Note 1: The Google Drive path does not start with a forward slash (`/`). Paths in My Drive will start with just `My Drive/`. and paths in a Shared drive will start with `shared_drive_name/`._

    _Note 2: Foreign users of Google Drive might not see `My Drive` listed on their Google Drive. They can try using the `My Drive/...` path or see what the log shows and match it up to that. One example is `Mon\u00A0Drive/` for French users._

   i. Native install

   - Format:

     ```json
     "SERVER_PATH_MAPPINGS": {
         "/path/on/local/host": [
             "/path/on/sonarr/host/",
             "path/on/google/drive/"
         ]
     },
     ```

   - For example, if you store your files under My Drive's Media folder (`My Drive/Media/...`), the server path mappings will look like this:

     ```json
     "SERVER_PATH_MAPPINGS": {
       "/mnt/unionfs/Media/Movies/": [
         "/home/seed/media/fused/"
         "My Drive/Media/Movies/"
       ],
     },
     ```

   - For example, if you store your files under a Google Shareddrive called "shared_movies" and within a Media folder (`shared_movies/Media/...`), the server path mappings will look like this:

     ```json
     "SERVER_PATH_MAPPINGS": {
       "/mnt/unionfs/Media/Movies/": [
         "/home/seed/media/fused/"
         "shared_movies/Media/Movies/"
       ],
     },
     ```

   ii. Docker install

   - Format:

     ```json
     "SERVER_PATH_MAPPINGS": {
         "/path/in/plex/container/": [
            "/path/from/sonarr/container/",
            "path/on/google/drive/"
         ]
     },
     ```

   - For example, if you store your files under Google Drive's My Drive Media folder (`My Drive/Media/...`) AND run Plex in a docker container, the server path mappings will look like this:

     ```json
     "SERVER_PATH_MAPPINGS": {
       "/data/Movies/": [
         "/movies/",
         "My Drive/Media/Movies/"
       ]
     }
     ```

   - For example, if you store your files under Google Drive's Shareddrive called "shared_movies" and within a Media folder (`shared_movies/Media/...`) AND run Plex in a docker container, the server path mappings will look like this:

      ```json
      "SERVER_PATH_MAPPINGS": {
        "/data/Movies/": [
          "/movies/",
          "shared_movies/Media/Movies/"
        ]
      }
      ```

1. Rclone Crypt Support - If your mounted Google Drive is encrypted using Rclone Crypt, Plex Autoscan can also decode the filenames for processing changes. This includes My/Shared drives entirely encrypted or just a subfolder i.e. in the below example only the encrypt subfolder is encrypted.

   1. Configure Rclone values. Example below:

      ```json
      "RCLONE": {
        "BINARY": "/usr/bin/rclone",
        "CONFIG": "/home/seed/.config/rclone/rclone.conf",
        "CRYPT_MAPPINGS": {
          "My Drive/encrypt/": [
             "gcrypt:"
          ]
        }
      },
      ```

   1. Disable mime type checking in your config file. This is not currently supported with Rclone Crypt Decoding. Rclone crypt encodes file paths and encrypts files causing Google Drive to reports all files in a crypt as '"mimeType": "application/octet-stream"'.

      `"MIME_TYPES": false`

   1. Add in your Rclone crypt paths on Google Drive into `SERVER_PATH_MAPPINGS`. This will tell Plex Autoscan to map Rclone crypt paths on Google Drive to their local counter part.

      ```json
      "SERVER_PATH_MAPPINGS": {
        "/home/seed/media/": [
        "My Drive/encrypt/"
        ]
      },
      ```

1. Google Drive Monitoring is now setup.

---

## Rclone Remote Control

_Note: This if for Rclone mounts using the "cache" or "vfs" backends._

When `RC_CACHE_REFRESH` is enabled, if a file exist check fails (as set in `SERVER_FILE_EXIST_PATH_MAPPINGS`), Plex Autoscan will keep sending an Rclone cache/expire or vfs/refresh requests, for that file's parent folder, until the file check succeeds.

For example, if the file `/mnt/unionfs/Media/A Good Movie (2000)/A Good Movie.mkv` doesn't exist locally, then a clear cache request will be sent to the remote for `A Good Movie (2000)` folder, on the Rclone remote. But if a file exist checks fails again, it will move to the parent folder and try to clear that (eg `Media`), and keep doing this until a file check exists comes back positive or checks count reaches `SERVER_MAX_FILE_CHECKS`.

```json
"RCLONE": {
  "RC_CACHE_REFRESH": {
    "ENABLED": false,
    "FILE_EXISTS_TO_REMOTE_MAPPINGS": {
      "Media/": [
        "/mnt/unionfs/Media/"
      ]
    },
    "RC_URL": "http://localhost:5572"
  }
},
```

`ENABLED` - enable or disable cache clearing.

`FILE_EXISTS_TO_REMOTE_MAPPINGS` - maps local mount path to Rclone remote one. Used during file exists checks.

- Format:

  ```json
  "FILE_EXISTS_TO_REMOTE_MAPPINGS": {
    "folder_on_rclone_remote/": [
      "/path/to/locally/mounted/folder/"
    ]
  },
  ```

`RC_URL` - URL and Port Rclone RC is set to.
