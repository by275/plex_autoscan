import logging
import os
import time
from datetime import datetime
from typing import Tuple

import peewee as pw
from peewee import fn
from playhouse.migrate import SqliteMigrator, migrate

logger = logging.getLogger("DB")


class BaseModel(pw.Model):
    class Meta:
        database = pw.Proxy()
        legacy_table_names = False

    @classmethod
    def configure_proxy(cls, database: pw.Database):
        cls._meta.database.initialize(database)


class ScanItem(BaseModel):
    path = pw.CharField(max_length=256, unique=True, null=False)
    request_from = pw.CharField(max_length=64, null=False)
    section_id = pw.IntegerField(null=False)
    event_type = pw.CharField(max_length=64, null=False)
    created_at = pw.DateTimeField(default=datetime.now)

    @classmethod
    def init(cls, path: str) -> None:
        if path is None:
            path = ":memory:"
            logger.warning(
                "You are using an in-memory database as Autoscan queue. Consider using a file-based one by specifying `--queuefile` arg in CLI."
            )
            database = pw.SqliteDatabase(path, thread_safe=False, check_same_thread=False)
        else:
            database = pw.SqliteDatabase(path)
        ScanItem.migrate_from_legacy_to_v1(database)
        cls.bind(database)
        if not os.path.exists(path) or not cls.table_exists():
            database.create_tables([cls])
            logger.info("Created Autoscan database tables.")
        if database.is_closed():
            database.connect()

    @classmethod
    def get_or_add(cls, **kwargs) -> Tuple[bool, pw.Model]:
        """add item if its scan path does not exist in db"""
        file_path = kwargs.get("path")
        dir_path = os.path.dirname(file_path) if "." in file_path else file_path
        query = cls.select().where(fn.LOWER(cls.path).contains(dir_path.lower()))

        try:
            return False, query.get()
        except cls.DoesNotExist:
            try:
                with cls._meta.database.atomic():
                    return True, cls.create(**kwargs)
            except pw.IntegrityError as exc:
                try:
                    return False, query.get()
                except cls.DoesNotExist:
                    raise exc from exc
        except Exception:
            logger.exception("Exception getting/adding '%s' from/to database:", file_path)
        return False, None

    @classmethod
    def delete_by_path(cls, path: str, loglevel: int = logging.INFO) -> bool:
        try:
            cls.delete().where(cls.path == path).execute()
            logger.log(loglevel, "Removed '%s' from Autoscan database.", path)
            time.sleep(1)
            return True
        except Exception:
            logger.exception("Exception deleting '%s' from Autoscan database:", path)
            return False

    @classmethod
    def count(cls) -> int:
        try:
            return cls.select().count()
        except Exception:
            logger.exception("Exception retrieving queued count:")
            return 0

    @staticmethod
    def migrate_from_legacy_to_v1(database: pw.SqliteDatabase) -> None:
        migrator = SqliteMigrator(database)
        try:
            with database.atomic():
                migrate(
                    migrator.rename_column("queueitemmodel", "scan_for", "request_from"),
                    migrator.rename_column("queueitemmodel", "scan_type", "event_type"),
                    migrator.rename_column("queueitemmodel", "scan_section", "section_id"),
                    migrator.rename_column("queueitemmodel", "scan_path", "path"),
                    migrator.add_column("queueitemmodel", "created_at", pw.DateTimeField(default=datetime.now)),
                    migrator.rename_table("queueitemmodel", "scan_item"),
                )
            logger.info("Migrated Autoscan database from legacy to v1.")
        except Exception:
            pass
