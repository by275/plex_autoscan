"""
@package smi2srt
@brief this module is for convert .smi subtitle file into .srt subtitle
    (Request by Alfred Chae)

Started : 2011/08/08
license: GPL

@version: 1.0.0
@author: Moonchang Chae <mcchae@gmail.com>
"""
# Moonchang Chae님 파일 수정본
# hojel님의 demux 부분 가져옴 (https://github.com/hojel/SmiConvert.bundle)
# soju6jan님의 smi2srt를 기반으로 함
from __future__ import annotations

import codecs
import logging
import os
import re
import shutil
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import List, Union

try:
    from typing import Iterator
except ImportError:
    from collections.abc import Iterator

logger = logging.getLogger("SMI2SRT")


@dataclass(init=False)
class subItem:
    """subtitle items with time and text"""

    start_ms: int = None
    end_ms: int = None
    text_smi: str = None

    __start_tc: str = None
    __end_tc: str = None
    text_srt: str = None

    SYNC_PTNS = [
        re.compile(r"<sync\s+start\s*=-?\s*(\d+)?>(.*)$", re.I),
        re.compile(r"<sync\s+start\s*=\s*(\d+)?\send\s*=(\d+)>(.*)$", re.I),
        re.compile(r"<sync\s+Start\s*=\"?(\d+)?\"?>?(.*)$", re.I),  # <SYNC Start="100">, 마지막 > 태그 없는거
        re.compile(r"<sync\s+s\s*t\s*a\s*r\s*t\s*=\s*(\d+)?>(.*)$", re.I),  # <SYNC S tart=1562678
    ]
    SUB_PTNS = [
        (re.compile(r"\s+"), " "),  # remove new-line
        (re.compile(r"&[a-z]{2,5};"), ""),  # remove web string like "&nbsp"
        (re.compile(r"&nbsp"), ""),  # remove "&nbsp" not endswith ";"
        (re.compile(r"(<br>)+", re.I), "\n"),  # replace "<br>" with '\n'
    ]
    TAG_PTN = re.compile(r"</?([a-z]+)[^>]*>([^<>]*)", re.I)

    @property
    def start_tc(self) -> str:
        if self.__start_tc is None and self.start_ms is not None:
            self.__start_tc = subItem.ms2tc(self.start_ms)
        return self.__start_tc

    @property
    def end_tc(self) -> str:
        if self.__end_tc is None and self.end_ms is not None:
            self.__end_tc = subItem.ms2tc(self.end_ms)
        return self.__end_tc

    @classmethod
    def from_smi_sync(cls, sync: str) -> subItem:
        for ptn in cls.SYNC_PTNS:
            m = ptn.search(sync)
            if m:
                break
        if not m:
            raise Exception(f"Invalid format tag: {sync}")
        this = cls()
        this.start_ms = int(m.group(1) or 0)
        this.text_smi = m.group(2)
        return this

    @staticmethod
    def ms2tc(ms: Union[int, str]) -> str:
        """Returns subrip timecode from milliseconds.
        HH:MM:SS,MMM

        This function is assuming input is no smaller than 1000 * 60 * 60 * 24

        Parameters:
            ms (str,int): time duration in milliseconds.
        """
        r = datetime.utcfromtimestamp(int(ms) / 1000)
        f = r.strftime("%H:%M:%S,%f")
        return f[:-3]

    def text_smi2srt(self):
        if self.text_smi is None:
            return
        text_smi = self.text_smi
        # substitue
        for ptn, subto in subItem.SUB_PTNS:
            text_smi = ptn.sub(subto, text_smi)
        # find all tags
        fndx = text_smi.find("<")
        if fndx >= 0:
            contents = text_smi
            sb = text_smi[0:fndx]
            contents = contents[fndx:]
            while True:
                m = subItem.TAG_PTN.match(contents)
                if m is None:
                    break
                contents = contents[m.end(2) :]
                if m.group(1).lower() in ["font", "b", "i", "u"]:
                    sb += m.string[0 : m.start(2)]
                sb += m.group(2)
            text_smi = sb
        self.text_srt = text_smi.strip().strip("\n")

    def srtjoin(self, index: int) -> str:
        elements = [
            f"{index:d}",
            f"{self.start_tc} --> {self.end_tc}",
            self.text_srt,
            "",
        ]
        return os.linesep.join(elements)

    def __repr__(self):
        return f"{self.start_ms}:{self.end_ms}:<{self.text_smi}>"


def guess_encoding(file_path: Union[Path, str], max_lines: int = 100) -> str:
    """Predict a file's text encoding

    priority: cchardet > charset-normalizer > chardet > heading
    """
    try:
        from cchardet import UniversalDetector

        num_lines = 0
        with open(file_path, "rb") as fp, UniversalDetector() as dt:
            for line in fp:
                num_lines += 1
                dt.feed(line)
                if dt.done or num_lines > max_lines:
                    break
        if dt.done:
            logger.debug("encoding detected by cchardet: %s", dt.result)
            encoding = dt.result.get("encoding")
            if encoding is not None:
                return encoding
    except Exception as e:
        logger.debug("failed to detect encoding by cchardet: %s", e)

    try:
        from charset_normalizer import from_bytes

        num_lines = 0
        byte_str = b""
        with open(file_path, "rb") as fp:
            for line in fp:
                num_lines += 1
                byte_str += line
                if num_lines > max_lines:
                    break

        result = from_bytes(byte_str).best()
        if result is not None:
            logger.debug("encoding detected by charset-normalizer: %s", result.encoding)
            return result.encoding
    except Exception as e:
        logger.debug("failed to detect encoding by charset-normalizer: %s", e)

    try:
        from chardet.universaldetector import UniversalDetector

        num_lines = 0
        dt = UniversalDetector()
        with open(file_path, "rb") as fp:
            for line in fp:
                num_lines += 1
                dt.feed(line)
                if dt.done or num_lines > max_lines:
                    break
        dt.close()
        if dt.done:
            logger.debug("encoding detected by cchardet: %s", dt.result)
            encoding = dt.result.get("encoding")
            if encoding is not None:
                return encoding
    except Exception as e:
        logger.debug("failed to detect encoding by chardet: %s", e)

    result = None
    try:
        byte_str = b""
        with open(file_path, "rb") as fp:
            for line in fp:
                byte_str += line
                if len(byte_str) > 10:
                    break

        # If the data starts with BOM, we know it is UTF
        if byte_str.startswith(codecs.BOM_UTF8):
            # EF BB BF  UTF-8 with BOM
            result = "UTF-8-SIG"
        elif byte_str.startswith((codecs.BOM_UTF32_LE, codecs.BOM_UTF32_BE)):
            # FF FE 00 00  UTF-32, little-endian BOM
            # 00 00 FE FF  UTF-32, big-endian BOM
            result = "UTF-32"
        elif byte_str.startswith(b"\xFE\xFF\x00\x00"):
            # FE FF 00 00  UCS-4, unusual octet order BOM (3412)
            result = "X-ISO-10646-UCS-4-3412"
        elif byte_str.startswith(b"\x00\x00\xFF\xFE"):
            # 00 00 FF FE  UCS-4, unusual octet order BOM (2143)
            result = "X-ISO-10646-UCS-4-2143"
        elif byte_str.startswith((codecs.BOM_LE, codecs.BOM_BE)):
            # FF FE  UTF-16, little endian BOM
            # FE FF  UTF-16, big endian BOM
            result = "UTF-16"

        if result is not None:
            logger.debug("encoding detected by heading: %s", result)
    except Exception as e:
        logger.debug("failed to detect encoding by heading: %s", e)
    return result


class smiFile:
    # for demuxing
    CLASS_PTN = re.compile(r"<P Class=(\w+)>", re.I)
    CLOSETAG_PTN = re.compile(r"</(BODY|SAMI)>", re.I)

    # for parsing lines of sync tags
    BODY_PTN = re.compile(r"<BODY>(.*)(?:</BODY>)?", re.I | re.S)
    SYNC_PTN = re.compile(r"<SYNC", re.M | re.I)

    def __init__(self):
        self.path: Path = None
        self.__encoding: str = None  # guessed encoding
        self.text: str = None
        self.__langs: List[str] = None

    def __str__(self):
        return str(self.path)

    @property
    def encoding(self) -> str:
        if self.__encoding is None and self.path is not None:
            self.__encoding = guess_encoding(self.path)
        return self.__encoding

    @property
    def languages(self) -> List[str]:
        if self.__langs is None and self.text is not None:
            self.__langs = sorted(set(map(str.upper, smiFile.CLASS_PTN.findall(self.text))))
        return self.__langs

    @classmethod
    def from_path(cls, file_path: Union[Path, str]) -> smiFile:
        this = cls()
        this.path = Path(file_path)
        return this.load()

    def load(self, max_bytes: int = 10 * 1024**2) -> smiFile:
        if not self.path.is_file():
            raise FileNotFoundError(self.path)
        if self.path.stat().st_size > max_bytes:
            raise IOError(f"File too large: {self.path}")
        return self._load()

    def _load(self) -> smiFile:
        # open and read file
        guessed_encoding = self.encoding
        if guessed_encoding is None:
            candidates = ["cp949", "utf-8"]
        elif guessed_encoding.lower().startswith(("utf-8", "utf_8")):
            candidates = [guessed_encoding, "cp949"]
        elif guessed_encoding.lower().startswith(("uhc", "iso8859")):
            # uhc == cp949
            # decoding 오류가 있을 때 iso8859_x로 잘못 탐지되기도 함
            candidates = ["cp949", "utf-8"]
        else:
            candidates = [guessed_encoding, "cp949", "utf-8"]
        for candidate in candidates:
            try:
                logger.debug("attempt to open file with encoding: %s", candidate)
                with open(self.path, "r", encoding=candidate) as fp:
                    self.text = fp.read()
            except Exception:
                pass
            else:
                self.__encoding = candidate
                return self

        # fallback to alternative method
        errs_min = 1000
        best_candidate = None
        for candidate in candidates:
            errs = 0
            with open(self.path, "rb") as fp:
                for line in fp:
                    try:
                        line.decode(encoding=candidate)
                    except Exception:
                        errs += 1
                        if errs > errs_min:
                            break
                if errs < errs_min:
                    best_candidate = candidate
                    errs_min = errs
        encoding = best_candidate or candidates[0]
        logger.debug("attempt to open file with encoding: %s", encoding)
        with open(self.path, "r", encoding=encoding, errors="replace") as fp:
            self.text = fp.read()
        return self

    def demux(self) -> dict:
        logger.debug("languages: %s", self.languages)
        if len(self.languages) < 2:
            # 너무 많은 예외가 있어 2개 미만일 때 KRCC로 간주하는게 합리적이다.
            return {"KRCC": self.text}

        result = {}
        for capClass in self.languages:
            outlines = []
            passLine = True
            for line in self.text.splitlines():
                query = smiFile.CLASS_PTN.search(line)
                if query:
                    curCapClass = query.group(1)
                    passLine = curCapClass == capClass
                if passLine or smiFile.CLOSETAG_PTN.search(line):
                    outlines.append(line)
            result[capClass] = os.linesep.join(outlines)
        return result

    def _to_srt(self, sgml: str) -> List[subItem]:
        # parse things inside body tag
        body = smiFile.BODY_PTN.search(sgml).group(1)

        sub_items = []
        for sync in smiFile.SYNC_PTN.split(body)[1:]:
            sync_tag = "".join(sync.splitlines())
            if not sync_tag:
                continue
            sub_items.append(subItem.from_smi_sync("<SYNC" + sync_tag))

        # fill in end_ms and convert text
        for ind, item in enumerate(sub_items):
            try:
                item.end_ms = sub_items[ind + 1].start_ms
            except IndexError:
                if ind == len(sub_items) - 1:
                    item.end_ms = item.start_ms + 5 * 1000
                else:
                    item.end_ms = item.start_ms
            item.text_smi2srt()

        # TODO
        # * end_ms sometimes smaller than start_ms
        # * next item sometimes starts before current item ends

        return [x for x in sub_items if x.text_srt]

    def to_srt(self) -> List[srtFile]:
        srt_files = []
        for lang, sgml in self.demux().items():
            srt_file = srtFile.from_sub_items(self._to_srt(sgml))
            srt_file.language = lang
            srt_files.append(srt_file)
        logger.debug("srt files: %s", srt_files)
        return srt_files


class srtFile:
    def __init__(self):
        self.path: Path = None
        self.items: List[subItem] = None
        self.language: str = None

    def __repr__(self):
        return f"srtFile({len(self.items)} items, language={self.language})"

    def write_to(self, file_path: Union[Path, str], overwrite: bool = False):
        file_path = Path(file_path)
        if file_path.exists() and not overwrite:
            logger.info(" - skipped file write: target already exists: %s", file_path)
            return
        with open(file_path, "w", encoding="utf-8") as fp:
            fp.write(os.linesep.join([x.srtjoin(i + 1) for i, x in enumerate(self.items)]))
        logger.info(" - written: %s", file_path)

    @classmethod
    def from_sub_items(cls, items: List[subItem]) -> srtFile:
        this = cls()
        this.items = items
        return this


class SMI2SRTHandle:
    # for filetype detection
    SRT_TC_PTN = re.compile(r"\d{2}:\d{2}:\d{2},\d{3}")
    # filename
    KO_STRIP_PTN = re.compile(r"\.kor?$", re.I)

    @classmethod
    def start(cls, work_path: Union[Path, str], **kwargs):
        work_path = Path(work_path)
        if not work_path.exists():
            raise FileNotFoundError(work_path)

        recursive = kwargs.pop("recursive", False)
        if work_path.is_dir():
            if recursive:
                return cls.batch(work_path.rglob("*.[sS][mM][iI]"), **kwargs)
            return cls.batch(work_path.glob("*.[sS][mM][iI]"), **kwargs)
        if work_path.is_file() and work_path.suffix.lower() == ".smi":
            return cls.batch([work_path], **kwargs)

    @classmethod
    def move(cls, old: Path, newname: str = None, backup_dir: Path = None) -> Path:
        """move/rename a file"""
        newdir = backup_dir or old.parent
        new = newdir.joinpath(newname or old.name)
        if old == new:
            return
        if new.exists():
            logger.info(" - skipped file move: target already exists: %s", new)
            return
        try:
            old.rename(new)
            logger.info(" - moved: %s", new)
        except Exception:
            try:
                shutil.move(old, new)
                logger.info(" - moved: %s", new)
            except Exception:
                logger.exception("Exception while moving a file: %s", old)
                return
        return new

    @classmethod
    def batch(
        cls,
        files: Iterator[Path],
        delete_src: bool = False,
        overwrite_existing: bool = False,
        backup_dir: str = None,
    ):
        if backup_dir is not None:
            backup_dir = Path(backup_dir)
            if not backup_dir.is_dir():
                raise NotADirectoryError(backup_dir)

        for file in files:
            if file.is_dir():
                continue

            logger.debug("=================================================================")
            logger.info("'%s' to SRT", file)

            smi_file = None
            srt_files = None
            try:
                smi_file = smiFile.from_path(file)
                srt_files = smi_file.to_srt()
            except Exception:
                if smi_file is None:
                    logger.exception("Exception while opening file: %s", file)
                    cls.move(file, backup_dir=backup_dir)
                else:
                    filetype = cls.guess_filetype(smi_file.text)
                    if filetype is None:
                        logger.exception("Exception while converting file: %s", file)
                        cls.move(file, backup_dir=backup_dir)
                    else:
                        logger.error(" - Unsupported but known filetype: %s", filetype)
                        cls.move(file, newname=file.stem + filetype, backup_dir=backup_dir)
            else:
                try:
                    basedir = file.parent
                    basestem = cls.KO_STRIP_PTN.sub("", file.stem)

                    # filename
                    for srt_file in srt_files:
                        lang = srt_file.language
                        if len(srt_files) == 1 or lang == "KRCC":
                            srtname = basestem + ".ko.srt"
                        else:
                            srtname = basestem + f".{lang.lower()[:2]}.srt"

                        srt_file.write_to(basedir.joinpath(srtname), overwrite=overwrite_existing)
                except Exception:
                    logger.exception("Exception writing srt file(s): %s", srt_files)
                    cls.move(file, backup_dir=backup_dir)
                else:
                    if delete_src:
                        file.unlink()
                        logger.info(" - deleted: %s", file)

    @classmethod
    def guess_filetype(cls, text: str) -> str:
        if text.strip().startswith("[Script Info]"):
            if any(x in text for x in ["v4.00+", "V4+", "V4.00+", "v4+"]):
                # Advanced SubStation Alpha
                return ".ass"
            # SubStation Alpha
            return ".ssa"
        if len(cls.SRT_TC_PTN.findall(text)) > 10:
            return ".srt"
        if text.strip().startswith("d8:announce"):
            return ".torrent"
        return None


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="SMI to SRT")
    parser.add_argument("work_path", type=str, help="폴더나 파일 경로")
    parser.add_argument("-r", "--recursive", help="하위 폴더까지 탐색", action="store_true")
    parser.add_argument("-d", "--delete-src", help="변환 후 smi 파일을 삭제", action="store_true")
    parser.add_argument("-o", "--overwrite-existing", help="srt 파일이 있는 경우에 덮어씀", action="store_true")
    parser.add_argument("-b", "--backup-dir", help="실패시 이동할 폴더 (생략시 이동하지 않음)", default=None)
    parser.add_argument("-l", "--loglevel", help="로그레벨", choices=("ERROR", "WARN", "INFO", "DEBUG"), default="INFO")

    args = vars(parser.parse_args())

    logger = logging.getLogger(__name__)
    logger.setLevel(args.pop("loglevel"))
    logger.addHandler(logging.StreamHandler())

    logger.debug("args: %s", args)

    SMI2SRTHandle.start(**args)
