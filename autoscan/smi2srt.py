# -*- coding: UTF-8 -*-
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
# SJVA, Plex plugin, 쉘 공용
import logging
import os
import re
import shutil
import traceback
from pathlib import Path

try:
    import chardet
except ImportError:
    pass

logger = logging.getLogger("SMI2SRT")


class smiItem(object):
    def __init__(self):
        self.start_ms = 0
        self.start_ts = "00:00:00,000"
        self.end_ms = 0
        self.end_ts = "00:00:00,000"
        self.contents = None
        self.linecount = 0

    @staticmethod
    def ms2ts(ms):
        hours = ms // 3600000
        ms = ms - hours * 3600000
        minutes = ms // 60000
        ms = ms - minutes * 60000
        seconds = ms // 1000
        ms = ms - seconds * 1000
        s = "%02d:%02d:%02d,%03d" % (hours, minutes, seconds, ms)
        return s

    def convertSrt(self):
        # 1) convert timestamp
        self.start_ts = smiItem.ms2ts(self.start_ms)
        self.end_ts = smiItem.ms2ts(self.end_ms - 10)
        # 2) remove new-line
        self.contents = re.sub(r"\s+", " ", self.contents)
        # 3) remove web string like "&nbsp";
        self.contents = re.sub(r"&[a-z]{2,5};", "", self.contents)
        # 4) replace "<br>" with '\n';
        self.contents = re.sub(r"(<br>)+", "\n", self.contents, flags=re.IGNORECASE)
        # 5) find all tags
        fndx = self.contents.find("<")
        if fndx >= 0:
            contents = self.contents
            sb = self.contents[0:fndx]
            contents = contents[fndx:]
            while True:
                m = re.match(r"</?([a-z]+)[^>]*>([^<>]*)", contents, flags=re.IGNORECASE)
                if m is None:
                    break
                contents = contents[m.end(2) :]
                # if m.group(1).lower() in ['font', 'b', 'i', 'u']:
                if m.group(1).lower() in ["b", "i", "u"]:
                    sb += m.string[0 : m.start(2)]
                sb += m.group(2)
            self.contents = sb
        self.contents = self.contents.strip().strip("\n")

    def __repr__(self):
        s = "%d:%d:<%s>:%d" % (self.start_ms, self.end_ms, self.contents, self.linecount)
        return s


class SMI2SRTHandle(object):
    remake = False
    recursive = False
    no_remove_smi = False
    no_append_ko = False
    no_change_ko_srt = False
    fail_move_path = ""
    result_list = {}

    @staticmethod
    def start(
        work_path,
        remake=False,
        recursive=False,
        no_remove_smi=False,
        no_append_ko=False,
        no_change_ko_srt=False,
        fail_move_path="",
    ):
        SMI2SRTHandle.remake = remake
        SMI2SRTHandle.recursive = recursive
        SMI2SRTHandle.no_remove_smi = no_remove_smi
        SMI2SRTHandle.no_append_ko = no_append_ko
        SMI2SRTHandle.no_change_ko_srt = no_change_ko_srt
        SMI2SRTHandle.fail_move_path = fail_move_path
        SMI2SRTHandle.result_list = {
            "option": {
                "work_path": work_path,
                "remake": remake,
                "recursive": recursive,
                "no_remove_smi": no_remove_smi,
                "no_append_ko": no_append_ko,
                "no_change_ko_srt": no_change_ko_srt,
                "fail_move_path": fail_move_path,
            },
            "list": [],
        }
        try:
            work_path = Path(work_path)
            if work_path.is_dir():
                SMI2SRTHandle.convert_directory(work_path)
            else:
                SMI2SRTHandle.convert_directory(work_path.parent, [work_path])
            return SMI2SRTHandle.result_list
        except Exception as e:
            logger.debug("Exception: %s", e)
            logger.debug(traceback.format_exc())

    @staticmethod
    def convert_directory(work_path, lists=None):
        if lists is None:
            lists = work_path.iterdir()
        for item in lists:
            try:
                if item.is_dir() and SMI2SRTHandle.recursive:
                    SMI2SRTHandle.convert_directory(item)
                elif item.is_file():
                    if item.suffix.lower() == ".smi":
                        if SMI2SRTHandle.no_append_ko or item.stem.lower().endswith((".kor", ".ko")):
                            srt_file = item.stem + ".srt"
                        else:
                            srt_file = item.stem + ".ko.srt"
                        srt_file = item.parent.joinpath(srt_file)
                        if srt_file.exists():
                            if SMI2SRTHandle.remake:
                                # log.debug('remake is true..')
                                pass
                            else:
                                # log.debug('remake is false..')
                                continue
                        logger.debug("=========================================")
                        logger.debug("source: %s", item)
                        logger.debug("target: %s", srt_file)
                        _ret = SMI2SRTHandle.convert_one_file_logic(item, srt_file)
                        logger.debug("result: %s", _ret)
                        if _ret["ret"] == "success" and not SMI2SRTHandle.no_remove_smi:
                            logger.debug("remove smi")
                            os.remove(item)
                        elif _ret["ret"] == "fail" and SMI2SRTHandle.fail_move_path:
                            target = Path(SMI2SRTHandle.fail_move_path).joinpath(item.name)
                            if item != target:
                                shutil.move(item, target)
                                logger.debug("move smi")
                        elif _ret["ret"] == "continue":
                            continue
                        elif _ret["ret"] == "not_smi_is_ass":
                            shutil.move(item, srt_file.parent.joinpath(srt_file.name.replace(".srt", ".ass")))
                            logger.debug("move to ass..")
                        elif _ret["ret"] == "not_smi_is_srt":
                            shutil.move(item, srt_file)
                            logger.debug("move to srt..")
                        elif _ret["ret"] == "not_smi_is_torrent":
                            shutil.move(item, item.parent.joinpath(item.name.replace(".smi", ".torrent")))
                            logger.debug("move to torrent..")
                        SMI2SRTHandle.result_list["list"].append(_ret)
                    elif item.name.lower().endswith((".ko.srt", ".kor.srt")) or (
                        item.name[-7] == "." and item.suffix.lower() == ".srt"
                    ):
                        logger.debug("pass : %s", item)
                    elif item.suffix.lower() == ".srt" and not SMI2SRTHandle.no_change_ko_srt:
                        logger.debug(".srt => .ko.srt : %s", item)
                        shutil.move(item, item.parent.joinpath(item.name.replace(".srt", ".ko.srt")))

            except Exception as e:
                logger.debug("Exception: %s", e)
                logger.debug(traceback.format_exc())

    @staticmethod
    def predict_encoding(file_path, n_lines=100):
        """Predict a file's encoding using chardet"""
        try:
            # Open the file as binary data
            with open(file_path, "rb") as f:
                # Join binary lines for specified number of lines
                rawdata = b"".join([f.readline() for _ in range(n_lines)])
            fenc = chardet.detect(rawdata)["encoding"]
            logger.debug("encoding detected by chardet: %s", fenc)
            return fenc
        except Exception as e:
            logger.debug("Exception: %s", e)

        try:
            ifp = open(file_path, "rb")
            aBuf = ifp.read()
            ifp.close()

            # If the data starts with BOM, we know it is UTF
            if aBuf[:3] == "\xEF\xBB\xBF":
                # EF BB BF  UTF-8 with BOM
                result = "UTF-8"
            elif aBuf[:2] == "\xFF\xFE":
                # FF FE  UTF-16, little endian BOM
                result = "UTF-16LE"
            elif aBuf[:2] == "\xFE\xFF":
                # FE FF  UTF-16, big endian BOM
                result = "UTF-16BE"
            elif aBuf[:4] == "\xFF\xFE\x00\x00":
                # FF FE 00 00  UTF-32, little-endian BOM
                result = "UTF-32LE"
            elif aBuf[:4] == "\x00\x00\xFE\xFF":
                # 00 00 FE FF  UTF-32, big-endian BOM
                result = "UTF-32BE"
            elif aBuf[:4] == "\xFE\xFF\x00\x00":
                # FE FF 00 00  UCS-4, unusual octet order BOM (3412)
                result = "X-ISO-10646-UCS-4-3412"
            elif aBuf[:4] == "\x00\x00\xFF\xFE":
                # 00 00 FF FE  UCS-4, unusual octet order BOM (2143)
                result = "X-ISO-10646-UCS-4-2143"
            else:
                result = "ascii"
            logger.debug("encoding detected by heading: %s", result)
            return result
        except Exception as e:
            logger.debug("Exception: %s", e)
            logger.debug(traceback.format_exc())

    @staticmethod
    def convert_one_file_logic(smi_file, srt_file):
        _ret = {"smi_file": str(smi_file)}
        try:
            if not smi_file.exists():
                _ret["ret"] = "fail"
                return _ret

            encoding = SMI2SRTHandle.predict_encoding(smi_file).lower()

            if encoding is not None:
                if encoding.startswith("utf-16") or encoding.startswith("utf-8"):
                    encoding2 = encoding
                else:
                    encoding2 = "cp949"
                logger.debug("text encoding: %s %s", encoding, encoding2)
                # if encoding == 'EUC-KR' or encoding == 'ascii' or encoding == 'Windows-1252' or encoding == 'ISO-8859-1':
                #     encoding = 'cp949'
                _ret["encoding1"] = encoding
                _ret["encoding2"] = encoding2
                try:
                    ifp = open(smi_file, "r", encoding=encoding2)
                    smi_sgml = ifp.read()
                    _ret["is_success_file_read"] = True
                except Exception as e:
                    _ret["is_success_file_read"] = False
                    logger.debug("Exception: %s", e)
                    # log.debug(traceback.format_exc())
                    logger.debug("line read logic start..")
                    ifp = open(smi_file, "rb")
                    lines = []
                    count = 0
                    while True:
                        line = ifp.readline()
                        if not line:
                            break
                        try:
                            lines.append(line.decode("utf-8"))
                        except Exception:
                            count += 1
                    smi_sgml = "".join(lines)
                    logger.debug("line except count: %s", count)
                    _ret["except_line_count"] = count
            else:
                _ret["ret"] = "fail"
                return _ret

            data = SMI2SRTHandle.demuxSMI(smi_sgml)
            _ret["lang_count"] = len(data)
            _ret["srt_list"] = []
            for lang, smi_sgml in data.items():
                logger.debug("lang info: %s", lang)
                try:
                    try:
                        fndx = smi_sgml.upper().find("<SYNC")
                    except Exception as e:
                        raise e

                    if fndx < 0:
                        _ret["ret"] = SMI2SRTHandle.process_not_sync_tag(smi_sgml)
                        return _ret
                    smi_sgml = smi_sgml[fndx:]
                    lines = smi_sgml.split("\n")

                    srt_list = []
                    sync_cont = ""
                    si = None
                    linecnt = 0
                    for line in lines:
                        linecnt += 1
                        sndx = line.upper().find("<SYNC")
                        if sndx >= 0:
                            m = re.search(r"<sync\s+start\s*=\s*(\d+)>(.*)$", line, flags=re.IGNORECASE)
                            if not m:
                                m = re.search(
                                    r"<sync\s+start\s*=\s*(\d+)\send\s*=(\d+)>(.*)$",
                                    line,
                                    flags=re.IGNORECASE,
                                )
                            if not m:
                                m = re.search(r"<sync\s+start\s*=-\s*(\d+)>(.*)$", line, flags=re.IGNORECASE)
                            if not m:
                                # <SYNC Start="100">, 마지막 > 태그 없는거
                                m = re.search(
                                    r"<SYNC\s+Start\s*=\"?(\d+)\"?>?(.*)$",
                                    line,
                                    flags=re.IGNORECASE,
                                )
                            if not m:
                                # <SYNC S tart=1562678
                                m = re.search(
                                    r"<sync\s+s\s*t\s*a\s*r\s*t\s*=\s*(\d+)>(.*)$",
                                    line,
                                    flags=re.IGNORECASE,
                                )
                            if not m:
                                line2 = line.lower().replace("<sync start=>", "<sync start=0>")
                                m = re.search(r"<sync\s+start\s*=\s*(\d+)>(.*)$", line2, flags=re.IGNORECASE)
                            if not m:
                                raise Exception('AAAAAA format tag of <Sync start=nnnn> with "%s"' % line)

                                # print '#raise Exception'
                            sync_cont += line[0:sndx]
                            last_si = si
                            if last_si is not None:
                                last_si.end_ms = int(m.group(1))
                                last_si.contents = sync_cont
                                srt_list.append(last_si)
                                last_si.linecount = linecnt
                                # print '[%06d] %s' % (linecnt, last_si)
                            sync_cont = m.group(2)
                            si = smiItem()
                            si.start_ms = int(m.group(1))
                        else:
                            sync_cont += line

                    # ofp = open(srt_file, 'w', encoding="utf8")
                    # ofp = open(srt_file, 'w')
                    if lang == "KRCC":
                        out_srt_file = srt_file
                    else:
                        if srt_file.name.endswith(".ko.srt"):
                            out_srt_name = srt_file.name.replace(".ko.srt", ".%s.srt" % lang.lower()[:2])
                        else:
                            out_srt_name = srt_file.name.replace(".srt", ".%s.srt" % lang.lower()[:2])
                        out_srt_file = srt_file.parent.joinpath(out_srt_name)

                    ofp = open(out_srt_file, "w", encoding="utf8")
                    ndx = 1
                    for si in srt_list:
                        si.convertSrt()
                        if (si.contents is None) or (len(si.contents) <= 0):
                            continue
                        # print si
                        sistr = "%d\n%s --> %s\n%s\n\n" % (ndx, si.start_ts, si.end_ts, si.contents)
                        ofp.write(sistr)
                        ndx += 1
                    ofp.close()
                    _ret["srt_list"].append({"lang": lang, "srt_file": str(out_srt_file)})
                except Exception as e:
                    logger.debug("Exception: %s", e)
                    logger.debug(traceback.format_exc())
                    _ret["ret"] = "fail"
                    return _ret
            _ret["ret"] = "success"
            return _ret
        except Exception as e:
            logger.debug("Exception: %s", e)
            logger.debug(traceback.format_exc())
            _ret["ret"] = "fail"
            return _ret

    @staticmethod
    def process_not_sync_tag(text):
        try:
            logger.debug("NO SYNC TAG")
            if text.strip().startswith("[Script Info]"):
                return "not_smi_is_ass"
            result = re.compile(r"\d{2}:\d{2}:\d{2},\d{3}").findall(text)
            if len(result) > 10:
                return "not_smi_is_srt"
            if text.strip().startswith("d8:announce"):
                return "not_smi_is_torrent"
            return "fail"
        except Exception as e:
            logger.debug("Exception: %s", e)
            logger.debug(traceback.format_exc())

    @staticmethod
    def demuxSMI(smi_sgml):
        try:
            # LANG_PTN = re.compile(r'^\s*\.([A-Z]{2}CC) *{ *[Nn]ame:.*; *[Ll]ang: *(\w{2})-(\w{2});.*}', re.M | re.I)
            LANG_PTN = re.compile(r"^\s*\.([A-Z]{2}CC)", re.M | re.I)
            CLASS_PTN = re.compile(r"<[Pp] [Cc]lass=([A-Z]{2}CC)>")
            CLOSETAG_PTN = re.compile(r"</(BODY|SAMI)>", re.I)

            langinfo = LANG_PTN.findall(smi_sgml)

            if len(langinfo) < 2:
                return {"KRCC": smi_sgml}
            result = dict()
            lines = smi_sgml.split("\n")
            # for capClass, lang, country in langinfo:
            for capClass in langinfo:
                outlines = []
                passLine = True
                for line in lines:
                    query = CLASS_PTN.search(line)
                    if query:
                        curCapClass = query.group(1)
                        passLine = True if curCapClass == capClass else False
                    if passLine or CLOSETAG_PTN.search(line):
                        outlines.append(line)
                # print "%s = %d" % (lang, len(outlines))
                if len(outlines) > 100:
                    result[capClass] = "\n".join(outlines)

            return result
        except Exception as e:
            logger.debug("Exception: %s", e)
            logger.debug(traceback.format_exc())


if __name__ == "__main__":
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.DEBUG)
    logger.addHandler(logging.StreamHandler())

    import argparse

    parser = argparse.ArgumentParser(description="SMI to SRT")
    parser.add_argument("work_path", type=str, help="폴더나 파일 경로")
    parser.add_argument("--remake", help="srt 파일이 있는 경우에도 재생성", action="store_true")
    parser.add_argument("--recursive", help="하위 폴더까지 탐색", action="store_true")
    parser.add_argument("--no_remove_smi", help="변환 후 smi 파일을 삭제하지 않음. (생략시 삭제)", action="store_true")
    parser.add_argument("--no_append_ko", help="파일명에 .ko를 추가하지 않음 (생략시 추가)", action="store_true")
    parser.add_argument("--no_change_ko_srt", help=".srt 파일을 .ko.srt로 변경하지 않음 (생략시 변경함)", action="store_true")
    parser.add_argument("--fail_move_path", help="실패시 이동할 폴더 (생략시 이동하지 않음)", default="")

    args = parser.parse_args()
    logger.debug("args:%s", args)

    ret = SMI2SRTHandle.start(
        args.work_path,
        remake=args.remake,
        recursive=args.recursive,
        no_remove_smi=args.no_remove_smi,
        no_append_ko=args.no_append_ko,
        no_change_ko_srt=args.no_change_ko_srt,
        fail_move_path=args.fail_move_path,
    )
