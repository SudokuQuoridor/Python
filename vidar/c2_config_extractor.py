# Author: SudokuQuoridor
# vidar 2.0 17.1 UPX unpacked SHA1: 292E9BA6755EDF4DAC79921E020E23DCF408FBA9
# vidar 2.0 17.6 UPX unpacked SHA1: 49B648973C26996557288FBB9DF294375172B2E4

# It is working at Vidar UPX Unpacked and version 17.1 ~ 17.6

import re
import argparse
import traceback
import requests
import json
from dataclasses import dataclass, asdict, replace
from typing import List, Tuple, Any, Optional

# 17.1 ~ 17.6 버전의 경우 OUTPUT_TABLE를 고정으로 사용하나 추후 변경 시 수정 필요
OUTPUT_TABLE =  bytes.fromhex("30 31 32 33 34 35 36 37 38 39 61 62 63 64 65 66 67 68 69 6A 6B 6C 6D 6E 6F 70 71 72 73 74 75 76 77 78 79 7A 41 42 43 44 45 46 47 48 49 4A 4B 4C 4D 4E 4F 50 51 52 53 54 55 56 57 58 59 5A 21 23 24 26 28 29 2A 2B 2C 2D 2E 2F 3A 3B 3C 3D 3E 3F 40 5B 5D 5E 5F 60 7B 7C 7D 7E 20")
OUTPUT_TABLE_len = len(OUTPUT_TABLE)
# 난독화 해제 로직
def custom_decode(binary: bytes, lookup_table: bytes) -> bytes:
	if not isinstance(lookup_table, bytes):
		raise TypeError
	if not lookup_table:
		return b""

	if not isinstance(binary, bytes):
		raise TypeError
	if not binary:
		return b""

	lookup_table_len = len(lookup_table)
	
	result = bytearray()
	for i, ch in enumerate(binary):
		idx = lookup_table.find(ch)

		if idx < 0:
			result.append(ch)
			continue

		num = (idx - i) % lookup_table_len
		result.append(OUTPUT_TABLE[num % OUTPUT_TABLE_len])

	return bytes(result)

RE_VERSION = re.compile(r"^\d+(\.\d){0,2}$") # version ex. 16, 17.1
RE_BUILD = re.compile(r"^[0-9a-fA-F]{32}$") # MD5 hash
RE_LOOKUP = re.compile(r"^[\x20-\x7E]{%d}$" % OUTPUT_TABLE_len) #printable lookup table and same output table's length

def validate_candidates(can: List[str]) -> bool:
	if len(can) != 8:
		print("[INFO] Failed to validate Candidate length")
		return False

	if not RE_VERSION.fullmatch(can[0]):
		print("[INFO] Failed to validate Version")
		return False
	
	if not RE_BUILD.fullmatch(can[1]):
		print("[INFO] Failed to validate Build_id")
		return False

	te = can[2].lower()
	if ("telegram" not in te) and ("t.me" not in te):
		print("[INFO] Failed to validate Telegram URL")
		return False	
	
	st = can[5].lower()
	if ("steamcommunity" not in st) and ("steam" not in st):
		print("[INFO] Failed to validate Steal URL")
		return False
	
	if len(can[4]) < 0x25 or len(can[7]) < 0x25:
		print("[INFO] Failed to validate User-Agent Length")
		return False
	
	if len(can[3]) < 4 or len(can[6]) < 4:
		print("[INFO] Failed to validate Marker Length")
		return False	
	
	return True

# 1. 표시목을 기준으로 블록 범위를 잡는다.
# 2. 블록 패턴 \x30 \x00 [\x20-\x7E]{2,4}를 통해 반환받은 시작주소 +2 블록 재정의
# 3. printable_ascii로 리스트화 0x20 8개 반복 제외 조건

# a1: Version 3~5 글자
# a2: build_id 32자 고정
# a3: Telegram URL
# a4: URL Marker
# a5: User-Agent
# a6: SteamCommunity URL
# a7: URL Marker
# a8: User-Agent
PRINTABLE_RUN = re.compile(rb"[\x20-\x7E]+")
def extract_printable_run(binary: bytes) -> List[bytes]:
	return [m.group(0) for m in PRINTABLE_RUN.finditer(binary) if m.group(0) != b"\x20\x20\x20\x20\x20\x20\x20\x20"] # 표시목 제외

BLOCK_PATTERN = re.compile(rb"(\x30\x00)[\x20-\x7E]{2,5}") #블록 시작 지점 선정 패턴

def search_candidates(file_buf: bytes) -> List[str]:
	opcode = bytes.fromhex("00 00 00 20 20 20 20 20 20 20 20 00 00 00 00 00")
	pos = 0
	cand = None

	while True:
		pos = file_buf.find(opcode, pos)

		if pos == -1:
			break
		
		print("[SUCCESS] Find opcode in binary")
		search_block = file_buf[pos - 0x200: pos + 0x800]

		block_pos = 0
		m = BLOCK_PATTERN.search(search_block)

		if m is None:
			pos = pos + len(opcode)
			continue
		
		print("[SUCCESS] Find block in binary")
		block_pos = m.start()

		search_block = search_block[block_pos + 2:]
		cand = extract_printable_run(search_block)

		if len(cand) < 9:
			pos = pos + 1
			continue
		
		print("[SUCCESS] Extract 9 Candidate")
		c2_config = []
		try:
			for can in cand:
				if can == cand[2]:
					continue

				c2_config.append(custom_decode(can, cand[2]).decode("ascii", errors="strict"))
		except Exception:
			traceback.print_exc()


		if validate_candidates(c2_config):
			print("[SUCCESS] Validate C2 config Candiates")			
			break
		else:
			c2_config = None

		pos = pos + 1
	
	return c2_config

@dataclass(frozen=True)
class DDRConfig:
	url: str
	marker: str
	user_agent: str

@dataclass(frozen=True)
class VidarC2Config:
	version: str
	build_id: str
	telegram_url: str
	telegram_c2url: List[str]
	steam_url: str
	steam_c2url: List[str]

def parse_config_class(c2_config: List[str]) -> Tuple[DDRConfig, DDRConfig, VidarC2Config]: # 반환값 1. telegram DDR, 2. steam DDR, 3 c2_config
	telegram_conf = DDRConfig(
		url = c2_config[2],
		marker = c2_config[3],
		user_agent = c2_config[4]
	)

	steam_conf = DDRConfig(
		url = c2_config[5],
		marker = c2_config[6],
		user_agent = c2_config[7]
	)

	vidar_conf = VidarC2Config(
		version = c2_config[0],
		build_id = c2_config[1],
		telegram_url = c2_config[2],
		telegram_c2url = [],
		steam_url = c2_config[5],
		steam_c2url = []
	)

	return (telegram_conf, steam_conf, vidar_conf)

# 시작 주소: 마커 ' ',  종료 주소: '|'
def extract_C2_URL(text: str, marker: str, multi: bool) -> List[str]:
	pat = re.compile(re.escape(marker) + r" ([^|]+)\|")
	hits = [m.group(1).strip() for m in pat.finditer(text)]

	if multi is False:
		return hits[:1]
	
	seed = set()
	out = []

	for h in hits:
		if h not in seed:
			seed.add(h)
			out.append(h)

	return out

def get_http_text(c2_url: str, ua: str) -> str:
	header = {"User-Agent": ua}
	try:
		r = requests.get(c2_url, headers=header, timeout= 15)

		r.raise_for_status()
		return r.text
	except Exception as e:
		print(f"[ERROR] Failed to Request HTTP Get {e}")
		return ""


def get_http_json(c2_url: str, ua: str) -> Optional[Any]:
	header = {"User-Agent": ua}
	try:
		r = requests.get(c2_url, headers=header, timeout= 15)

		r.raise_for_status()
		return r.json()		
	except Exception as e:
		print(f"[ERROR] Failed to Request HTTP Get {e}")
		return None

# steamcommunity의 경우 url 끝에 "/ajaxaliases/"를 붙여 json 포멧의 과거 사용한 c2 URL 목록을 반환받음
def append_steam(steam_url: str) -> str:
	steam_url = steam_url.rstrip('/')

	steam_url += "/ajaxaliases/"

	return steam_url

def main():
	parse = argparse.ArgumentParser(description = "Vidar 2.0 17.1 ~ 17.6 C2 Config Extrator")
	parse.add_argument("file", help = "Select UPX Unpacked Vidar file")
	parse.add_argument("-out", help = "Specify Result Path", type = str)
	args = parse.parse_args()

	try:
		with open(args.file, 'rb') as r:
			binary = r.read()
	except FileNotFoundError:
		print(f"[ERROR] Failed {args.file} not founded")
		return False

	print(f"[SUCCESS] Load Vidar file")

	c2_config = None
	c2_config = search_candidates(binary)

	if c2_config is None:
		print(f"[FAIL] Failed to Find C2 Config")
		return False

	telegram, steam, vidar_conf = parse_config_class(c2_config)
	telegram_html = get_http_text(telegram.url, telegram.user_agent)

	c2_url_telegram = extract_C2_URL(telegram_html, telegram.marker, False)

	steam_ajax = append_steam(steam.url)
	steam_json = get_http_json(steam_ajax, steam.user_agent)
	steam_text = json.dumps(steam_json or {}, ensure_ascii=False)
	c2_url_steam = extract_C2_URL(steam_text, steam.marker, True)

	output = replace(vidar_conf, telegram_c2url = c2_url_telegram, steam_c2url = c2_url_steam)
	out_dict = asdict(output)

	try:
		if args.out:
			with open(args.out, "w", encoding="utf-8") as o:
				json.dump(out_dict, o, indent=2)
		else:
			with open("result.json", "w", encoding="utf-8") as o:
				json.dump(out_dict, o, indent=2)
	except Exception as e:
		print(f"[ERROR] Failed to write result.json {e}")		
		
	print(f"[OK] Success to Extrator Vidar 2.0 config")

if __name__ == "__main__":
	main()

