#!/usr/bin/env python3
"""
khôi phục tin nhắn đã xóa từ WAL và giải mã secret message
Chạy:
    python3 for01.py <thư_mục_dữ_liệu_app> [-o out]
    # thư mục dữ liệu app là thư mục chứa databases
Cần: pip install cryptography
"""
import argparse
import base64
import datetime
import hashlib
import os
import re
import sqlite3
import struct
import sys
import zlib
from pathlib import Path
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
# ---------------- Tham số lấy từ APK (com.example.chatapp.Constants) ----------------
NONCE_HEX      = "706eeff3706eeff3706eeff3706eeff3"
ORDER_XOR      = 931071618            # = 0x377F0682
SECRET_MESSAGE = "sqlite3_forensics_2026"
SELECT_MOD     = 3
# PREFS_NAME = "chat_prefs", SALT_KEY = "device_salt" -> salt nằm trong shared_prefs/chat_prefs.xml
# ---------------- Salt lấy từ shared_prefs/chat_prefs.xml ----------------
SALT_B64       = "bVaN8B8ekPGF5tPMwKoubg=="
TABLE   = "messages"
BODY_RE = re.compile(r"^[A-Za-z0-9+/]{2}==$")   # body mang đúng 1 byte (base64 của 1 byte)
TZ      = datetime.timezone(datetime.timedelta(hours=7))
WAL_HDR, WAL_FRAME_HDR = 32, 24
# ======================================================================
# BƯỚC 1: Đọc WAL
# ======================================================================
def read_wal_header(blob):
    """Header 32 byte: magic, version, page size, checkpoint seq, salt1, salt2, checksum1, checksum2."""
    magic, ver, pgsz, ckpt, s1, s2, c1, c2 = struct.unpack(">8I", blob[:WAL_HDR])
    if magic not in (0x377F0682, 0x377F0683):
        raise ValueError("Magic WAL không hợp lệ: 0x%08x" % magic)
    return {"big_endian": magic == 0x377F0683,         # 0x...83 = checksum big-endian
            "page_size": 65536 if pgsz == 1 else pgsz,
            "salt": (s1, s2), "checksum": (c1, c2)}
def wal_checksum(data, s1, s2, big_endian):
    """Checksum của SQLite WAL: cộng dồn theo từng cặp word 32-bit."""
    words = struct.unpack(("%s%dI" % (">" if big_endian else "<", len(data) // 4)), data)
    for i in range(0, len(words), 2):
        s1 = (s1 + words[i] + s2) & 0xFFFFFFFF
        s2 = (s2 + words[i + 1] + s1) & 0xFFFFFFFF
    return s1, s2
def iter_frames(blob, hdr):
    """Duyệt từng frame (header 24 byte + 1 trang) và kiểm tra salt + checksum."""
    ps, be = hdr["page_size"], hdr["big_endian"]
    run = hdr["checksum"]                    # checksum cộng dồn, bắt đầu từ checksum của header
    off, idx = WAL_HDR, 0
    while off + WAL_FRAME_HDR + ps <= len(blob):
        fh = blob[off:off + WAL_FRAME_HDR]
        pgno, dbsize, fs1, fs2, fc1, fc2 = struct.unpack(">6I", fh)
        page = blob[off + WAL_FRAME_HDR:off + WAL_FRAME_HDR + ps]
        c = wal_checksum(fh[:8], run[0], run[1], be)
        c = wal_checksum(page, c[0], c[1], be)
        ok = c == (fc1, fc2) and (fs1, fs2) == hdr["salt"]
        # Frame sai salt/checksum là rác của lần WAL cũ -> SQLite bỏ qua, ta cũng dừng tại đây
        if not ok:
            break
        yield {"index": idx, "pgno": pgno, "commit_size": dbsize, "page": page}
        run = c
        off += WAL_FRAME_HDR + ps
        idx += 1
def split_transactions(frames):
    """Cắt transaction tại mỗi commit frame (db size after commit != 0)."""
    txs, cur = [], []
    for f in frames:
        cur.append(f)
        if f["commit_size"]:
            txs.append(cur)
            cur = []
    return txs
def materialize(db_blob, frames, upto, page_size, out_path):
    """Dựng snapshot: áp mọi frame có index <= upto lên bản sao của .db.
    Áp nguyên trang nên record nằm trên overflow page cũng được khôi phục đúng."""
    data = bytearray(db_blob)
    dbsize = None
    for f in frames:
        if f["index"] > upto:
            break
        p = f["pgno"]
        need = p * page_size
        if len(data) < need:
            data.extend(b"\x00" * (need - len(data)))
        data[(p - 1) * page_size:p * page_size] = f["page"]
        if f["commit_size"]:
            dbsize = f["commit_size"]
    if dbsize:
        data = data[:dbsize * page_size]
        data[28:32] = struct.pack(">I", dbsize)        # đồng bộ số trang trong DB header
    with open(out_path, "wb") as fh:
        fh.write(bytes(data))
    return out_path
def open_ro(path):
    # immutable=1: SQLite không tạo -wal/-shm, không checkpoint, không ghi gì vào file
    return sqlite3.connect(Path(path).resolve().as_uri() + "?mode=ro&immutable=1", uri=True)
def read_rows(path):
    con = open_ro(path)
    try:
        cols = [r[1] for r in con.execute("PRAGMA table_info(%s)" % TABLE)]
        rows = {r[0]: dict(zip(cols, r[1:]))
                for r in con.execute("SELECT rowid,%s FROM %s" % (",".join(cols), TABLE))}
        return cols, rows
    finally:
        con.close()
def recover_deleted(db_path, wal_path, outdir):
    db_blob = open(db_path, "rb").read()               # chỉ đọc byte, không mở bằng sqlite3
    wal_blob = open(wal_path, "rb").read()
    page_size = struct.unpack(">H", db_blob[16:18])[0]
    page_size = 65536 if page_size == 1 else page_size
    hdr = read_wal_header(wal_blob)
    frames = list(iter_frames(wal_blob, hdr))
    txs = split_transactions(frames)
    print("[*] WAL: %d frame hợp lệ, %d transaction đã commit, page size %d"
          % (len(frames), len(txs), page_size))
    # Snapshot 0 = file .db trước khi áp WAL, sau đó là snapshot sau từng transaction
    snaps = [materialize(db_blob, [], -1, page_size, os.path.join(outdir, "state_00_base.db"))]
    for i, tx in enumerate(txs, 1):
        snaps.append(materialize(db_blob, frames, tx[-1]["index"], page_size,
                                 os.path.join(outdir, "state_%02d_tx%d.db" % (i, i))))
    # So sánh snapshot liên tiếp: rowid biến mất = bản ghi bị DELETE
    deleted, prev = {}, None
    for i, path in enumerate(snaps):
        cols, rows = read_rows(path)
        if prev is not None:
            gone = sorted(set(prev) - set(rows))
            added = len(set(rows) - set(prev))
            print("    state_%02d: %4d dòng  (+%d, -%d)" % (i, len(rows), added, len(gone)))
            for rid in gone:
                deleted[rid] = prev[rid]
        else:
            print("    state_00: %4d dòng  (file .db gốc)" % len(rows))
        prev = rows
    print("[+] Khôi phục %d bản ghi đã bị xóa" % len(deleted))
    return deleted
# ======================================================================
# BƯỚC 2: Ghép ciphertext
# ======================================================================
def fmt_ts(ts):
    sec = ts / 1000 if ts > 10**11 else ts             # timestamp ms hay s
    return datetime.datetime.fromtimestamp(sec, TZ).strftime("%Y-%m-%d %H:%M:%S")
def build_ciphertext(deleted):
    cands = [r for r in deleted.values()
             if isinstance(r.get("body"), str) and BODY_RE.match(r["body"])]
    # Nếu có nhiều thread, lấy thread chứa nhiều tin nhắn mang byte nhất
    if cands and "thread_id" in cands[0]:
        by_thread = {}
        for r in cands:
            by_thread.setdefault(r["thread_id"], []).append(r)
        print("[*] Ứng viên body 'XX==' theo thread: %s"
              % {k: len(v) for k, v in sorted(by_thread.items())})
        thread, cands = max(by_thread.items(), key=lambda kv: len(kv[1]))
        print("[*] Chọn thread_id = %s (%d bản ghi)" % (thread, len(cands)))
    selected = []
    for r in cands:
        k = r["timestamp"] ^ ORDER_XOR                 # sortkey
        if k % SELECT_MOD == 0:                        # chỉ tin nhắn này mang byte thật
            selected.append((k, r))
    selected.sort(key=lambda x: x[0])                  # sắp sortkey tăng dần
    print("[*] Giữ sortkey %% %d == 0: %d bản ghi" % (SELECT_MOD, len(selected)))
    print("    %-4s %-19s %-12s %-6s %s" % ("#", "timestamp (UTC+7)", "sortkey", "body", "byte"))
    ct = bytearray()
    for i, (k, r) in enumerate(selected):
        b = base64.b64decode(r["body"])[0]
        ct.append(b)
        print("    %-4d %-19s %-12d %-6s %02x" % (i, fmt_ts(r["timestamp"]), k, r["body"], b))
    return bytes(ct)
# ======================================================================
# BƯỚC 3: Giải mã
# ======================================================================
def chacha20(data, key, nonce):
    # cryptography expects a 16-byte parameter: 64-bit counter + 64-bit nonce.
    # Preserve the challenge parameter exactly.
    return Cipher(algorithms.ChaCha20(key, nonce), mode=None).decryptor().update(data)
def decrypt(ct, salt_b64):
    salt = base64.b64decode(salt_b64)                  # salt phải decode base64 trước khi ghép
    secret = SECRET_MESSAGE.encode()
    nonce = bytes.fromhex(NONCE_HEX)
    expect_crc = int(NONCE_HEX[:8], 16)                # NONCE = CRC32(flag) lặp 4 lần
    found = None
    for label, material in (("SECRET || salt", secret + salt),
                            ("salt || SECRET", salt + secret)):
        key = hashlib.sha256(material).digest()
        pt = chacha20(ct, key, nonce)
        crc = zlib.crc32(pt) & 0xFFFFFFFF
        ok = crc == expect_crc
        print("    [%s] %-15s crc32=%08x  %r" % ("+" if ok else "-", label, crc, pt))
        if ok:
            found = pt
    return found
# ======================================================================
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("appdir", help="thư mục dữ liệu app (chứa databases/)")
    ap.add_argument("-o", "--outdir", default="out", help="thư mục chứa snapshot dựng lại")
    a = ap.parse_args()
    db = os.path.join(a.appdir, "databases", "chatapp.db")
    wal = db + "-wal"
    for p in (db, wal):
        if not os.path.exists(p):
            sys.exit("[!] Không tìm thấy %s" % p)
    os.makedirs(a.outdir, exist_ok=True)
    print("=== BƯỚC 1: Khôi phục bản ghi đã xóa từ WAL ===")
    deleted = recover_deleted(db, wal, a.outdir)
    print("\n=== BƯỚC 2: Ghép ciphertext ===")
    ct = build_ciphertext(deleted)
    print("[+] Ciphertext (%d byte): %s" % (len(ct), ct.hex()))
    print("\n=== BƯỚC 3: Giải mã ChaCha20 ===")
    print("[*] Salt (device_salt): %s" % SALT_B64)
    flag = decrypt(ct, SALT_B64)
    if flag:
        print("\n[+] SECRET MESSAGE: %s" % flag.decode("utf-8", "replace"))
    else:
        print("\n[!] Không thứ tự ghép key nào cho CRC32 khớp, kiểm tra lại ciphertext.")
if __name__ == "__main__":
    main()
