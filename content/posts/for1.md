+++
title = "for1 — CSCV2026 vòng chung khảo"
date = 2026-10-16T22:00:00+07:00
draft = false
tags = ["CSCV2026", "Forensics", "Android", "SQLite", "WAL", "ChaCha20"]
categories = ["Writeups"]
summary = "Khôi phục 32 tin nhắn đã xóa từ SQLite WAL, ghép ciphertext và giải mã tin nhắn bí mật trong ứng dụng Android."
ShowToc = true
TocOpen = false
+++

Bài này có một chuỗi khá dễ gây hiểu nhầm trong APK: `sqlite3_forensics_2026`. Tên biến là `SECRET_MESSAGE`, nhưng lấy nó bọc vào format flag thì chưa xong. Nó chỉ là một phần nguyên liệu tạo khóa; tin nhắn cần tìm nằm trong những bản ghi đã bị xóa khỏi database.

## Khảo sát artifact

Giải nén `artifact.zip`, các file đáng chú ý là:

```text
chatapp.apk
databases/
    chatapp.db
    chatapp.db-wal
    chatapp.db-shm
shared_prefs/
    chat_prefs.xml
```

Mình phân tích APK bằng JADX và đọc database trên bản sao. Không cần cài ứng dụng lên điện thoại hay chạy APK.

Trong `com.example.chatapp.Constants` có các giá trị:

```java
NONCE_HEX = "706eeff3706eeff3706eeff3706eeff3";
ORDER_XOR = 931071618;
SECRET_MESSAGE = "sqlite3_forensics_2026";
SELECT_MOD = 3;
PREFS_NAME = "chat_prefs";
SALT_KEY = "device_salt";
```

Hai tên cuối dẫn tới `shared_prefs/chat_prefs.xml`:

```xml
<map>
    <string name="device_salt">bVaN8B8ekPGF5tPMwKoubg==</string>
</map>
```

Như vậy đã có secret, salt và nonce. Phần còn thiếu là ciphertext. Chỉ truy vấn trạng thái cuối của bảng `messages` sẽ bỏ lỡ nhóm tin nhắn chứa dữ liệu này.

## Lấy lại tin nhắn từ WAL

SQLite ở chế độ WAL ghi các phiên bản trang mới vào file `-wal`. Khi checkpoint diễn ra, các thay đổi mới được ghi về database chính. Nếu WAL còn giữ phiên bản trang trước khi xóa, ta có thể dựng lại trạng thái cũ của bảng.

Ở đây mình dựng snapshot sau từng transaction đã commit, rồi so sánh các `rowid`. Cách này giữ nguyên cấu trúc SQLite, thay vì mò từng chuỗi trong vùng byte của WAL.

WAL có header 32 byte. Mỗi frame gồm header 24 byte và một trang dữ liệu. Trước khi dùng frame cần kiểm tra salt và checksum; trường database size trong frame header khác 0 đánh dấu frame kết thúc transaction đã commit.

Với artifact này:

```text
Page size:                 4096
Số frame hợp lệ:              6
Số transaction đã commit:     3
```

Để dựng một snapshot, bắt đầu từ bản sao `chatapp.db`, áp các frame theo thứ tự cho tới mốc commit cần xét:

```python
start = (page_number - 1) * page_size
snapshot[start:start + page_size] = frame_page
```

Nếu cùng một trang được ghi nhiều lần, phiên bản sau ghi đè phiên bản trước. Sau mỗi commit, điều chỉnh kích thước snapshot theo số trang trong commit frame. Các frame chưa commit không được tính thành trạng thái hoàn chỉnh.

Mình mở từng snapshot ở chế độ chỉ đọc, không cho SQLite tự áp thêm WAL:

```python
sqlite3.connect(
    snapshot_path.resolve().as_uri() + "?mode=ro&immutable=1",
    uri=True,
)
```

So sánh các trạng thái cho kết quả:

| Trạng thái | Số dòng trong `messages` | Thay đổi |
| --- | ---: | --- |
| Database nền | 887 | — |
| Sau transaction 1 | 919 | Thêm 32 |
| Sau transaction 2 | 887 | Xóa 32 |
| Sau transaction 3 | 951 | Thêm 64 |

Nhóm cần lấy chính là 32 dòng có ở snapshot 1 nhưng biến mất ở snapshot 2:

```python
gone = set(previous_rows) - set(current_rows)
for rowid in gone:
    deleted[rowid] = previous_rows[rowid]
```

Tất cả ứng viên có body dạng Base64 một byte thuộc `thread_id = 5`. Đến đây mới có dữ liệu để xử lý phần mã hóa.

## Lọc và ghép ciphertext

Không ghép theo `rowid` hay thời gian hiển thị. Với mỗi tin nhắn đã khôi phục, tính:

```python
sortkey = row["timestamp"] ^ 931071618
```

Chỉ giữ tin nhắn có `sortkey % 3 == 0`, rồi sắp tăng dần theo `sortkey`. Body có dạng `Yw==`, `Xw==`…; giải mã Base64 mỗi body sẽ thu được một byte.

```python
selected = []
for row in deleted.values():
    body = row.get("body")
    if not isinstance(body, str) or not re.fullmatch(r"[A-Za-z0-9+/]{2}==", body):
        continue
    sortkey = row["timestamp"] ^ 931071618
    if sortkey % 3 == 0:
        selected.append((sortkey, row))

selected.sort(key=lambda item: item[0])
ciphertext = b"".join(
    base64.b64decode(row["body"])
    for _, row in selected
)
```

Sau khi lọc còn 16 tin nhắn. Các body theo đúng thứ tự là:

```text
Yw== Xw== yA== gg== mQ== 8w== qQ== Qw==
Xw== Mg== og== VQ== LA== fw== Pg== rA==
```

Ghép lại được ciphertext 16 byte:

```text
635fc88299f3a9435f32a2552c7f3eac
```

## Giải mã và kiểm tra kết quả

Salt phải được decode Base64 trước khi ghép với secret. Thứ tự cho kết quả đúng là:

```text
key = SHA256(UTF8(SECRET_MESSAGE) || Base64Decode(device_salt))
```

Đoạn dưới có thể chạy độc lập để kiểm tra bước giải mã:

```python
import base64
import hashlib
import zlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms

ciphertext = bytes.fromhex("635fc88299f3a9435f32a2552c7f3eac")
salt = base64.b64decode("bVaN8B8ekPGF5tPMwKoubg==")
secret = b"sqlite3_forensics_2026"
nonce = bytes.fromhex("706eeff3706eeff3706eeff3706eeff3")
key = hashlib.sha256(secret + salt).digest()

decryptor = Cipher(algorithms.ChaCha20(key, nonce), mode=None).decryptor()
plaintext = decryptor.update(ciphertext) + decryptor.finalize()
assert zlib.crc32(plaintext) & 0xffffffff == 0x706eeff3
print(plaintext.decode())
```

Ở đây truyền nguyên tham số 16 byte cho API ChaCha20 của `cryptography`. Tham số này bao gồm counter và nonce theo cách API đó định nghĩa; không tự cắt nó thành nonce 12 byte để chuyển sang thư viện khác.

Kết quả:

```text
W4l_1s_s0_c00l!!
CRC32 = 706eeff3
```

Giá trị CRC32 khớp nhóm 8 ký tự hex được lặp lại trong `NONCE_HEX`. Thử thứ tự `salt || secret` cho bản rõ rác và CRC32 khác, nên có thể loại ngay.

## Flag

```text
CSCV2026{W4l_1s_s0_c00l!!}
```

Mình đã chạy lại script trên database và WAL trong `artifact.zip`, xác nhận được cả số dòng qua từng snapshot, ciphertext và CRC32. Bản script đầy đủ: [for1.py](/downloads/cscv2026/for1.py).

Phần mình thấy hay ở bài này là 32 dòng đã biến mất khỏi bảng nhưng lịch sử trang vẫn còn. Có khóa đúng mà bỏ qua WAL thì vẫn chưa có ciphertext để giải.
