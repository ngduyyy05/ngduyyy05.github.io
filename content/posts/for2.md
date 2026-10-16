+++
title = "for2 — CSCV2026 vòng chung khảo"
date = 2026-10-16T22:01:00+07:00
draft = false
tags = ["CSCV2026", "Forensics", "NTFS", "USN Journal", "MFT", "FTK Imager"]
categories = ["Writeups"]
summary = "Dựng lại đường dẫn file đã xóa từ USN Journal khi vùng trống bị ghi đè và các MFT record đã bị tái sử dụng."
ShowToc = true
TocOpen = false
+++

Đề cho ảnh `raw.E01` của một phân vùng dữ liệu. Máy đã bị xâm nhập, dữ liệu bị xóa và toàn bộ vùng trống bị ghi đè. Yêu cầu là tìm đường dẫn đầy đủ của một file text quan trọng từng tồn tại trên phân vùng.

Đề chỉ hỏi đường dẫn, nên chưa cần khôi phục nội dung file. Mình bắt đầu với metadata NTFS và nhật ký thay đổi.

## Kiểm tra ảnh và đọc MFT

SHA-256 của `raw.E01`:

```text
c98969cbd394ae92f9bf449c1657e7b230a9050daa953dc04950657ee5bd7e24
```

Trên PowerShell có thể kiểm tra bằng:

```powershell
Get-FileHash .\raw.E01 -Algorithm SHA256
```

Ảnh chứa trực tiếp một volume NTFS, cluster size 4096 byte. Mình đọc ảnh ở chế độ chỉ đọc, không chạy các executable bên trong.

MFT còn nhiều bản ghi file đã xóa, ví dụ `Contract appendix 13.txt` và `Rollout plan 5.txt`. Tuy nhiên, một số đường dẫn bị đứt ở thư mục cha. Đáng chú ý hơn, phía sau có cả loạt thư mục như `Recovered`, `audit_26`, `secure_DD`… Điều này khiến tên hiện tại trong MFT chưa đủ để kết luận cây thư mục cũ.

Trong NTFS, file reference gồm **số MFT record và sequence number**. Khi một slot được tái sử dụng, sequence thay đổi. Cùng record 126 nhưng sequence 1 và sequence 2 là hai đời bản ghi khác nhau.

## Chuyển sang USN Journal

Nhật ký nằm ở:

```text
\$Extend\$UsnJrnl:$J
```

`$J` là named stream của `$UsnJrnl`; nó không phải một file độc lập ngang hàng với `$UsnJrnl` trong thư mục `$Extend`. Stream `$Max` chứa thông tin cấu hình, còn dữ liệu các sự kiện nằm trong `$J`.

Trong lần giải này mình đọc stream trực tiếp từ E01 bằng Dissect, xuất danh sách USN ra JSON để lọc. Nếu làm bằng bộ công cụ GUI/CLI quen thuộc thì quy trình tương đương là:

1. Mở E01 trong FTK Imager bằng **File → Add Evidence Item → Image File**.
2. Xuất `$MFT` và named stream `$J` của `$Extend\$UsnJrnl` ra thư mục phân tích riêng. Cách chọn stream có thể khác giữa các phiên bản FTK; cần kiểm tra đúng dữ liệu `$J`, tránh lấy unnamed stream trống.
3. Parse bằng MFTECmd, rồi mở CSV trong Timeline Explorer.

Ví dụ, nếu đã lưu stream dưới tên `UsnJrnl_J.bin`:

```powershell
.\MFTECmd.exe -f 'D:\case\$MFT' --csv 'D:\case\csv' --csvf mft.csv
.\MFTECmd.exe -f 'D:\case\UsnJrnl_J.bin' --csv 'D:\case\csv' --csvf usn.csv
```

Tên cột có thể khác theo phiên bản parser. Các trường cần giữ là filename, file record/sequence, parent record/sequence, timestamp và reason.

## Tìm file text đã mất dấu trong MFT

Lọc các tên `.txt` trong USN, ngoài file của WinRAR và các tài liệu thông thường còn có:

```text
playlist_balladsong.txt
```

Tên này không còn xuất hiện trong danh sách MFT hiện tại. Nhật ký lại giữ đủ các lần tạo, sửa và xóa của nó:

| Sự kiện | Thời gian UTC | File reference | Parent reference |
| --- | --- | --- | --- |
| Tạo file | 2026-09-07 04:18:47 | 130:1 | 129:1 |
| Xóa file | 2026-09-07 04:54:23 | 130:1 | 129:1 |

Reason của sự kiện xóa là `0x80000200`: `CLOSE` kết hợp `FILE_DELETE`.

Để dựng đường dẫn, bắt đầu với parent `129:1`, tìm bản ghi USN có file reference tương ứng, lấy tên thư mục rồi tiếp tục với parent của nó. Không tra mỗi số 129 trong MFT hiện tại, vì slot đó đã có thể thuộc về thư mục khác.

## Nối lại chuỗi thư mục cha

Các sự kiện tạo cho ta chuỗi sau. Offset tính từ đầu stream `$J` đã xuất, không phải từ đầu file E01:

| Offset hex | Tên | Record:sequence | Parent |
| --- | --- | --- | --- |
| `FF50` | `playlist_balladsong.txt` | 130:1 | 129:1 |
| `FEC0` | `ops_7B` | 129:1 | 128:1 |
| `FE20` | `vault_CA` | 128:1 | 127:1 |
| `FD80` | `proj_F3` | 127:1 | 126:1 |
| `FCE0` | `legal_14` | 126:1 | 125:1 |
| `FC40` | `Archive` | 125:1 | 5:5 |

Record 5 là thư mục gốc. Ghép từ gốc xuống được:

```text
\Archive\legal_14\proj_F3\vault_CA\ops_7B\playlist_balladsong.txt
```

Có thể kiểm tra thủ công bằng hex editor. Ở bản ghi `FF50`, trường File Reference tại `+0x08` và Parent Reference tại `+0x10` là:

```text
File:    82 00 00 00 00 00 01 00
Parent:  81 00 00 00 00 00 01 00
```

Với USN v2, sáu byte thấp biểu diễn số record, hai byte cao biểu diễn sequence, theo little-endian. Vì vậy hai giá trị trên lần lượt là `130:1` và `129:1`.

Điểm dễ nối nhầm nhất là record 126. Nhật ký cho thấy:

```text
126:1  legal_14
126:2  Recovered
```

Ngay sau khi cây thư mục cũ bị xóa, record này được dùng lại cho `Recovered`. Nếu bỏ qua sequence thì đường dẫn dựng ra sẽ chứa tên thư mục chưa tồn tại vào lúc file mục tiêu được tạo.

## Lấy ký tự ổ đĩa từ Recycle Bin

Chuỗi trên mới là đường dẫn tính từ gốc volume. Để thêm drive letter, mình kiểm tra metadata `$I` trong Recycle Bin:

```text
\$RECYCLE.BIN\S-1-5-21-4021386281-1410677034-1276173017-1001\$ITRUADM.xlsx
```

File này giữ đường dẫn trước khi một tài liệu khác được chuyển vào thùng rác:

```text
E:\Works\Reports\Q3_security_report_KEY-B7C53EF8.xlsx
```

Đây là dấu vết cho thấy volume dữ liệu từng được gán ký tự `E:`. Nó nằm trong ảnh thu được, không phải ký tự ổ trên máy đang phân tích.

## Flag

```text
CSCV2026{E:\Archive\legal_14\proj_F3\vault_CA\ops_7B\playlist_balladsong.txt}
```

Mình lưu riêng [các bản ghi USN liên quan](/downloads/cscv2026/for2-target-records.json) để đối chiếu các reference và thời điểm. Đường dẫn trên được dựng từ metadata trong ảnh; mình chưa có kết quả nộp lên hệ thống chấm.

Ghi đè vùng trống đã làm hướng carve nội dung kém hữu ích, nhưng `$J` vẫn giữ lịch sử tên và thư mục cha. Phần quyết định ở bài này là đọc đúng đời bản ghi, thay vì tin vào tên hiện tại trong MFT.
