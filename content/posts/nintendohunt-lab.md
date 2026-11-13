+++
title = "NintendoHunt Lab Writeup"
date = 2026-11-13T00:00:00+07:00
draft = false
tags = ["Memory Forensics", "Volatility", "Windows", "NTFS", "Alternate Data Streams", "CyberChef"]
categories = ["Writeups"]
summary = "Phân tích bộ nhớ Windows bằng Volatility 2: xác định tiến trình đáng ngờ, giải mã hash ẩn trong bộ nhớ và truy tìm dấu vết registry, ADS, browser cache."
ShowToc = true
TocOpen = false
+++

NintendoHunt là bài lab phân tích bộ nhớ Windows. Từ file `memdump.mem`, mình sử dụng **Volatility 2.6.1**, `strings`, `grep` và CyberChef để lần theo tiến trình đáng ngờ, dữ liệu ẩn trong bộ nhớ và các dấu vết trên hệ thống.

## Q1: What is the process ID of the currently running malicious process?

Trước khi phân tích tiến trình, cần xác định profile phù hợp với bản dump. Volatility 2 sử dụng profile để diễn giải các cấu trúc dữ liệu của hệ điều hành.

Chạy plugin `imageinfo` để xem các profile được đề xuất:

```bash
python2 vol.py -f memdump.mem imageinfo
```

![Plugin imageinfo đề xuất profile Win10x64_17134](/images/imported/nintendohunt/image1.png)

Trong bài này, mình chọn `Win10x64_17134` và sử dụng profile đó cho các lệnh tiếp theo.

Để kiểm tra quan hệ cha–con giữa các tiến trình, chạy `pstree`:

```bash
python2 vol.py -f memdump.mem --profile=Win10x64_17134 pstree
```

![Cây tiến trình cho thấy svchost.exe PID 8560 là con của explorer.exe PID 4824](/images/imported/nintendohunt/image2.png)

Kết quả cho thấy `explorer.exe` có PID `4824` sinh ra tiến trình `svchost.exe` có PID `8560`.

Đây là quan hệ đáng ngờ: `svchost.exe` thông thường được khởi chạy bởi `services.exe` để lưu trữ các dịch vụ Windows. Trong cây tiến trình này, nó lại là con trực tiếp của `explorer.exe`, gợi ý một chương trình được khởi chạy trong phiên làm việc của người dùng và mang tên giống tiến trình hệ thống.

> **Đáp án:** `8560`

## Q2: What is the md5 hash hidden in the malicious process memory?

Sau khi xác định PID, dùng `memdump` để trích xuất bộ nhớ của tiến trình `8560`:

```bash
mkdir -p dump
python2 vol.py -f memdump.mem --profile=Win10x64_17134 memdump -p 8560 -D dump
```

Tiếp theo, trích xuất các chuỗi có thể đọc được và tìm trường `contents`:

```bash
strings dump/8560.dmp > 8560string.txt
grep -in "contents" 8560string.txt
```

![Chuỗi trong bộ nhớ tiến trình chứa trường contents và giá trị Base64 sau t.h.e. fl.ag.is.](/images/imported/nintendohunt/image3.png)

Trong đầu ra có trường `contents` chứa chuỗi `t.h.e. fl.ag.is.` và một giá trị Base64:

```text
M2ExOTY5N2YyOTA5NWJjMjg5YTk2ZTQ1MDQ2Nzk2ODA=
```

Đưa chuỗi này vào CyberChef và áp dụng recipe **From Base64**:

![CyberChef giải mã Base64 thành chuỗi MD5](/images/imported/nintendohunt/image4.png)

Kết quả là chuỗi hash cần tìm:

```text
3a19697f29095bc289a96e4504679680
```

> **Đáp án:** `3a19697f29095bc289a96e4504679680`

## Q3: What is the process name of the malicious process parent?

Từ kết quả `pstree` ở Q1, tiến trình `svchost.exe` có PID `8560` và PPID `4824`. PID `4824` tương ứng với `explorer.exe`.

Quan hệ cha–con được thể hiện như sau:

```text
explorer.exe (PID 4824)
└── svchost.exe (PID 8560, PPID 4824)
```

> **Đáp án:** `explorer.exe`

## Q4: What is the MAC address of this machine's default gateway?

Thông tin mạng đã lưu có thể được tìm trong registry. Mình sử dụng plugin `printkey` để kiểm tra đường dẫn sau trong hive `SOFTWARE`:

```text
Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Unmanaged
```

Lệnh truy vấn khóa:

```bash
python2 vol.py -f memdump.mem --profile=Win10x64_17134 printkey \
  -K 'Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Unmanaged'
```

Tiếp tục kiểm tra subkey của chữ ký mạng bằng cách thêm tên subkey vào đường dẫn truyền cho `-K`. Trong kết quả của subkey tương ứng, trường `DefaultGatewayMac` có kiểu `REG_BINARY` và chứa sáu byte:

```text
00 50 56 fe d8 07
```

![Giá trị DefaultGatewayMac trong registry là 00 50 56 fe d8 07](/images/imported/nintendohunt/image5.png)

Viết lại sáu byte theo định dạng địa chỉ MAC, ta được:

> **Đáp án:** `00:50:56:FE:D8:07`

## Q5: What is the name of the file that is hidden in the alternative data stream?

NTFS hỗ trợ **Alternate Data Streams (ADS)**, cho phép một file có các luồng dữ liệu được đặt tên bên cạnh luồng dữ liệu mặc định. Dữ liệu trong các luồng bổ sung có thể bị bỏ qua nếu chỉ kiểm tra nội dung chính của file.

Để tìm dấu vết ADS trong bản dump, sử dụng `mftparser` và lọc các dòng chứa `DATA ADS`:

```bash
python2 vol.py -f memdump.mem --profile=Win10x64_17134 mftparser \
  | grep -i "DATA ADS"
```

![Kết quả mftparser liệt kê ADS mang tên yes.txt](/images/imported/nintendohunt/image6.png)

Đầu ra liệt kê các tên như `$Bad`, `$Max`, `Zone.Identifier` và `yes.txt`. Mục cần tìm trong bài lab là:

```text
$DATA ADS Name: yes.txt
```

> **Đáp án:** `yes.txt`

## Q6: What is the full path of the browser cache created when the user visited "www.13cubed.com"?

Tiếp tục dùng `mftparser`, lần này lọc các bản ghi chứa chuỗi `13cubed`:

```bash
python2 vol.py -f memdump.mem --profile=Win10x64_17134 mftparser \
  | grep -i "13cubed"
```

![Các bản ghi MFT chứa file cache 13cubed[1].htm và 13cubed[1].png](/images/imported/nintendohunt/image7.png)

Kết quả cho thấy các file cache liên quan đến tên miền mục tiêu, trong đó có `13cubed[1].htm` với dấu thời gian `2018-08-01 19:29:27 UTC+0000`. Bản ghi này chứa đường dẫn cần tìm; các thành phần như `MICROS~1.MIC` và `MICROS~1` được giữ nguyên theo dạng tên ngắn xuất hiện trong kết quả.

> **Đáp án:**

```text
C:\Users\CTF\AppData\Local\Packages\MICROS~1.MIC\AC\#!001\MICROS~1\Cache\AHF2COV9\13cubed[1].htm
```
