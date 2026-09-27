+++
title = "HackTheBox - Reminiscent Notes"
date = 2026-09-27T09:20:00+07:00
draft = false
tags = ["HackTheBox", "Memory Forensic", "Email Forensic", "Volatility", "PowerShell", "Blue Team"]
categories = ["Writeups"]
summary = "Ghi chú tiếng Việt cho Reminiscent: từ email đính kèm resume.zip, lần theo LNK trong memory, decode PowerShell/Base64 và lấy flag."
ShowToc = true
TocOpen = false

[cover]
  image = "/images/hero-cyber-city.png"
  alt = "Cyber city forensic blog cover"
+++

> Nguồn tham khảo: [Odin - HackTheBox Reminiscent](https://odintheprotector.github.io/2023/09/20/hackthebox-reminiscent.html). Bài này viết lại flow điều tra để dễ đọc lại khi học memory/email forensic.

## Bối cảnh

Máy ảo của một recruiter có traffic đáng ngờ. Trước khi tách máy khỏi mạng, đội điều tra đã capture memory dump. Ngoài memory còn có email để đối chiếu.

Mô típ rất thực tế: nạn nhân nhận email tuyển dụng kèm “resume”, mở file đính kèm, rồi payload chạy qua PowerShell.

## Flow giải

### 1. Chọn profile đúng

Từ file `imageinfo.txt`, profile phù hợp là:

```text
Win2008R2SP1x64_23418
```

Khi chạy Volatility với profile này, `pslist` cho thấy process `powershell.exe` xuất hiện gần cuối danh sách. Đây là tín hiệu mạnh vì payload từ phishing attachment thường dùng PowerShell để tải/chạy stage tiếp theo.

### 2. Đọc email và xác định attachment

Email cho thấy file đính kèm tên:

```text
resume.zip
```

Quay lại memory dump, scan các file liên quan tới `resume.zip`. Bài gốc tìm thấy các object dạng:

```text
resume.zip.lnk
```

Đây là thủ pháp quen thuộc: người dùng tưởng mở zip/resume, nhưng thực chất kích hoạt shortcut `.lnk`.

### 3. Dump LNK và đọc string

Sau khi dump các file `.lnk`, dùng `strings` để xem nội dung. Trong LNK có một chuỗi Base64 rất dài. Decode lần đầu sẽ thu được PowerShell command.

Trong PowerShell command đó lại có thêm một chuỗi Base64 khác. Decode tiếp chuỗi thứ hai sẽ lấy được flag.

Flow ngắn gọn:

```text
memory dump -> filescan resume.zip.lnk -> dump file -> strings -> base64 decode -> PowerShell -> base64 decode -> flag
```

## Điểm học được

- Khi email có attachment, hãy dùng nội dung email làm keyword để quay lại memory.
- `.lnk` rất hay được dùng để che command line dài hoặc payload Base64.
- PowerShell command thường có nhiều lớp encode, đừng dừng ở lần decode đầu tiên.
- Process `powershell.exe` trong memory giúp xác nhận attachment đã được kích hoạt.

## Checklist làm lại

1. Chọn profile từ `imageinfo`.
2. Chạy `pslist` để tìm PowerShell hoặc process lạ.
3. Đọc email, lấy tên attachment làm keyword.
4. `filescan` keyword đó trong memory.
5. Dump file khả nghi.
6. Chạy `strings`, tìm Base64 hoặc command PowerShell.
7. Decode theo từng lớp cho tới khi ra nội dung cuối.
