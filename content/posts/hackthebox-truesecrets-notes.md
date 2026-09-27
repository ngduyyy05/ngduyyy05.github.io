+++
title = "HackTheBox - TrueSecrets Notes"
date = 2026-09-27T09:10:00+07:00
draft = false
tags = ["HackTheBox", "Memory Forensic", "Volatility", "TrueCrypt", "Blue Team"]
categories = ["Writeups"]
summary = "Ghi chú tiếng Việt cho challenge TrueSecrets: dùng Volatility để tìm TrueCrypt volume, lấy mật khẩu, mount volume và giải mã session log."
ShowToc = true
TocOpen = false

[cover]
  image = "/images/hero-cyber-city.png"
  alt = "Cyber city forensic blog cover"
+++

## Ý tưởng chính

TrueSecrets là challenge memory forensic xoay quanh TrueCrypt. Mục tiêu không chỉ là tìm file volume, mà còn phải lấy được thông tin runtime trong memory để mở volume và đọc dữ liệu bên trong.

## Quy trình phân tích

### 1. Xác định profile và process

Bước đầu là chạy Volatility để nhận diện profile của memory dump. Bài gốc xác định đây là memory Windows 7, sau đó liệt kê process.

Trong danh sách process có vài dấu hiệu rất đáng chú ý:

- `TrueCrypt.exe`
- `7zFM.exe`
- console/process liên quan tới thao tác file

Khi thấy TrueCrypt trong memory dump, nên nghĩ ngay tới khả năng key/password vẫn còn trong RAM hoặc ít nhất metadata volume còn truy xuất được.

### 2. Tìm file liên quan tới backup

Tiếp theo, scan file object trong memory để tìm các tên liên quan tới dữ liệu backup. Hai file đáng chú ý là:

```text
development.tc
backup_development.zip
```

Sau khi dump file ra máy phân tích, cần kiểm tra lại bằng `file` hoặc tool tương đương. Extension trong memory không phải lúc nào cũng đáng tin, còn file dump đôi khi chỉ biết offset chứ không biết đúng loại file.

### 3. Lấy password TrueCrypt từ memory

Volatility 2 có plugin `truecryptsummary` để hiển thị thông tin TrueCrypt còn nằm trong RAM. Với challenge này, plugin giúp lấy được password để mount `development.tc`.

Sau khi mount volume, bên trong có:

- `AgentServer.cs`
- thư mục `sessions`

Đây là bước chuyển từ “tìm container” sang “hiểu dữ liệu attacker lưu trong container”.

## Phân tích AgentServer.cs

`AgentServer.cs` là một server C# lắng nghe kết nối từ agent ở port `40001`. Khi operator nhập command, server gửi command tới agent, nhận output rồi ghi vào log session.

Điểm quan trọng là log không lưu plaintext. Nội dung được mã hóa bằng DES trước khi append vào file `.log.enc`.

Các giá trị cần để giải mã nằm ngay trong source:

```text
key = AKaPdSgV
iv  = QeThWmYq
```

Vì DES dùng key/IV 8 byte, hai chuỗi này đủ để viết script decrypt hoặc dùng script có sẵn.

## Lấy flag

Sau khi decrypt các session log, bài gốc tìm thấy flag ở dòng cuối của file:

```text
de008160-66e4-4d51-8264-21cbc27661fc.log.enc
```

Điểm học được:

- Memory dump có thể chứa password TrueCrypt còn dùng được.
- Khi tìm thấy encrypted volume, đừng brute-force vội; hãy kiểm tra plugin chuyên dụng trước.
- Source code trong artifact thường cho luôn thuật toán và key material.
- Session log mã hóa vẫn là log; nếu có key/IV thì timeline command của attacker sẽ lộ ra rất nhanh.

## Ảnh chụp phân tích

![TrueSecrets profile check](/images/imported/hackthebox-truesecrets/01.png)
![TrueSecrets process list](/images/imported/hackthebox-truesecrets/02.png)
![TrueSecrets console artifact](/images/imported/hackthebox-truesecrets/03.png)
![TrueSecrets file scan](/images/imported/hackthebox-truesecrets/04.png)
![TrueSecrets truecryptsummary](/images/imported/hackthebox-truesecrets/05.png)
![TrueSecrets mounted volume](/images/imported/hackthebox-truesecrets/06.png)
![TrueSecrets decrypted session](/images/imported/hackthebox-truesecrets/07.png)

## Checklist làm lại

1. `imageinfo` hoặc plugin tương đương để chọn profile.
2. `pslist`/`pstree` để nhìn process lạ.
3. `filescan` tìm volume/archive/session.
4. Dump file ra ngoài và xác định loại file thật.
5. Dùng `truecryptsummary` nếu có TrueCrypt.
6. Mount volume, đọc source/config, rồi decrypt log.
