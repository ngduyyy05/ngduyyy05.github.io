+++
title = "CyberDefenders - KrakenKeylogger Lab Writeup"
date = 2026-10-09T00:01:00+07:00
draft = false
tags = ["CyberDefenders", "Windows Forensics", "Malware Analysis", "Persistence", "AnyDesk"]
categories = ["Writeups"]
summary = "Lần theo dấu vết Telegram, shortcut độc hại, cấu hình Greenshot và log AnyDesk để dựng lại chuỗi tấn công trong lab KrakenKeylogger."
ShowToc = true
TocOpen = false
+++

KrakenKeylogger tập trung vào việc lần theo dấu vết trên máy Windows: tin nhắn gửi tệp ZIP, shortcut tải mã độc giai đoạn hai, cơ chế duy trì truy cập qua Greenshot và phiên kết nối AnyDesk.

**Công cụ:** DB Browser for SQLite, VirusTotal và trình soạn thảo văn bản.

| Artifact | Mục đích phân tích |
| --- | --- |
| `wpndatabase.db` | Xác định ứng dụng nhắn tin và mật khẩu ZIP |
| `templet.lnk` | Tìm domain tải mã độc giai đoạn hai |
| `Greenshot.ini` | Xác định lệnh và đường dẫn phục vụ persistence |
| `ad.trace` | Truy vết địa chỉ IP trong phiên AnyDesk |

## Q1: Ứng dụng nhắn tin

*What is the web messaging app the employee used to talk to the attacker?*

Kiểm tra cơ sở dữ liệu Windows Push Notification để tìm thông báo liên quan đến cuộc trao đổi giữa nhân viên và kẻ tấn công.

1. Mở `wpndatabase.db` bằng **DB Browser for SQLite** và chọn bảng `Notification`.
2. Kiểm tra bản ghi **#20**. Cột `Payload` chứa thông báo ở dạng XML.
3. Đọc payload: tin nhắn đến từ **Nawaf**, nhắc đến tệp `our project templet test.zip`.
4. Đối chiếu URL attribution trong thông báo. Domain `web.telegram.org` xác định ứng dụng được sử dụng là **Telegram**.

![Bản ghi Notification chứa payload tin nhắn Telegram](/images/imported/krakenkeylogger/kraken-01.png)

> **Đáp án:** `telegram`

## Q2: Mật khẩu tệp ZIP

*What is the password for the protected ZIP file sent by the attacker to the employee?*

Tiếp tục đọc nội dung tin nhắn trong payload XML ở câu 1. Mật khẩu nằm ngay sau tên tệp ZIP:

```text
our project templet test.zip,pass:@1122d
```

![Nội dung tin nhắn chứa mật khẩu ZIP](/images/imported/krakenkeylogger/kraken-02.png)

Chuỗi sau `pass:` là mật khẩu cần dùng để giải nén.

> **Đáp án:** `@1122d`

## Q3: Domain tải mã độc giai đoạn hai

*What domain did the attacker use to download the second stage of the malware?*

Trong thư mục đã giải nén `Downloads/project templet test`, xác định shortcut **`templet.lnk`** và tính SHA-256 của tệp:

```text
beec3ec08fba224c161464ebcc64727912c6678dd452596440809ce99c8390fd
```

![Xác định shortcut templet.lnk và giá trị hash để tra cứu](/images/imported/krakenkeylogger/kraken-03.png)

Tra cứu hash trên **VirusTotal**, mở **Relations → Contacted URLs**. Kết quả ghi nhận URL dùng để tải payload giai đoạn hai:

```text
https://masherofmasters.cyou/chin/se1.hta
```

![VirusTotal hiển thị URL tải payload se1.hta](/images/imported/krakenkeylogger/kraken-04.png)

Tách hostname khỏi URL để lấy domain mà câu hỏi yêu cầu.

> **Đáp án:** `masherofmasters.cyou`

## Q4: Lệnh được chèn vào Greenshot

*What is the name of the command that the attacker injected using one of the installed LOLAPPS on the machine to achieve persistence?*

Rà soát thư mục `AppData\Roaming` của nạn nhân, xác định ứng dụng chụp màn hình **Greenshot** và kiểm tra tệp cấu hình `Greenshot.ini`.

Trong phần `[ExternalCommand]`, ngoài mục **MS Paint** còn có một lệnh mang tên bất thường: `jlhgfjhdflghjhuhuh`. Cấu hình của lệnh này gọi `cmd.exe` để chạy shortcut độc hại.

![Lệnh bất thường trong phần ExternalCommand của Greenshot.ini](/images/imported/krakenkeylogger/kraken-05.png)

Đây là tên lệnh được chèn vào ứng dụng hợp pháp để phục vụ cơ chế persistence trong bài lab.

> **Đáp án:** `jlhgfjhdflghjhuhuh`

## Q5: Đường dẫn tệp phục vụ persistence

*What is the complete path of the malicious file that the attacker used to achieve persistence?*

Tiếp tục kiểm tra tham số của lệnh vừa tìm thấy trong `Greenshot.ini`:

```ini
Argument.jlhgfjhdflghjhuhuh=/c "C:\Users\OMEN\AppData\Local\Temp\templet.lnk"
```

![Tham số Argument trỏ đến shortcut trong thư mục Temp](/images/imported/krakenkeylogger/kraken-06.png)

Đường dẫn nằm sau `/c` là tệp shortcut mà lệnh sẽ gọi.

> **Đáp án:** `C:\Users\OMEN\AppData\Local\Temp\templet.lnk`

## Q6: Ứng dụng phục vụ lấy cắp dữ liệu

*What is the name of the application the attacker utilized for data exfiltration?*

Kiểm tra các thư mục ứng dụng trong `AppData\Roaming` và xác định dấu vết của **AnyDesk**.

![Thư mục AnyDesk trong dữ liệu roaming của người dùng](/images/imported/krakenkeylogger/kraken-07.png)

Theo kết quả điều tra trong bài lab, AnyDesk là ứng dụng được sử dụng để truy cập từ xa và phục vụ lấy cắp dữ liệu. Log của ứng dụng là artifact cần kiểm tra tiếp để tìm địa chỉ kết nối.

> **Đáp án:** `AnyDesk`

## Q7: Địa chỉ IP của kẻ tấn công

*What is the IP address of the attacker?*

Mở tệp **`ad.trace`** trong thư mục AnyDesk, tìm các sự kiện đăng nhập và kết nối. Tại dòng **275**, log ghi nhận:

```text
anynet.any_socket - Logged in from 77.232.122.31:4026 on relay 872f8937.
```

![Dòng 275 trong ad.trace ghi nhận địa chỉ kết nối AnyDesk](/images/imported/krakenkeylogger/kraken-08.png)

Địa chỉ trước dấu `:` là IP cần tìm; `4026` là cổng trong bản ghi kết nối.

> **Đáp án:** `77.232.122.31`

## Tổng hợp đáp án

| Câu | Đáp án |
| --- | --- |
| Q1 | `telegram` |
| Q2 | `@1122d` |
| Q3 | `masherofmasters.cyou` |
| Q4 | `jlhgfjhdflghjhuhuh` |
| Q5 | `C:\Users\OMEN\AppData\Local\Temp\templet.lnk` |
| Q6 | `AnyDesk` |
| Q7 | `77.232.122.31` |
