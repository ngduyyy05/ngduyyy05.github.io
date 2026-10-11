+++
title = "CyberDefenders - HireMe Lab Writeup"
date = 2026-10-11T00:00:00+07:00
draft = false
tags = ["CyberDefenders", "Windows Forensics", "Registry", "Email Forensics", "Chrome"]
categories = ["Writeups"]
summary = "Phân tích Registry, email Outlook, dữ liệu Chrome và tài liệu trên ổ đĩa để lần theo hoạt động của Karen trong lab HireMe."
ShowToc = true
TocOpen = false
+++

HireMe tập trung vào điều tra dữ liệu trên máy Windows của Karen. Bài viết lần theo thông tin hệ thống, trao đổi email với TAAUSAI, lịch sử tải xuống và tài liệu lưu trên ổ đĩa.

**Công cụ:** FTK Imager, công cụ đọc Registry, RECmd và OST Viewer.

| Artifact | Nội dung cần kiểm tra |
| --- | --- |
| `SAM`, `SYSTEM`, `SOFTWARE` | Tài khoản, cấu hình hệ thống và phần mềm |
| Outlook `.ost` | Nội dung trao đổi với TAAUSAI |
| Chrome `Web Data`, `History` | Thông tin người dùng và URL tải xuống |
| `AlpacaCare.docx` | Thời gian truy cập và nguồn nội dung |

## Q1: What is the administrator's username?

Cách nhanh nhất để tìm tên người dùng là kiểm tra thư mục `Users` trên phân vùng chứa Windows trong FTK Imager.

![Thư mục người dùng trên phân vùng Windows](/images/imported/hireme/hireme-01.png)

Có thể đối chiếu thêm với hive `SAM` trong thư mục `\Windows\System32\config`, tại nhánh:

```text
SAM\Domains\Account\Users
```

> **Đáp án:** `Karen`

## Q2: What is the OS's build number?

Xuất hive `SOFTWARE` từ `\Windows\System32\config`, mở bằng công cụ đọc Registry và kiểm tra nhánh:

```text
Microsoft\Windows NT\CurrentVersion
```

![Thông tin Windows build trong hive SOFTWARE](/images/imported/hireme/hireme-02.png)

> **Đáp án:** `16299`

## Q3: What is the hostname of the computer?

Xuất hive `SYSTEM` từ FTK Imager và mở bằng công cụ đọc Registry. Kiểm tra giá trị tên máy trong cấu hình hệ thống như ảnh dưới.

![Tên máy trong hive SYSTEM](/images/imported/hireme/hireme-03.png)

> **Đáp án:** `TOTALLYNOTAHACK`

## Q4: A messaging application was used to communicate with a fellow Alpaca enthusiast. What is the name of the software?

Kiểm tra dấu vết ứng dụng nhắn tin trong dữ liệu người dùng. Ảnh dưới ghi nhận ứng dụng **Skype**.

![Dấu vết ứng dụng Skype trên máy của Karen](/images/imported/hireme/hireme-04.png)

> **Đáp án:** `Skype`

## Q5: What is the zip code of the administrator's post?

Kiểm tra dữ liệu trình duyệt Chrome, cụ thể là tệp `Web Data` trong profile của Karen:

```text
[root]\Users\Karen\AppData\Local\Google\Chrome\User Data\Default\Web Data
```

![Thông tin mã bưu chính trong dữ liệu Chrome](/images/imported/hireme/hireme-05.png)

> **Đáp án:** `19709`

## Q6: What are the initials of the person who contacted the admin user from TAAUSAI?

Tìm tệp dữ liệu Outlook tại:

```text
[root]\Users\Karen\AppData\Local\Microsoft\Outlook\klovespizza@outlook.com.ost
```

![Tệp OST của Karen trong FTK Imager](/images/imported/hireme/hireme-06.png)

Xuất tệp và mở bằng **OST Viewer**, sau đó đọc các email liên quan đến TAAUSAI để xác định tên viết tắt của người liên hệ.

![Email từ người liên hệ của TAAUSAI](/images/imported/hireme/hireme-07.png)

> **Đáp án:** `MS`

## Q7: How much money was TAAUSAI willing to pay upfront?

Tiếp tục đọc cuộc trao đổi email và xác định số tiền mà TAAUSAI đề nghị trả trước.

![Email đề cập số tiền trả trước](/images/imported/hireme/hireme-08.png)

> **Đáp án:** `150000`

## Q8: What country is the admin user meeting the hacker group in?

Tìm thông tin địa điểm gặp mặt trong cuộc trao đổi.

![Thông tin địa điểm gặp mặt trong email](/images/imported/hireme/hireme-09.png)

Tọa độ được ghi nhận:

```text
27°22'50.10"N, 33°37'54.62"E
```

Đối chiếu tọa độ trên bản đồ để xác định quốc gia.

![Đối chiếu tọa độ với vị trí trên bản đồ](/images/imported/hireme/hireme-10.png)

> **Đáp án:** `Egypt`

## Q9: What is the machine's timezone? (Use the three-letter abbreviation)

Kiểm tra cấu hình múi giờ của máy trong dữ liệu hệ thống.

![Cấu hình múi giờ của máy](/images/imported/hireme/hireme-11.png)

> **Đáp án:** `UTC`

## Q10: When was AlpacaCare.docx last accessed?

Chọn `AlpacaCare.docx` trong FTK Imager và đọc trường **Date Accessed** trong phần thuộc tính tệp.

![Thời gian truy cập cuối của AlpacaCare.docx](/images/imported/hireme/hireme-12.png)

> **Đáp án:** `2019-03-17 21:52`

## Q11: There was a second partition on the drive. What is the letter assigned to it?

Đối chiếu thông tin phân vùng trong nhánh Registry:

```text
SYSTEM\MountedDevices
```

![Ánh xạ ký tự ổ đĩa trong MountedDevices](/images/imported/hireme/hireme-13.png)

> **Đáp án:** `A`

## Q12: Câu trả lời của Karen trong email

Quay lại chuỗi email **Interested in the job**. Trong thư phản hồi, Karen ghi rõ câu trả lời là `TheCardCriesNoMore`.

![Email của Karen ghi câu trả lời TheCardCriesNoMore](/images/imported/hireme/hireme-14.png)

> **Đáp án:** `TheCardCriesNoMore`

## Q13: What is the job position offered to Karen? (3 words, 2 spaces in between)

Đọc email phản hồi tiếp theo. Vị trí công việc được đề nghị cho Karen là **cyber security analyst**.

![Email đề nghị vị trí cyber security analyst](/images/imported/hireme/hireme-15.png)

> **Đáp án:** `cyber security analyst`

## Q14: When was the admin user password last changed?

Thông tin thay đổi mật khẩu nằm trong hive `SAM`. Xuất hive này từ bộ dữ liệu điều tra.

![Hive SAM được chọn để phân tích](/images/imported/hireme/hireme-16.png)

Phân tích bằng **RECmd** và kiểm tra thời điểm đổi mật khẩu của tài khoản quản trị.

![Kết quả phân tích thời gian thay đổi mật khẩu](/images/imported/hireme/hireme-17.png)

> **Đáp án:** `03/21/2019 19:13:09`

## Q15: What version of Chrome is installed on the machine?

Kiểm tra thông tin Google Chrome trong hive `SOFTWARE`, tại nhánh:

```text
SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Google Chrome
```

![Phiên bản Google Chrome trong Registry](/images/imported/hireme/hireme-18.png)

> **Đáp án:** `72.0.3626.121`

## Q16: What is the HostUrl of Skype?

Xuất tệp `History` của Chrome từ FTK Imager và kiểm tra dữ liệu tải xuống để tìm URL của bộ cài Skype.

```text
[root]\Users\Karen\AppData\Local\Google\Chrome\User Data\Default\History
```

![URL tải bộ cài Skype trong lịch sử Chrome](/images/imported/hireme/hireme-19.png)

> **Đáp án:** `https://download.skype.com/s4l/download/win/Skype-8.41.0.54.exe`

## Q17: What is the domain name of the website Karen browsed on Alpaca care that the file AlpacaCare.docx is based on?

Xuất `AlpacaCare.docx` từ FTK Imager để kiểm tra nội dung tài liệu.

![Tệp AlpacaCare.docx trong FTK Imager](/images/imported/hireme/hireme-21.png)

Đối chiếu nội dung và thông tin website được lưu trong tài liệu để xác định nguồn.

![Thông tin Palomino Alpaca Farm trong nội dung tài liệu](/images/imported/hireme/hireme-22.png)

> **Đáp án:** `palominoalpacafarm.com`

## Tổng hợp đáp án

| Câu | Đáp án |
| --- | --- |
| Q1 | `Karen` |
| Q2 | `16299` |
| Q3 | `TOTALLYNOTAHACK` |
| Q4 | `Skype` |
| Q5 | `19709` |
| Q6 | `MS` |
| Q7 | `150000` |
| Q8 | `Egypt` |
| Q9 | `UTC` |
| Q10 | `2019-03-17 21:52` |
| Q11 | `A` |
| Q12 | `TheCardCriesNoMore` |
| Q13 | `cyber security analyst` |
| Q14 | `03/21/2019 19:13:09` |
| Q15 | `72.0.3626.121` |
| Q16 | `https://download.skype.com/s4l/download/win/Skype-8.41.0.54.exe` |
| Q17 | `palominoalpacafarm.com` |

Cảm ơn bạn đã đọc!
