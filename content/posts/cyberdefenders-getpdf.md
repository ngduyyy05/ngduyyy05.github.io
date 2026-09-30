+++
title = "CyberDefenders - GetPDF Walkthrough"
date = 2026-09-30T09:00:00+07:00
draft = false
tags = ["CyberDefenders", "Malware Analysis", "Network Forensics", "PDF", "Wireshark", "pdfid", "scdbg"]
categories = ["Writeups"]
summary = "GetPDF walkthrough ngắn gọn: phân tích PCAP, trích PDF độc hại, bóc JavaScript, tìm shellcode, payload và CVE liên quan."
ShowToc = true
TocOpen = false

[cover]
  image = "/images/imported/getpdf/cover.webp"
  alt = "CyberDefenders GetPDF cover"
+++

Lab GetPDF tập trung vào chuỗi tấn công qua PDF độc hại: nạn nhân truy cập trang bị chèn JavaScript, bị dẫn tới file PDF khai thác Adobe Reader, sau đó payload tải và chạy malware. Bài này chỉ giữ phần phân tích cần học, bỏ phần mô tả lab dài.

**Artifacts:** `lala.pcap`, PDF trích xuất từ HTTP traffic.  
**Tools:** Wireshark, `pdfid`, `peepdf`, PDFStreamDumper, CyberChef, `scdbg`.

![GetPDF tooling overview](/images/imported/getpdf/getpdf-01.png)

## Q1: How many URL path(s) are involved in this incident?

Mở `lala.pcap` bằng Wireshark và lọc HTTP request:

```wireshark
http.request
```

Đếm các URL path xuất hiện trong incident. Một số path có thể trùng request nhưng vẫn cần xem theo chuỗi truy cập.

![HTTP requests in Wireshark](/images/imported/getpdf/getpdf-02.jpg)

**Answer:** `6`

## Q2: What is the URL which contains the JS code?

Lọc các HTTP response rồi inspect body. Response đáng chú ý chứa HTML kèm thẻ `<script>`.

```wireshark
http.response
```

![HTTP response filter](/images/imported/getpdf/getpdf-03.jpg)

Trong HTTP stream, JavaScript nằm ở response của path forensic challenge.

![HTML response containing script](/images/imported/getpdf/getpdf-04.jpg)

**Answer:** `http://blog.honeynet.org.my/forensic_challenge/`

## Q3: What is the URL hidden in the JS code?

Export HTTP object chứa HTML/JS:

```text
File -> Export Objects -> HTTP
```

![Export HTTP object](/images/imported/getpdf/getpdf-05.png)

Beautify đoạn JavaScript để nhìn rõ luồng xử lý.

![Beautified obfuscated JavaScript](/images/imported/getpdf/getpdf-06.jpg)

Đoạn code bị obfuscate, nhưng biến cuối được truyền vào hàm thực thi. Log biến đó trong môi trường an toàn sẽ reveal URL ẩn.

![Logging decoded JavaScript variable](/images/imported/getpdf/getpdf-07.jpg)

![Decoded JavaScript output](/images/imported/getpdf/getpdf-08.jpg)

**Answer:** `http://blog.honeynet.org.my/forensic_challenge/getpdf.php`

## Q4: What is the MD5 hash of the PDF file contained in the packet?

Quay lại Wireshark, export HTTP objects và lưu file PDF được tải về.

![Export PDF object](/images/imported/getpdf/getpdf-09.jpg)

Tính MD5 của PDF đã export:

```powershell
Get-FileHash .\fcexploit.pdf -Algorithm MD5
```

![MD5 hash of PDF](/images/imported/getpdf/getpdf-10.jpg)

**Answer:** `659cf4c6baa87b082227540047538c2a`

## Q5: How many object(s) are contained inside the PDF file?

Dùng `pdfid` để thống kê object và indicator trong PDF.

```powershell
py -m pdfid .\fcexploit.pdf
```

![pdfid object count](/images/imported/getpdf/getpdf-11.jpg)

Các keyword như `/JS`, `/JavaScript`, `/OpenAction`, `/EmbeddedFile` là dấu hiệu PDF có nội dung cần phân tích sâu hơn.

![Suspicious PDF keywords](/images/imported/getpdf/getpdf-12.png)

**Answer:** `19`

## Q6: How many filtering schemes are used for the object streams?

Mở PDF bằng editor hoặc parser rồi tìm keyword `Filter`. Các filter cho biết stream cần decode theo cơ chế nào.

![PDF filters](/images/imported/getpdf/getpdf-13.jpg)

**Answer:** `4`

## Q7: What is the number of the object stream that might contain malicious JS code?

Dùng PDFStreamDumper để load PDF và duyệt các object. Object số `5` chứa JavaScript đáng ngờ.

![PDFStreamDumper object 5](/images/imported/getpdf/getpdf-14.png)

Beautify JS trong object này để đọc logic.

![Object 5 JavaScript beautified](/images/imported/getpdf/getpdf-15.png)

JS duyệt annotations và lấy dữ liệu từ metadata/object khác, nên cần lần tiếp sang các object được tham chiếu.

![peepdf object navigation](/images/imported/getpdf/getpdf-16.jpg)

![peepdf info output](/images/imported/getpdf/getpdf-17.jpg)

![peepdf info object](/images/imported/getpdf/getpdf-18.jpg)

Object `10` chứa chuỗi bị obfuscate bằng pattern thay thế.

![Object 10 obfuscated data](/images/imported/getpdf/getpdf-19.jpg)

Sau khi thay pattern bằng `0x`/decode trong CyberChef, sẽ ra đoạn JavaScript trung gian.

![CyberChef decode object data](/images/imported/getpdf/getpdf-20.jpg)

![Beautified intermediate JavaScript](/images/imported/getpdf/getpdf-21.png)

**Answer:** `5`

## Q8: What object streams contain the JS code responsible for executing the shellcodes?

Từ logic ở Q7, các pattern tiếp theo dẫn tới object `7` và `9`. Hai object này giữ hai phần của JavaScript chịu trách nhiệm tạo/executing shellcode.

![Object 7 shellcode JavaScript data](/images/imported/getpdf/getpdf-22.png)

![Object 9 shellcode JavaScript data](/images/imported/getpdf/getpdf-23.png)

Thay pattern bằng `%`, URL-decode hai phần rồi ghép lại.

![Decoded object stream](/images/imported/getpdf/getpdf-24.png)

![Combined decoded JavaScript](/images/imported/getpdf/getpdf-25.png)

**Answer:** `7,9`

## Q9: What is the full path of malicious executable files after being dropped?

Trong JavaScript đã ghép, payload shellcode nằm trong chuỗi `%uXXXX`. Trích chuỗi đó ra file text rồi chuyển `%uXXXX` thành bytes little-endian để có `shellcode.bin`.

![Extracting encoded shellcode](/images/imported/getpdf/getpdf-26.png)

![Writing shellcode bytes](/images/imported/getpdf/getpdf-27.png)

Sau khi có shellcode, emulate bằng `scdbg` trong môi trường phân tích:

```powershell
scdbg.exe /f shellcode.bin
```

![Running scdbg](/images/imported/getpdf/getpdf-28.png)

`scdbg` cho thấy shellcode gọi `URLDownloadToFileA`, ghi file vào thư mục system32 rồi chạy file đó.

![scdbg dropped executable path](/images/imported/getpdf/getpdf-29.png)

**Answer:** `c:\WINDOWS\system32\a.exe`

## Q10: What is the URL of the malicious executable dropped by CVE-2010-0188 shellcode?

Quay lại HTTP objects/requests trong PCAP. Có một executable được tải về với tên `the_real_malware.exe`.

![HTTP object for executable payload](/images/imported/getpdf/getpdf-30.png)

![Full request URL for malware](/images/imported/getpdf/getpdf-31.jpg)

**Answer:** `http://blog.honeynet.org.my/forensic_challenge/the_real_malware.exe`

## Q11: How many CVEs are included in the PDF file?

PDFStreamDumper/decoded JavaScript cho thấy có nhiều payload strings liên quan tới các exploit khác nhau; tổng số CVE cần trả lời là `5`.

![Payload string review](/images/imported/getpdf/getpdf-32.jpg)

![Exploit/CVE review](/images/imported/getpdf/getpdf-33.jpg)

![Final CVE count context](/images/imported/getpdf/getpdf-34.jpg)

**Answer:** `5`

## Final Answers

| Question | Answer |
|---|---|
| Q1 | `6` |
| Q2 | `http://blog.honeynet.org.my/forensic_challenge/` |
| Q3 | `http://blog.honeynet.org.my/forensic_challenge/getpdf.php` |
| Q4 | `659cf4c6baa87b082227540047538c2a` |
| Q5 | `19` |
| Q6 | `4` |
| Q7 | `5` |
| Q8 | `7,9` |
| Q9 | `c:\WINDOWS\system32\a.exe` |
| Q10 | `http://blog.honeynet.org.my/forensic_challenge/the_real_malware.exe` |
| Q11 | `5` |
