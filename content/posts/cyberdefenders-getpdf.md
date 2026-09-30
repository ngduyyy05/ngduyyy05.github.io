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

![GetPDF tooling overview](https://miro.medium.com/v2/resize:fit:700/1*0Mkt_OQWUDbNa9hprJEv9A.png)

## Q1: How many URL path(s) are involved in this incident?

Mở `lala.pcap` bằng Wireshark và lọc HTTP request:

```wireshark
http.request
```

Đếm các URL path xuất hiện trong incident. Một số path có thể trùng request nhưng vẫn cần xem theo chuỗi truy cập.

![HTTP requests in Wireshark](https://miro.medium.com/v2/resize:fit:700/1*OXoZByxPPKgNhPNraOZoLQ.jpeg)

**Answer:** `6`

## Q2: What is the URL which contains the JS code?

Lọc các HTTP response rồi inspect body. Response đáng chú ý chứa HTML kèm thẻ `<script>`.

```wireshark
http.response
```

![HTTP response filter](https://miro.medium.com/v2/resize:fit:700/1*LUAyFPjjzp9uTwVU-xtC9A.jpeg)

Trong HTTP stream, JavaScript nằm ở response của path forensic challenge.

![HTML response containing script](https://miro.medium.com/v2/resize:fit:700/1*FTME1lAujwHwegfaSik77A.jpeg)

**Answer:** `http://blog.honeynet.org.my/forensic_challenge/`

## Q3: What is the URL hidden in the JS code?

Export HTTP object chứa HTML/JS:

```text
File -> Export Objects -> HTTP
```

![Export HTTP object](https://miro.medium.com/v2/resize:fit:700/1*mi-QHzWHDupLHtfRx47pvA.png)

Beautify đoạn JavaScript để nhìn rõ luồng xử lý.

![Beautified obfuscated JavaScript](https://miro.medium.com/v2/resize:fit:700/1*eUkNpo05M94h1PcZv69kog.jpeg)

Đoạn code bị obfuscate, nhưng biến cuối được truyền vào hàm thực thi. Log biến đó trong môi trường an toàn sẽ reveal URL ẩn.

![Logging decoded JavaScript variable](https://miro.medium.com/v2/resize:fit:700/1*j5l2W0eq4t4vHytAR2J1TQ.jpeg)

![Decoded JavaScript output](https://miro.medium.com/v2/resize:fit:700/1*QbO3wW826-HoZgH5V7GTRQ.jpeg)

**Answer:** `http://blog.honeynet.org.my/forensic_challenge/getpdf.php`

## Q4: What is the MD5 hash of the PDF file contained in the packet?

Quay lại Wireshark, export HTTP objects và lưu file PDF được tải về.

![Export PDF object](https://miro.medium.com/v2/resize:fit:700/1*wBUpCPJY0-KkEOFraL4PJQ.jpeg)

Tính MD5 của PDF đã export:

```powershell
Get-FileHash .\fcexploit.pdf -Algorithm MD5
```

![MD5 hash of PDF](https://miro.medium.com/v2/resize:fit:700/1*U1lAFGmVMKwxjbMIWHX3wg.jpeg)

**Answer:** `659cf4c6baa87b082227540047538c2a`

## Q5: How many object(s) are contained inside the PDF file?

Dùng `pdfid` để thống kê object và indicator trong PDF.

```powershell
py -m pdfid .\fcexploit.pdf
```

![pdfid object count](https://miro.medium.com/v2/resize:fit:700/1*JYEQnv0DxI_M89pb1jRtEg.jpeg)

Các keyword như `/JS`, `/JavaScript`, `/OpenAction`, `/EmbeddedFile` là dấu hiệu PDF có nội dung cần phân tích sâu hơn.

![Suspicious PDF keywords](https://miro.medium.com/v2/resize:fit:700/1*JVUImvpCcZkKM0q9PqXr7Q.png)

**Answer:** `19`

## Q6: How many filtering schemes are used for the object streams?

Mở PDF bằng editor hoặc parser rồi tìm keyword `Filter`. Các filter cho biết stream cần decode theo cơ chế nào.

![PDF filters](https://miro.medium.com/v2/resize:fit:700/1*4ES2B59UCkOEE2XMHc_EIQ.jpeg)

**Answer:** `4`

## Q7: What is the number of the object stream that might contain malicious JS code?

Dùng PDFStreamDumper để load PDF và duyệt các object. Object số `5` chứa JavaScript đáng ngờ.

![PDFStreamDumper object 5](https://miro.medium.com/v2/resize:fit:700/1*mDkFw5MnhglDeOIJy7ZUrw.png)

Beautify JS trong object này để đọc logic.

![Object 5 JavaScript beautified](https://miro.medium.com/v2/resize:fit:700/1*0nuCrRAeD2zpBqN3xcCmUw.png)

JS duyệt annotations và lấy dữ liệu từ metadata/object khác, nên cần lần tiếp sang các object được tham chiếu.

![peepdf object navigation](https://miro.medium.com/v2/resize:fit:700/1*znbn_0y4hf-CYZF5fD5u5g.jpeg)

![peepdf info output](https://miro.medium.com/v2/resize:fit:287/1*h-ibhAy3l24l5jKAoLox3w.jpeg)

![peepdf info object](https://miro.medium.com/v2/resize:fit:700/1*_bChGuROAsYIDg_CBQ5vzA.jpeg)

Object `10` chứa chuỗi bị obfuscate bằng pattern thay thế.

![Object 10 obfuscated data](https://miro.medium.com/v2/resize:fit:650/1*wSidI63JsnLecJmc9Ot4tw.jpeg)

Sau khi thay pattern bằng `0x`/decode trong CyberChef, sẽ ra đoạn JavaScript trung gian.

![CyberChef decode object data](https://miro.medium.com/v2/resize:fit:700/1*ml-QvVTBE561E6LtFOHRgQ.jpeg)

![Beautified intermediate JavaScript](https://miro.medium.com/v2/resize:fit:392/1*6sTviF7v-BdAPlbWeJn2EA.png)

**Answer:** `5`

## Q8: What object streams contain the JS code responsible for executing the shellcodes?

Từ logic ở Q7, các pattern tiếp theo dẫn tới object `7` và `9`. Hai object này giữ hai phần của JavaScript chịu trách nhiệm tạo/executing shellcode.

![Object 7 shellcode JavaScript data](https://miro.medium.com/v2/resize:fit:700/1*wsHy9pnryN-S1m-97Qftzw.png)

![Object 9 shellcode JavaScript data](https://miro.medium.com/v2/resize:fit:700/1*Y99iBgbHFOnACzwIYksclA.png)

Thay pattern bằng `%`, URL-decode hai phần rồi ghép lại.

![Decoded object stream](https://miro.medium.com/v2/resize:fit:700/1*eS0XF8iT8k_WcmgSkGEkkQ.png)

![Combined decoded JavaScript](https://miro.medium.com/v2/resize:fit:700/1*uxb3VSzDPkVbsdI0na04_w.png)

**Answer:** `7,9`

## Q9: What is the full path of malicious executable files after being dropped?

Trong JavaScript đã ghép, payload shellcode nằm trong chuỗi `%uXXXX`. Trích chuỗi đó ra file text rồi chuyển `%uXXXX` thành bytes little-endian để có `shellcode.bin`.

![Extracting encoded shellcode](https://miro.medium.com/v2/resize:fit:700/1*-GG32eMRjH4SSPz4pzfuZg.png)

![Writing shellcode bytes](https://miro.medium.com/v2/resize:fit:700/1*jtUJbOTGH_SEzSDjvur9PA.png)

Sau khi có shellcode, emulate bằng `scdbg` trong môi trường phân tích:

```powershell
scdbg.exe /f shellcode.bin
```

![Running scdbg](https://miro.medium.com/v2/resize:fit:700/1*e35w-UIo3ADSRBl_L8WzWw.png)

`scdbg` cho thấy shellcode gọi `URLDownloadToFileA`, ghi file vào thư mục system32 rồi chạy file đó.

![scdbg dropped executable path](https://miro.medium.com/v2/resize:fit:700/1*4hvsYouuya0rcpupryFwbQ.png)

**Answer:** `c:\WINDOWS\system32\a.exe`

## Q10: What is the URL of the malicious executable dropped by CVE-2010-0188 shellcode?

Quay lại HTTP objects/requests trong PCAP. Có một executable được tải về với tên `the_real_malware.exe`.

![HTTP object for executable payload](https://miro.medium.com/v2/resize:fit:700/1*mlfR5thmlSIrFNJSol5wFg.png)

![Full request URL for malware](https://miro.medium.com/v2/resize:fit:700/1*UvdJl12R2NBtt0HQQi2s_A.jpeg)

**Answer:** `http://blog.honeynet.org.my/forensic_challenge/the_real_malware.exe`

## Q11: How many CVEs are included in the PDF file?

PDFStreamDumper/decoded JavaScript cho thấy có nhiều payload strings liên quan tới các exploit khác nhau; tổng số CVE cần trả lời là `5`.

![Payload string review](https://miro.medium.com/v2/resize:fit:700/1*5jEcbseGFTUuqixMmV0L_A.jpeg)

![Exploit/CVE review](https://miro.medium.com/v2/resize:fit:700/1*CvotVCIhZQrTyjT0r-AOlg.jpeg)

![Final CVE count context](https://miro.medium.com/v2/resize:fit:700/1*W4Hiujn2if84jFgC4ga-vw.jpeg)

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
