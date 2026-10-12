+++
title = "CyberDefenders - l337 S4uc3 Lab Writeup"
date = 2026-10-12T00:00:00+07:00
draft = false
tags = ["CyberDefenders", "Network Forensics", "Memory Forensics", "Wireshark", "Volatility", "Linux", "Zeus"]
categories = ["Writeups"]
summary = "Phân tích PCAP và bộ nhớ Linux để truy vết Zeus, truy cập WordPress và shell được sinh từ phiên Meterpreter."
ShowToc = true
TocOpen = false
+++

Lab l337 S4uc3 kết hợp phân tích lưu lượng mạng với bộ nhớ Linux. Mục tiêu là xác định các máy liên quan, lần theo hoạt động của Zeus, kiểm tra truy cập vào website và đối chiếu dấu vết shell trong memory dump.

| Artifact | Vai trò |
| --- | --- |
| `GrrCON.pcapng` | HTTP, kết nối C2, đăng nhập và dữ liệu phiên tấn công |
| `IR-Alert.png` | Cảnh báo IDS và các địa chỉ liên quan |
| `webserver.vmss` | Tiến trình, vùng nhớ và packet queue của webserver |
| Profile `LinuxDFIRwebsvrx64` | Diễn giải cấu trúc bộ nhớ Linux bằng Volatility 2 |

**Công cụ:** Wireshark, Volatility 2 và `md5sum`.

**Quy ước thời gian:** đáp án thời gian trong bài dùng UTC. Một số ảnh hiển thị UTC+7, nên phải đổi cả ngày lẫn giờ khi đối chiếu. Ảnh chụp là kết quả thực hành; bài không giả định đã chạy lại PCAP hoặc memory dump trong lần biên tập này.

## Q1: Public IP của webserver

Website cần điều tra là `development.wse.local`. Bắt đầu từ HTTP để tìm địa chỉ nội bộ của server, sau đó kiểm tra các request liên quan:

```wireshark
http.host == "development.wse.local"
```

```wireshark
http.request && ip.addr == 172.16.0.108
```

Trong ảnh, frame 617 gửi đến IP nội bộ `172.16.0.108`, nhưng HTTP header `Host` và trường `Full request URI` chứa `74.204.41.73`. Đây là địa chỉ public được dùng để truy cập webserver trong bài lab; không lấy IP nội bộ ở cột Destination làm đáp án.

![HTTP Host và Full request URI của webserver](/images/imported/l337-s4uc3/l337-01.png)

> **Đáp án:** `74.204.41.73`

## Q2: Arrival time của frame 1

Mở **Statistics → Capture File Properties** để xem thời điểm gói đầu tiên. Có thể kiểm tra trực tiếp frame bằng:

```wireshark
frame.number == 1
```

Ảnh ghi `2013-09-11 05:51:07` theo UTC+7. Trừ 7 giờ được `2013-09-10 22:51:07 UTC`. Khi đọc chi tiết frame, giữ phần giây theo yêu cầu thay vì làm tròn phần thập phân lên giây kế tiếp.

![Capture File Properties và thời điểm gói đầu tiên](/images/imported/l337-s4uc3/l337-02.png)

> **Đáp án:** `22:51:07 UTC`

## Q3: Phiên bản PHP

Chọn request đến website và mở **Follow → HTTP Stream**. Phiên bản PHP xuất hiện trong response header `X-Powered-By`:

```http
X-Powered-By: PHP/5.3.2-1ubuntu4.20
```

Đáp án cần phiên bản PHP chính, không kèm hậu tố gói Ubuntu.

![Response header tiết lộ phiên bản PHP và Apache](/images/imported/l337-s4uc3/l337-03.png)

> **Đáp án:** `5.3.2`

## Q4: Phiên bản Apache

Dùng cùng HTTP response ở Q3. Header `Server` cho biết phần mềm webserver và phiên bản được công bố:

```http
Server: Apache/2.2.14 (Ubuntu)
```

Chỉ lấy số phiên bản Apache; đây là thông tin từ banner HTTP, không phải kết quả kiểm kê package trên máy.

> **Đáp án:** `2.2.14`

## Q5: Malware được IDS cảnh báo

Mở `IR-Alert.png` và đọc tên signature. Cảnh báo nhắc đến **Zeus**, vì vậy đây là tên malware mà câu hỏi yêu cầu, không phải tên file tải xuống hay một địa chỉ IP.

![Cảnh báo IDS liên quan đến Zeus](/images/imported/l337-s4uc3/l337-04.png)

> **Đáp án:** `Zeus`

## Q6: Gateway của LAN

Địa chỉ gateway trong bài là `172.16.0.1`. Ảnh cho thấy địa chỉ này trao đổi với webserver, nhưng chỉ riêng một cuộc hội thoại HTTP chưa đủ chứng minh vai trò gateway.

![Lưu lượng giữa 172.16.0.1 và các máy trong LAN](/images/imported/l337-s4uc3/l337-05.png)

Để kiểm tra thêm trong PCAP, lọc `arp`, xem ánh xạ IP/MAC, rồi đối chiếu MAC đích của lưu lượng gửi ra ngoài subnet. Việc đối chiếu ở lớp Ethernet giúp phân biệt gateway với một host nội bộ thông thường.

```wireshark
arp
```

> **Đáp án:** `172.16.0.1`

## Q7: IP được Zeus dùng để kiểm tra kết nối

Đọc trường **Destination IP** trong cảnh báo. Ảnh ghi nguồn `172.16.0.109`, đích `74.125.225.112` và mô tả Zeus gửi GET đến Google để kiểm tra Internet.

![Địa chỉ đích và HTTP GET trong cảnh báo Zeus](/images/imported/l337-s4uc3/l337-06.png)

Dù đề dùng từ “ping”, payload trong ảnh là HTTP `GET /webhp`, không phải ICMP Echo. IP này là đích kiểm tra kết nối, chưa phải máy chủ điều khiển malware.

> **Đáp án:** `74.125.225.112`

## Q8: IP máy chủ C2 của Zeus

Bắt đầu từ địa chỉ đã xác định ở Q7:

```wireshark
ip.addr == 74.125.225.112
```

![Lọc lưu lượng tới IP kiểm tra kết nối](/images/imported/l337-s4uc3/l337-07.png)

Theo dõi TCP stream để xem nội dung HTTP. Request tới `/webhp` là đầu mối để tìm thêm chuỗi liên quan trong capture; bản thân nội dung trang Google không chứng minh đây là C2.

![Nội dung HTTP trong TCP stream liên quan đến Google](/images/imported/l337-s4uc3/l337-08.png)

Tìm chuỗi `webhp` bằng chức năng tìm kiếm trong packet bytes, rồi đối chiếu với stream tải executable. Trong quá trình lần theo ở bản thực hành, stream 141 dẫn tới địa chỉ `88.198.6.20`.

![Đối chiếu chuỗi webhp với stream tải executable](/images/imported/l337-s4uc3/l337-09.png)

Tiếp tục lọc địa chỉ vừa tìm được:

```wireshark
ip.addr == 88.198.6.20
```

Ảnh cho thấy máy `172.16.0.109` liên tục gửi `POST /gt.php` tới địa chỉ này. Kết hợp với việc tải `bt.exe` và `cf.bin` ở các câu sau, đây là endpoint C2 của Zeus trong lab. Không suy ra malware chỉ từ cookie hoặc một liên kết trong HTML.

![Các HTTP POST lặp lại tới gt.php trên máy chủ C2](/images/imported/l337-s4uc3/l337-10.png)

> **Đáp án:** `88.198.6.20`

## Q9: File cấu hình .bin

Mở **File → Export Objects → HTTP** và tìm tên file có đuôi `.bin`. Danh sách trong ảnh ghi nhận `cf.bin`, hostname `88.198.6.20`, kích thước 446 byte.

![HTTP object list chứa cf.bin](/images/imported/l337-s4uc3/l337-11.png)

Có thể quay lại request tương ứng để đối chiếu URI, thay vì chọn file chỉ vì có phần mở rộng giống yêu cầu.

```wireshark
http.request.uri contains ".bin"
```

> **Đáp án:** `cf.bin`

## Q10: Mật khẩu đăng nhập WordPress

Lọc các request đăng nhập:

```wireshark
http.request.method == "POST" && http.request.uri contains "wp-login.php"
```

Mở form data hoặc Follow HTTP Stream để đọc các trường `log` và `pwd`. Ảnh ghi tài khoản `Jsmith` và mật khẩu `wM812ugu`, tiếp theo là response `302 Found` và cookie WordPress.

![Form đăng nhập WordPress và response của server](/images/imported/l337-s4uc3/l337-12.png)

**Đối chiếu mốc giờ:** ảnh này là stream 159, request từ `172.16.0.109` vào khoảng `22:56:29 UTC`; nó chứng minh giá trị credential, không phải ảnh trực tiếp của lần đăng nhập ngoài mạng gần `22:59 UTC`. Để xác minh đúng sự kiện được hỏi, tiếp tục kiểm tra các POST ở mốc đó, nguồn kết nối và response. Không coi mọi lần dùng cùng mật khẩu là cùng một sự kiện.

> **Đáp án:** `wM812ugu`

## Q11: Thời điểm truy cập trang Designs

Mật khẩu bảo vệ nội dung được đề cung cấp là `1qBeJ2Az`. Tìm request POST có chuỗi này:

```wireshark
http.request.method == "POST" && frame contains "1qBeJ2Az"
```

Trong ảnh, frame 5743 gửi `POST /wp-pass.php`, trường `post_password` đúng giá trị cần tìm và timestamp là `23:04:04 UTC`. Đối chiếu tiếp response chuyển hướng và request tới trang để gắn thời điểm với hành động mở nội dung.

![POST wp-pass.php chứa mật khẩu trang Designs](/images/imported/l337-s4uc3/l337-13.png)

> **Đáp án:** `23:04:04 UTC`

## Q12: Source port của shellcode exploit

Đề cho destination port `31708`. Lọc UDP theo cổng đích:

```wireshark
udp.dstport == 31708
```

Chọn gói **UDP** và mở phần User Datagram Protocol. Frame 348 hiển thị `Source Port: 39709` và `Destination Port: 31708`. Cần phân biệt với các gói ICMP báo Port Unreachable cũng xuất hiện trong kết quả do chứa thông tin gói UDP gốc.

![UDP source port 39709 và destination port 31708](/images/imported/l337-s4uc3/l337-14.png)

> **Đáp án:** `39709`

## Q13: Linux kernel version trong phản hồi sysinfo

Theo dõi TCP stream 155 để đọc dữ liệu trao đổi trong phiên Meterpreter:

```wireshark
tcp.stream == 155
```

Tìm `sysinfo` hoặc chuỗi `Linux`. Kết quả trong ảnh chứa hostname `WWW01` và phiên bản kernel `2.6.32-38-server`. Không nhầm kernel version với phiên bản Apache hay PHP đã tìm trước đó.

![Phản hồi sysinfo chứa phiên bản Linux kernel](/images/imported/l337-s4uc3/l337-15.png)

> **Đáp án:** `2.6.32-38-server`

## Q14: Token trong frame 3897

Đi thẳng tới frame được hỏi:

```wireshark
frame.number == 3897
```

Mở phần **HTML Form URL Encoded**, chọn trường `token` và sao chép giá trị. Ảnh xác nhận đây là POST tới `/pma/index.php` ở frame **3897**, không phải 3987.

![Trường token trong form data của frame 3897](/images/imported/l337-s4uc3/l337-16.png)

> **Đáp án:** `b7aad621db97d56771d6316a6d0b71e9`

## Q15: Công cụ tải file nén từ webserver

Lọc request có tên file nén:

```wireshark
http.request.method == "GET" && http.request.uri contains ".tar.gz"
```

Frame 5304 yêu cầu `/unimportant.tar.gz`. Header `User-Agent` chứa `Wget/1.13.4 (linux-gnu)`, nên công cụ được nhận diện trong request là `wget`. User-Agent có thể bị thay đổi; trong phạm vi câu hỏi, đây là trường trực tiếp để đọc tên công cụ.

![Request tải unimportant.tar.gz với User-Agent Wget](/images/imported/l337-s4uc3/l337-17.png)

> **Đáp án:** `wget`

## Q16: Tên executable tải về liên quan đến Zeus

Lọc HTTP request của máy bị nhiễm và quan sát các URI tải executable:

```wireshark
ip.addr == 172.16.0.109 && http.request
```

Frame 3510 ghi `GET /bt.exe` tới `88.198.6.20`, tiếp sau là tải `cf.bin` và các POST tới `gt.php`. Chuỗi này liên kết file tải về với hạ tầng đã xác định ở Q8. PCAP cho thấy việc tải file; để chứng minh trực tiếp thời điểm chạy cần thêm artifact phía host.

![Request tải bt.exe trước cf.bin và các POST tới C2](/images/imported/l337-s4uc3/l337-18.png)

> **Đáp án:** `bt.exe`

## Q17: Đường dẫn system shell

Chuyển sang memory dump và liệt kê command line của các tiến trình:

```bash
python2 /opt/volatility/vol.py -f /tmp/webserver.vmss --profile=LinuxDFIRwebsvrx64 linux_psaux
```

Ảnh cho thấy PID 1274 chạy `sh -c /bin/sh`, còn PID 1275 có command line `/bin/sh`. Đọc đường dẫn trong arguments để trả lời; tên tiến trình `sh` đơn thuần không đủ cho yêu cầu “full file path”.

![Command line của hai tiến trình shell](/images/imported/l337-s4uc3/l337-19.png)

> **Đáp án:** `/bin/sh`

## Q18: Parent PID của chuỗi shell

Liệt kê PID và PPID:

```bash
python2 /opt/volatility/vol.py -f /tmp/webserver.vmss --profile=LinuxDFIRwebsvrx64 linux_pslist
```

Ảnh thể hiện chuỗi:

```text
1042 -> 1274 (sh) -> 1275 (sh)
```

![PID và PPID của các shell trong memory dump](/images/imported/l337-s4uc3/l337-20.png)

**Phân biệt:** PPID trực tiếp của PID 1274 là `1042`; PPID trực tiếp của PID 1275 là `1274`. Vì vậy `1042` là tiến trình cha ở đầu chuỗi mà đáp án lab yêu cầu, không phải PPID trực tiếp giống nhau của cả hai shell.

> **Đáp án:** `1042`

## Q19: latency_record_count của PID 1274

Mở shell tương tác để đọc cấu trúc tiến trình trong memory dump:

```bash
python2 /opt/volatility/vol.py -f /tmp/webserver.vmss --profile=LinuxDFIRwebsvrx64 linux_volshell
```

Chuyển context sang PID 1274, lấy đối tượng tiến trình rồi in cấu trúc tại địa chỉ tương ứng:

```python
cc(pid=1274)
proc()
dt("task_struct", 0xffff880006dd8000)
```

Địa chỉ trên khớp offset của PID 1274 ở ảnh Q18 và chỉ áp dụng cho dump này. Tìm field `latency_record_count` trong kết quả `dt`; ảnh cho giá trị `0`.

![Trường latency_record_count trong task_struct](/images/imported/l337-s4uc3/l337-21.png)

> **Đáp án:** `0`

## Q20: File được map đầu tiên của PID 1274

Lấy danh sách vùng nhớ riêng cho tiến trình cần kiểm tra:

```bash
python2 /opt/volatility/vol.py -f /tmp/webserver.vmss --profile=LinuxDFIRwebsvrx64 linux_proc_maps -p 1274
```

Đọc cột **File Path** ở mapping đầu tiên. Kết quả là `/bin/dash`; các vùng phía sau gồm thư viện, heap và stack.

![Mapping đầu tiên của PID 1274 trỏ tới bin dash](/images/imported/l337-s4uc3/l337-22.png)

Q17 hỏi đường dẫn được gọi trong command line, còn Q20 hỏi file backing cho vùng nhớ. Hai câu lấy dữ liệu từ hai trường khác nhau, vì vậy không thay đáp án `/bin/dash` bằng `/bin/sh`.

> **Đáp án:** `/bin/dash`

## Q21: MD5 của receive.1105.3

Tạo thư mục đầu ra rồi trích các packet queue từ bộ nhớ:

```bash
mkdir -p /tmp/packets
python2 /opt/volatility/vol.py -f /tmp/webserver.vmss --profile=LinuxDFIRwebsvrx64 linux_pkt_queues -D /tmp/packets
```

Kết quả trong ảnh ghi hai file, mỗi file 32 byte. Câu hỏi yêu cầu `receive.1105.3`, không phải `receive.930.10`.

![Xuất packet queue thành các file receive](/images/imported/l337-s4uc3/l337-23.png)

Tính MD5 trực tiếp trên file nhị phân đã xuất:

```bash
md5sum /tmp/packets/receive.1105.3
```

![MD5 của receive.1105.3](/images/imported/l337-s4uc3/l337-24.png)

> **Đáp án:** `184c8748cfcfe8c0e24d7d80cac6e9bd`

## Tổng hợp đáp án

| Câu | Đáp án |
| --- | --- |
| Q1 | `74.204.41.73` |
| Q2 | `22:51:07 UTC` |
| Q3 | `5.3.2` |
| Q4 | `2.2.14` |
| Q5 | `Zeus` |
| Q6 | `172.16.0.1` |
| Q7 | `74.125.225.112` |
| Q8 | `88.198.6.20` |
| Q9 | `cf.bin` |
| Q10 | `wM812ugu` |
| Q11 | `23:04:04 UTC` |
| Q12 | `39709` |
| Q13 | `2.6.32-38-server` |
| Q14 | `b7aad621db97d56771d6316a6d0b71e9` |
| Q15 | `wget` |
| Q16 | `bt.exe` |
| Q17 | `/bin/sh` |
| Q18 | `1042` |
| Q19 | `0` |
| Q20 | `/bin/dash` |
| Q21 | `184c8748cfcfe8c0e24d7d80cac6e9bd` |
