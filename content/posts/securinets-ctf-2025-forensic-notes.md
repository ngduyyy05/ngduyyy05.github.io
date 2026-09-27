+++
title = "Securinets CTF 2025 - Forensic Notes"
date = 2026-09-27T09:00:00+07:00
draft = false
tags = ["Securinets", "Forensic", "Blue Team", "Disk Forensic", "Memory Forensic", "Network Forensic", "Reverse Engineering"]
categories = ["Writeups"]
summary = "Bản ghi chú tiếng Việt cho các hướng giải forensic ở Securinets CTF 2025: mail artifact, malware C2, file mã hóa, DNS exfil và reverse ransomware."
ShowToc = true
TocOpen = false

[cover]
  image = "/images/hero-cyber-city.png"
  alt = "Cyber city forensic blog cover"
+++

> Nguồn tham khảo: [Odin - Securinets CTF 2025 - Forensic](https://odintheprotector.github.io/2025/10/07/securinets-ctf-2025-forensic.html). Bài này là bản viết lại thành ghi chú học tập tiếng Việt, có lược bớt ảnh và code dài.

## Tổng quan

Bài gốc gom nhiều challenge forensic của Securinets CTF 2025. Mình chia lại thành ba cụm để đọc dễ hơn:

- **Silent Visitor:** điều tra Windows artifact, Thunderbird, malware và C2.
- **Lost File:** kết hợp AD1, memory dump và reverse binary để khôi phục file bị mã hóa.
- **Recovery:** phân tích backup bị mã hóa, DNS exfiltration và logic ransomware.

Điểm đáng học nhất là cách nối nhiều nguồn bằng chứng: disk image cho file/log, memory dump cho process/console/environment, còn reverse engineering giúp hiểu đúng thuật toán mã hóa.

## Silent Visitor

Challenge này đi theo một chuỗi điều tra khá cổ điển: xác định máy nạn nhân, mail client, email attacker, malware được tải về, rồi truy dấu C2 và persistence.

### Các mốc artifact

| Câu hỏi | Cách tìm | Giá trị đáng nhớ |
|---|---|---|
| Hash disk image | Tính SHA256 của image | `122b2b4bf1433341ba6e8fefd707379a98e6e9ca376340379ea42edb31a5dba2` |
| OS build | Registry `SOFTWARE\Microsoft\Windows NT\CurrentVersion` | `19045` |
| IP victim | Registry TCP/IP interfaces | `192.168.206.131` |
| Mail app | Profile/app artifact | `Thunderbird` |
| Victim email | Thunderbird profile | `ammar55221133@gmail.com` |
| Attacker email | Thunderbird profile | `masmoudim522@gmail.com` |
| Malware URL | Email/link + VT | `https://tmpfiles.org/dl/23860773/sys.exe` |
| Malware SHA256 | Hash sample | `be4f01b3d537b17c5ba7dc1bb7cd4078251364398565a0ca1e96982cff820b6d` |
| C2 | Network/VT/reverse | `40.113.161.85:5000` |

### Persistence và C2

Malware tạo một file định danh trên máy nạn nhân. Nội dung được dùng như một ID cho phiên nạn nhân:

```text
3649ba90-266f-48e1-960c-b908e1f28aef
```

Persistence nằm trong key Run của user hiện tại:

```text
HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\MyApp
```

Giá trị trỏ về file malware trong thư mục Documents:

```text
C:\Users\ammar\Documents\sys.exe
```

Khi malware liên lạc C2, request đầu tiên đi tới endpoint có chuỗi nhận diện khá rõ:

```text
http://40.113.161.85:5000/helppppiscofebabe23
```

Token bí mật để giao tiếp C2 là:

```text
e7bcc0ba5fb1dc9cc09460baaa2a6986
```

Điểm học được: nếu sample đã có trên VirusTotal, hãy tận dụng metadata trước để có hướng đi nhanh, nhưng vẫn nên kiểm tra lại bằng artifact local như registry hive, Thunderbird profile và file hệ thống.

## Lost File

Challenge đưa hai nguồn chính: một file **AD1** và một file **vmem**. Flow hợp lý là:

1. Mở AD1 bằng FTK Imager để tìm file khả nghi.
2. Export executable và file bị mã hóa.
3. Reverse executable để hiểu input nào tham gia tạo key.
4. Dùng memory dump để khôi phục các giá trị bị thiếu.

### Ý tưởng của binary

Binary nhận một input từ user, đọc computer name, rồi tìm file `secret_part.txt`. Ba phần này được ghép lại thành material để tính SHA256. Kết quả hash được dùng làm key/IV cho AES-256 mã hóa file `to_encrypt.txt`.

Chi tiết cần để giải:

- User input có thể phục hồi từ console trong memory.
- Computer name có thể lấy bằng Volatility plugin về environment/console.
- `secret_part.txt` đã bị xóa, nhưng vẫn có thể recover từ AD1; chuỗi quan trọng trong đó là `sigmadroid`.

Sau khi đủ ba mảnh, ta tính lại key/IV theo logic của chương trình rồi giải mã file `.enc`.

### Checklist khi gặp dạng này

- Đừng chỉ nhìn file còn tồn tại; file deleted trong image đôi khi là mảnh key quan trọng nhất.
- Nếu binary xóa file sau khi đọc, kiểm tra unallocated/deleted entries.
- Memory dump có thể giữ lại console command, argument, environment variable hoặc buffer.
- Với malware/packer đơn giản, đọc `main` trước thường đủ để dựng lại luồng mã hóa.

## Recovery

Phần này thú vị hơn vì có cả backup bị mã hóa, lịch sử PowerShell, Git history và DNS exfiltration.

### Từ PowerShell history tới Git

Trong backup, nhiều file có tên bình thường nhưng nội dung không đọc được. Lịch sử PowerShell hé lộ một GitHub repo đáng ngờ. Khi xem lại lịch sử commit, có commit chứa logic exfil qua DNS với domain label `meow`.

Trong pcap, các DNS query mang dữ liệu theo dạng chunk. Ý tưởng khôi phục:

1. Lọc DNS query liên quan tới `meow`.
2. Lấy label chứa dữ liệu và index.
3. Decode base32.
4. Byte đầu tiên làm khóa XOR cho phần còn lại của chunk.
5. Sắp xếp chunk theo index rồi ghép lại.

Kết quả là một executable đã bị pack. Sau khi unpack và mở trong IDA, có thể thấy logic mã hóa file không phải AES phức tạp mà là XOR với keystream sinh từ LCG.

### Logic mã hóa file

Seed của keystream phụ thuộc vào đường dẫn file. Đây là điểm dễ làm sai: chỉ cần path khác một ký tự thì stream sinh ra sẽ khác và file không giải được.

Các điểm quan trọng:

- Đường dẫn gốc được suy ra là `C:\Users\gumba\Desktop\`.
- Secret hard-code có dạng nội dung dài liên quan tới `evilsecret...encryption`.
- LCG dùng hai hằng quen thuộc: `1664525` và `1013904223`.
- Keystream lấy byte thấp của state sau mỗi vòng update.

Vì vậy khi viết script giải mã, cần truyền đúng filename/path như malware nhìn thấy lúc mã hóa, không phải đường dẫn hiện tại trên máy phân tích.

## Ghi chú cuối

Bộ bài này rất đáng đọc nếu đang học DFIR vì nó ép mình dùng nhiều lớp bằng chứng:

- Registry và mail artifact để dựng timeline ban đầu.
- VirusTotal và reverse để hiểu malware.
- Memory forensic để lấy giá trị runtime.
- Git history và pcap để khôi phục dữ liệu bị exfil.
- Reverse thuật toán mã hóa để viết script giải mã thay vì đoán.

Khi làm lại, mình sẽ ưu tiên viết timeline trước, sau đó mới đi sâu reverse. Timeline giúp không bị lạc giữa quá nhiều artifact.
