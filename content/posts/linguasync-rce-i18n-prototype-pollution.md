+++
title = "LinguaSync — RCE via i18n Prototype Pollution"
date = 2026-11-02T00:00:00+07:00
draft = false
tags = ["Web", "Prototype Pollution", "RCE", "Node.js", "Express", "i18next", "Burp Suite"]
categories = ["Writeups"]
summary = "Custom Web Lab 407: Prototype Pollution tại API i18n làm ô nhiễm tùy chọn shell, kết hợp chức năng sinh báo cáo để thực thi lệnh và đọc flag."
ShowToc = true
TocOpen = false
+++

LinguaSync là ứng dụng quản lý bản dịch xây dựng bằng Node.js/Express, tích hợp i18next để quản lý tài nguyên đa ngôn ngữ và cung cấp chức năng tạo báo cáo. Mục tiêu của **Custom Web Lab 407** là tìm chuỗi lỗ hổng cho phép thực thi lệnh trên máy chủ và đọc flag.

## 1. Phân tích bề mặt tấn công

Hai endpoint đáng chú ý trong bài lab:

| Endpoint | Chức năng | Điểm cần kiểm tra |
| --- | --- | --- |
| `GET /locales/resources` | Nhận `lng` và `ns`, dựng đối tượng phản hồi bằng `setPath()` | Dữ liệu người dùng được dùng làm khóa thuộc tính |
| `POST /api/reports/generate` | Nhận dữ liệu báo cáo và gọi `child_process.spawn()` | Tùy chọn tiến trình con và giá trị `reportType` |

API đa ngôn ngữ tạo ra trạng thái prototype bị ô nhiễm; tính năng sinh báo cáo là nơi kích hoạt tác động của trạng thái đó.

## 2. Nguyên nhân: Prototype Pollution trong `setPath()`

Hàm `setPath()` duyệt các khóa trong mảng `path` mà không kiểm tra khóa có phải thuộc tính riêng của đối tượng hay không. Đoạn code trong tài liệu được định dạng lại như sau:

```javascript
const result = {};
setPath(result, [lng, ns], bundle);
res.json(result);

function setPath(obj, path, value) {
  let current = obj;

  for (let i = 0; i < path.length - 1; i++) {
    if (!current[path[i]]) current[path[i]] = {};
    current = current[path[i]];
  }

  current[path[path.length - 1]] = value;
}
```

Với đối tượng thông thường trong JavaScript, `__proto__` có thể trỏ đến prototype của đối tượng. Khi `lng` là `__proto__`, biểu thức `current[path[i]]` đọc một giá trị kế thừa thay vì một thuộc tính riêng.

Do giá trị này đã tồn tại, câu lệnh khởi tạo `{}` bị bỏ qua. Biến `current` sau đó trỏ đến `Object.prototype`. Nếu `ns` là `shell` và `bundle` nhận giá trị mặc định `true` như mô tả trong lab, phép gán cuối tương đương:

```javascript
Object.prototype.shell = true;
```

Thuộc tính `shell` lúc này có thể được kế thừa bởi các đối tượng thông thường trong cùng tiến trình nếu chúng không tự định nghĩa thuộc tính đó.

## 3. Chuỗi khai thác trong môi trường lab

### Bước 1: Làm ô nhiễm thuộc tính `shell`

Gửi request tới API tài nguyên đa ngôn ngữ với hai tham số:

```http
GET /locales/resources?lng=__proto__&ns=shell HTTP/1.1
```

Ảnh từ tài liệu cho thấy server trả `200 OK` với body `{}`:

![Request tới API i18n với lng=__proto__ và ns=shell trả về 200 OK](/images/imported/linguasync/image1.png)

Phản hồi `{}` phù hợp với việc đối tượng `result` không có thuộc tính riêng được thêm vào để tuần tự hóa. Tuy nhiên, riêng phản hồi này chưa đủ để xác nhận Prototype Pollution; bước gọi chức năng báo cáo dưới đây cho thấy tác động tiếp theo trong lab.

### Bước 2: Kích hoạt qua chức năng sinh báo cáo

Sau request trên, gửi yêu cầu sinh báo cáo với `reportType` chứa dấu phân tách lệnh shell:

```http
POST /api/reports/generate HTTP/1.1
Content-Type: application/json

{
  "projectId": "2",
  "reportType": "stats;cat /root/flag.txt"
}
```

Trong môi trường lab, khi đường gọi tiến trình con sử dụng giá trị `shell` bị kế thừa, dấu `;` được shell diễn giải thành dấu phân tách lệnh. Sau phần sinh báo cáo, lệnh `cat /root/flag.txt` được thực thi.

Ảnh response cho thấy `success: true`, còn trường `output` chứa nội dung báo cáo và chuỗi `FLAG{...}` ở cuối:

![Chức năng sinh báo cáo trả về output chứa flag sau payload trong reportType](/images/imported/linguasync/image2.png)

## 4. Giải thích cơ chế RCE

Chuỗi nguyên nhân và kết quả trong bài lab:

1. `lng` không được kiểm soát trước khi đưa vào đường dẫn thuộc tính.
2. `setPath()` đi từ đối tượng `result` sang `Object.prototype` thông qua `__proto__`.
3. Phép gán với `ns=shell` thiết lập `Object.prototype.shell = true`.
4. Đường gọi tiến trình con dùng tùy chọn `shell` bị kế thừa.
5. Giá trị `reportType` chứa `;` được shell diễn giải và thực thi lệnh bổ sung.

Hai lỗi nằm ở hai khu vực chức năng khác nhau. Chỉ kiểm tra riêng API i18n hoặc riêng chức năng xuất báo cáo có thể bỏ sót chuỗi tác động chéo này.

Tác động đến `child_process.spawn()` phụ thuộc cách ứng dụng xây dựng, sao chép và truyền đối tượng options, cùng phiên bản Node.js. Kết quả trong tài liệu xác nhận hành vi của môi trường lab; không nên suy ra mọi lời gọi `spawn()` đều bị ảnh hưởng chỉ vì `Object.prototype.shell` tồn tại.

## 5. Ghi chú khi kiểm thử

Tài liệu gốc ghi nhận cách xử lý query string mặc định của Express không hoạt động như giả định ban đầu, nhưng không kèm payload thử nghiệm hoặc cấu hình parser tương ứng. Vì vậy, khi tái hiện cần kiểm tra giá trị thực tế của `req.query` trong môi trường được phép kiểm thử.

Request thành công được ghi lại trong bài sử dụng trực tiếp hai tham số `lng=__proto__` và `ns=shell`.

## 6. Biện pháp khắc phục

- Không dùng tham số người dùng làm đường dẫn thuộc tính tùy ý. Giới hạn `lng` và `ns` theo danh sách giá trị hợp lệ; chặn các khóa nguy hiểm như `__proto__`, `constructor` và `prototype` ở mọi cấp.
- Dùng `Object.hasOwn()` khi duyệt khóa để phân biệt thuộc tính riêng với thuộc tính kế thừa. Cân nhắc `Object.create(null)` hoặc `Map` cho cấu trúc dữ liệu dạng từ điển; vẫn cần kiểm soát khóa đầu vào.
- Khi dùng `child_process.spawn()`, truyền tùy chọn `shell: false` một cách tường minh và bảo đảm quá trình dựng options không lấy thuộc tính ngoài ý muốn từ prototype.
- Kiểm soát `reportType` theo danh sách loại báo cáo hợp lệ; truyền chương trình và đối số riêng biệt, tránh ghép dữ liệu người dùng thành chuỗi lệnh shell.
- Bổ sung kiểm thử tích hợp cho chuỗi tác động giữa API i18n và chức năng sinh báo cáo, bao gồm việc gửi khóa nguy hiểm rồi kiểm tra hành vi gọi tiến trình con.
