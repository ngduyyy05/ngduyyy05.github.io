+++
title = "Approved-ish — WolvCTF 2026"
date = 2026-11-22T00:00:00+07:00
draft = false
tags = ["WolvCTF 2026", "Web", "Business Logic", "Authorization"]
categories = ["Writeups"]
summary = "Dùng ID alias viết hoa trong backup/restore để đổi shard sau khi manifest đã được duyệt, rồi lấy snapshot của restricted-v1."
ShowToc = true
TocOpen = false
+++

Gợi ý của challenge là: “The builder only ever ships what was approved. Right?” Mình tập trung kiểm tra xem snapshot có gắn với dữ liệu tại thời điểm duyệt hay chỉ tra lại alias khi xuất.

Mục tiêu là khiến một manifest được duyệt khi alias trỏ đến shard thường sample-v1 xuất nội dung của restricted-v1. Mình làm được việc đó qua luồng backup/restore của alias, không cần gửi request song song.

## Mình bắt đầu từ frontend

Frontend cho thấy các API chính:

| Endpoint | Vai trò |
|---|---|
| POST /api/session | Tạo workspace |
| GET /api/shards | Liệt kê shard và trạng thái |
| POST /api/aliases | Tạo alias trỏ tới shard |
| PATCH /api/aliases/{id} | Đổi đích alias |
| POST /api/manifests | Tạo manifest từ danh sách alias ID |
| POST /api/manifests/{id}/approve | Duyệt manifest |
| GET /api/aliases/backup | Tải backup alias dạng JSON |
| POST /api/aliases/restore | Khôi phục alias từ JSON |
| POST /api/manifests/{id}/snapshot | Xuất snapshot của manifest |

Trong request tạo manifest, mình thấy manifest nhận danh sách alias_ids. Giao diện cũng có backup/restore ngoài đường PATCH. Phần gợi ý nhắc đến cách viết hoa trong legacy backup nên mình kiểm tra xem restore xử lý ID và trạng thái khóa có giống các API còn lại không.

Mình không có source backend, nên các kết luận về cách so sánh ID bên trong server là suy luận từ request và kết quả quan sát được.

## Tạo manifest ở trạng thái hợp lệ

Mình mở challenge bằng Burp Browser, tạo workspace, rồi lấy cookie phiên từ Proxy → HTTP history để dùng trong Repeater. Cookie dưới đây được thay bằng placeholder; các ID là ID ghi lại trong lần giải này.

Liệt kê shard:

~~~http
GET /api/shards HTTP/1.1
Host: approved-ish-web.wolvctf-2026.kctf.cloud
Cookie: <session-cookie>
~~~

Phản hồi cho thấy sample-v1 là shard thường và restricted-v1 là shard bị hạn chế. Lúc này mình chỉ biết restricted-v1 là mục tiêu cần kiểm tra, chưa biết nội dung của nó.

Mình tạo alias trỏ tới shard thường:

~~~http
POST /api/aliases HTTP/1.1
Host: approved-ish-web.wolvctf-2026.kctf.cloud
Cookie: <session-cookie>
Content-Type: application/json

{"target_shard_id":"sample-v1"}
~~~

Alias được tạo trong lần giải có ID:

~~~text
e9fd7a6f4c7b431088a26af2be48e2c5
~~~

Sau đó mình tạo manifest tham chiếu alias này:

~~~http
POST /api/manifests HTTP/1.1
Host: approved-ish-web.wolvctf-2026.kctf.cloud
Cookie: <session-cookie>
Content-Type: application/json

{"alias_ids":["e9fd7a6f4c7b431088a26af2be48e2c5"]}
~~~

Manifest ID nhận được là 74d23d9f21394046a94cd976bf44de2f. Mình gửi duyệt:

~~~http
POST /api/manifests/74d23d9f21394046a94cd976bf44de2f/approve HTTP/1.1
Host: approved-ish-web.wolvctf-2026.kctf.cloud
Cookie: <session-cookie>
Content-Length: 0
~~~

Approval endpoint xác nhận manifest đã được duyệt khi alias vẫn trỏ tới sample-v1.

## Đổi alias qua backup/restore

Mình tải backup hiện tại:

~~~http
GET /api/aliases/backup HTTP/1.1
Host: approved-ish-web.wolvctf-2026.kctf.cloud
Cookie: <session-cookie>
~~~

Backup có dạng:

~~~json
{
  "aliases": [
    {
      "id": "e9fd7a6f4c7b431088a26af2be48e2c5",
      "target_shard_id": "sample-v1"
    }
  ],
  "format": "approved-ish.aliases.v1",
  "workspace_id": "e660c2ad39b64e7cb4a5c09c6a0d076b"
}
~~~

Mình sửa hai giá trị trong backup: viết hoa ID và đổi target_shard_id sang restricted-v1, rồi gửi lại cho restore:

~~~http
POST /api/aliases/restore HTTP/1.1
Host: approved-ish-web.wolvctf-2026.kctf.cloud
Cookie: <session-cookie>
Content-Type: application/json

{
  "aliases": [
    {
      "id": "E9FD7A6F4C7B431088A26AF2BE48E2C5",
      "target_shard_id": "restricted-v1"
    }
  ],
  "format": "approved-ish.aliases.v1",
  "workspace_id": "e660c2ad39b64e7cb4a5c09c6a0d076b"
}
~~~

Sau restore, snapshot của manifest đã duyệt trả về alias ID dạng chữ thường như ban đầu nhưng shard_id đã đổi thành restricted-v1. Kết quả này cho thấy ID viết hoa trong backup vẫn tác động được tới alias mà manifest đang tham chiếu.

## Lấy snapshot và flag

Mình gọi snapshot trên chính manifest đã được duyệt trước đó:

~~~http
POST /api/manifests/74d23d9f21394046a94cd976bf44de2f/snapshot HTTP/1.1
Host: approved-ish-web.wolvctf-2026.kctf.cloud
Cookie: <session-cookie>
Content-Length: 0
~~~

Server trả HTTP 200 OK cùng nội dung của shard bị hạn chế:

~~~json
{
  "manifest_id": "74d23d9f21394046a94cd976bf44de2f",
  "shards": [
    {
      "alias_id": "e9fd7a6f4c7b431088a26af2be48e2c5",
      "content": "wctf{b067644b2447025b739c58132106bbaf}",
      "shard_id": "restricted-v1"
    }
  ],
  "version": 1
}
~~~

![Snapshot trả về flag từ restricted-v1](/images/imported/wolvctf-2026/approved-ish/approved-ish-result.png)

Flag: wctf{b067644b2447025b739c58132106bbaf}

## Root cause và cách khắc phục

Có hai kiểm tra cần được ràng buộc với nhau:

- Restore chấp nhận alias ID viết hoa và vẫn cập nhật alias mà manifest đang dùng. Quan sát này cho thấy đường restore và kiểm tra trạng thái khóa có thể chuẩn hóa hoặc so sánh ID không nhất quán; vì không có source backend, mình không khẳng định chính xác hàm nào gây ra việc đó.
- Approval không cố định alias trỏ tới shard nào. Snapshot tra lại đích hiện tại của alias, nên thay đổi sau khi duyệt làm nội dung xuất ra khác với dữ liệu đã được duyệt.

Đây là lỗi phân quyền và tính toàn vẹn của quy trình duyệt, có thể xem là TOCTOU ở mức logic. Không cần race condition: mình đổi alias sau khi approval hoàn tất rồi mới gọi snapshot.

Để sửa, server cần chuẩn hóa ID trước khi tìm alias và kiểm tra quyền, áp dụng cùng chính sách cho PATCH lẫn restore, đồng thời gắn approval với phiên bản alias hoặc shard cụ thể. Snapshot cũng nên kiểm tra lại quyền truy cập ngay lúc xuất.
