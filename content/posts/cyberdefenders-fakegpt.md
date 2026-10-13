+++
title = "CyberDefenders - FakeGPT Lab Writeup"
date = 2026-10-13T00:00:00+07:00
draft = false
tags = ["CyberDefenders", "Malware Analysis", "Browser Extension", "JavaScript", "Credential Access"]
categories = ["Writeups"]
summary = "Phân tích extension giả mạo ChatGPT: giải mã hostname, theo dõi form và bàn phím, mã hóa payload và gửi dữ liệu qua phần tử ảnh."
ShowToc = true
TocOpen = false
+++

FakeGPT tập trung vào phân tích extension trình duyệt giả mạo trợ lý ChatGPT. Từ mã nguồn trong các ảnh thực hành, ta lần theo cách extension chọn website mục tiêu, thu thập thông tin đăng nhập và chuyển dữ liệu ra ngoài.

| Thành phần | Nội dung phân tích |
| --- | --- |
| `manifest.json` | Quyền truy cập, background script và content script |
| `loader.js` | Kiểm tra môi trường và tải mã chức năng |
| `app.js` | Chọn mục tiêu, bắt sự kiện, đóng gói và gửi dữ liệu |
| `encryptPayload()` | Lời gọi AES, IV và định dạng payload |

**Công cụ:** trình soạn thảo mã nguồn và CyberChef. Các kết luận dưới đây dựa trên phân tích tĩnh các đoạn code trong ảnh.

## Q1: Which encoding method does the browser extension use to obscure target URLs, making them more difficult to detect during analysis?

Trong `app.js`, hàm có tên làm rối `_0xabc1` gọi `atob()`. Mảng `targets` dùng hàm này để giải mã một chuỗi trước khi so sánh với hostname của trang hiện tại.

```javascript
return atob(_0x321a);
```

`atob()` là đầu mối nhận diện **Base64**. Ở chiều ngược lại, hàm bọc quanh `btoa()` cũng xuất hiện trong ảnh. Tên hàm bị làm rối không thay đổi chức năng của API được gọi bên trong.

![Hàm atob và hostname được biểu diễn bằng Base64 trong app.js](/images/imported/fakegpt/fakegpt-01.png)

Base64 giúp tránh để hostname ở dạng văn bản dễ tìm kiếm, nhưng không phải mã hóa bảo mật: có thể giải mã mà không cần khóa.

> **Đáp án:** `Base64`

## Q2: Which website does the extension monitor for data theft, and how does it activate on the target site?

Đưa chuỗi trong mảng `targets` vào CyberChef và chọn **From Base64**:

```text
d3d3LmZhY2Vib29rLmNvbQ==
```

Kết quả trả về là `www.facebook.com`.

![CyberChef giải mã chuỗi mục tiêu thành www.facebook.com](/images/imported/fakegpt/fakegpt-02.png)

Quay lại code ở Q1, điều kiện kích hoạt là:

```javascript
targets.indexOf(window.location.hostname) !== -1
```

Chỉ khi hostname hiện tại nằm trong `targets`, code mới đăng ký các listener `submit` và `keydown`. Đây là phép so khớp hostname chính xác, không phải kiểm tra mọi địa chỉ có chứa chữ “facebook”. Manifest có thể cho phép inject script trên nhiều trang, nhưng nhánh thu thập dữ liệu trong `app.js` vẫn chịu điều kiện này.

> **Đáp án:** `www.facebook.com`; kích hoạt các listener khi `window.location.hostname` khớp mục tiêu đã giải mã.

## Q3: How does the extension exfiltrate stolen data, and which HTML element is used for this purpose?

Tìm hàm `sendToServer(encryptedData)`. Hàm tạo một đối tượng bằng `new Image()`, đưa payload vào tham số `data` của URL rồi thêm ảnh vào `document.body`.

Trình duyệt tải tài nguyên được gán vào `src`, qua đó gửi payload dưới dạng query string trong request lấy ảnh. `encodeURIComponent()` giúp biểu diễn payload hợp lệ trong URL; nó không mã hóa dữ liệu theo nghĩa mật mã.

![Hàm sendToServer sử dụng đối tượng Image và thuộc tính src](/images/imported/fakegpt/fakegpt-03.png)

Cách gửi này không cần gọi `fetch()` hay `XMLHttpRequest`. Phần tử dùng làm phương tiện truyền dữ liệu là **`<img>`**. Đoạn code không cho thấy thuộc tính ẩn ảnh, nên không cần giả định ảnh được đặt `display: none`.

> **Đáp án:** gửi payload qua URL của request tải ảnh, sử dụng phần tử `<img>`.

## Q4: What is the first specific condition in the code that triggers the extension to deactivate itself?

Trong `loader.js`, nhánh kiểm tra môi trường có hai điều kiện nối bằng toán tử OR:

```javascript
navigator.plugins.length === 0 || /HeadlessChrome/.test(navigator.userAgent)
```

Điều kiện **đầu tiên** là danh sách plugin trình duyệt có độ dài bằng `0`. Điều kiện thứ hai kiểm tra chuỗi `HeadlessChrome` trong User-Agent. Đây là các dấu hiệu mà tác giả code dùng để nghi ngờ môi trường tự động hoặc phân tích; chúng không phải bằng chứng chắc chắn về máy ảo.

![Nhánh kiểm tra plugins và HeadlessChrome trong loader.js](/images/imported/fakegpt/fakegpt-04.png)

**Lưu ý khi đọc code:** nhánh này hiện thông báo sẽ vô hiệu hóa extension, nhưng ảnh chỉ cho thấy việc đăng ký callback `onMessage` trả về `false`. Phần tải `core/app.js` vẫn nằm phía sau, không có `return` thoát hàm bao ngoài hay lệnh tắt extension. Vì vậy đáp án xác định điều kiện kiểm tra đầu tiên, không khẳng định cơ chế tự tắt hoạt động hoàn chỉnh.

> **Đáp án:** `navigator.plugins.length === 0`

## Q5: Which events does the extension monitor to capture user input, and how does it process the data?

Trong nhánh dành cho website mục tiêu, extension theo dõi hai sự kiện:

1. **`submit`:** lấy form từ `event.target`, tạo `FormData`, đọc `username` hoặc `email`, rồi đọc `password`. Khi cả tên đăng nhập và mật khẩu đều có giá trị, code gọi `exfiltrateCredentials()`.
2. **`keydown`:** lấy phím từ `event.key`, sau đó chuyển giá trị đến `exfiltrateData()` với loại dữ liệu `keystroke`.

![Hai listener submit và keydown trong app.js](/images/imported/fakegpt/fakegpt-05.png)

Hai nhánh đều đóng gói dữ liệu kèm hostname, chuyển thành JSON, gọi `encryptPayload()` rồi đưa kết quả tới `sendToServer()`. Như vậy extension vừa lấy giá trị form tại lúc gửi, vừa theo dõi từng sự kiện nhấn phím.

> **Đáp án:** `submit` và `keydown`; dữ liệu được đóng gói thành JSON, mã hóa và chuyển tới hàm gửi.

## Q6: Which API or method is used to monitor user keystrokes?

API được sử dụng là **`document.addEventListener()`**, với tên sự kiện **`keydown`**. Callback đọc `event.key` để biết phím vừa được nhấn.

![Listener keydown đọc giá trị event.key](/images/imported/fakegpt/fakegpt-06.png)

Phân biệt ba thành phần: `addEventListener` là phương thức đăng ký, `keydown` là sự kiện được lắng nghe và `event.key` là dữ liệu lấy từ sự kiện. Listener nằm ở cấp document, không chỉ gắn riêng vào ô mật khẩu.

> **Đáp án:** `document.addEventListener('keydown', ...)`

## Q7: Where does the extension transmit exfiltrated data, and how is the transmission secured?

Đọc giá trị gán cho `img.src` trong `sendToServer()`. Endpoint xuất hiện trong ảnh là:

```text
https://Mo.Elshaheedy.com/collect?data=
```

Payload được nối vào sau tham số `data`. Host đích là `Mo.Elshaheedy.com`, còn `/collect` là đường dẫn nhận dữ liệu.

![Endpoint collect và hàm mã hóa payload trước khi gửi](/images/imported/fakegpt/fakegpt-07.png)

Code sử dụng **HTTPS** cho kênh truyền và gọi **AES** để mã hóa nội dung trước đó. Cần tách hai lớp này: HTTPS bảo vệ kết nối khi request thành công, còn AES xử lý payload ở phía ứng dụng. HTTPS không làm endpoint trở nên đáng tin cậy; máy chủ nhận vẫn có được dữ liệu gửi đến nó.

> **Đáp án:** `Mo.Elshaheedy.com`, đường dẫn `/collect`, dùng `HTTPS` và payload được xử lý bằng `AES`.

## Q8: Which function is responsible for exfiltrating user credentials?

Trong listener `submit`, sau khi kiểm tra `username && password`, code gọi **`exfiltrateCredentials(username, password)`**.

Hàm này tạo payload gồm ba trường `user`, `pass` và `site`, chuyển payload thành chuỗi JSON rồi lần lượt gọi `encryptPayload()` và `sendToServer()`.

![Hàm exfiltrateCredentials và các hàm được gọi tiếp theo](/images/imported/fakegpt/fakegpt-08.png)

`sendToServer()` là bước vận chuyển chung. Hàm chuyên xử lý credential mà câu hỏi yêu cầu là `exfiltrateCredentials()`.

> **Đáp án:** `exfiltrateCredentials()`

## Q9: What encryption algorithm is used to secure stolen data?

Trong `encryptPayload()`, lời gọi quyết định thuật toán là:

```javascript
CryptoJS.AES.encrypt(data, key, { iv: iv })
```

![Lời gọi CryptoJS.AES.encrypt trong encryptPayload](/images/imported/fakegpt/fakegpt-09.png)

Code tạo key từ chuỗi hard-code, tạo IV bằng `WordArray.random(16)`, rồi ghép IV với ciphertext và biểu diễn kết quả bằng Base64. **AES** là thuật toán mã hóa; Base64 chỉ là cách biểu diễn đầu ra để truyền dưới dạng chuỗi. Không suy ra một biến thể như AES-256 chỉ từ tên `AES.encrypt()`.

> **Đáp án:** `AES`

## Q10: What does the extension access to store or manipulate session-related data and authentication information?

Kiểm tra mảng `permissions` trong `manifest.json`. Quyền **`cookies`** xuất hiện cùng các quyền host HTTP/HTTPS.

![Quyền cookies trong manifest.json](/images/imported/fakegpt/fakegpt-10.png)

Cookie có thể chứa định danh phiên hoặc thông tin liên quan đến xác thực. Đây là loại dữ liệu mà câu hỏi nhắm tới, khác với quyền `storage` dùng cho vùng lưu trữ của extension.

Ảnh manifest cho thấy extension **yêu cầu quyền** truy cập cookies; để kết luận nó đã thực sự đọc, sửa hoặc lấy cắp cookie nào cần tìm thêm lời gọi API tương ứng hoặc bằng chứng khi chạy. Không coi khai báo quyền là bằng chứng hành vi đã xảy ra.

> **Đáp án:** `Cookies`

## Tổng hợp đáp án

| Câu | Đáp án chính |
| --- | --- |
| Q1 | `Base64` |
| Q2 | `www.facebook.com`, so khớp `window.location.hostname` |
| Q3 | `<img>`, gửi dữ liệu qua URL tải ảnh |
| Q4 | `navigator.plugins.length === 0` |
| Q5 | `submit` và `keydown` |
| Q6 | `document.addEventListener('keydown', ...)` |
| Q7 | `Mo.Elshaheedy.com`, HTTPS và AES |
| Q8 | `exfiltrateCredentials()` |
| Q9 | `AES` |
| Q10 | `Cookies` |
