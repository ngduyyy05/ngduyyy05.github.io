+++
title = "HCM PTIT CTF 2026 — Galactic Invaders"
date = 2026-10-31T20:03:00+07:00
draft = false
tags = ["HCM PTIT CTF 2026", "Web", "JavaScript", "Client-side"]
categories = ["Writeups"]
summary = "Đọc logic game phía client, tìm debug hook trên window và đặt cặp score/previousScore hợp lệ để gọi hàm hiện flag."
ShowToc = true
TocOpen = false

[cover]
  image = "/images/hcm-ptit-ctf-2026.jpg"
  alt = "HCM PTIT CTF 2026"
+++

Trang `/rules` nói Galactic Invaders chỉ mở “đường truyền mã hóa” khi người chơi đạt 1.000.000 điểm. Chơi tới mốc đó không phải hướng hợp lý; toàn bộ game và điều kiện thắng đều nằm trong JavaScript tải xuống trình duyệt.

## Điều kiện hiện flag

Trong `game.js`, hàm kiểm tra điểm có dạng:

```javascript
function checkFlag() {
    const hidden = atob("YW50aWNoZWF0Q2hlY2s="); // anticheatCheck
    if (score > 999999 && score == (previousScore + 10)) {
        localStorage.setItem(hidden, "1");
        secureFlagDisplay(hidden);
        localStorage.removeItem(hidden);
    }
}
```

Không chỉ cần đủ một triệu điểm, `score` còn phải đúng bằng `previousScore + 10`, tương ứng với một lần vừa hạ mục tiêu và nhận 10 điểm.

Nếu chỉ gán `score = 1000000` trong Console, ta chỉ tạo hoặc sửa biến global chứ không đụng tới `score` bên trong closure; điều kiện thứ hai cũng chưa được thỏa. Tuy nhiên script đã để lộ sẵn một debug hook:

```javascript
window.checkFlag = checkFlag;
window.__ctf = {
    setScore: (s, p) => {
        score = s;
        previousScore = p;
    },
    triggerCheck: () => checkFlag()
};
```

Nhờ `window.__ctf`, không cần gỡ rối toàn bộ khối mã phía sau.

## Khai thác

Mở Console tại `/game` và chạy:

```javascript
window.__ctf.setScore(1000000, 999990);
window.__ctf.triggerCheck();
```

`triggerCheck()` gọi lại đúng hàm kiểm tra của game, sau đó `secureFlagDisplay()` giải mã và hiện flag bằng hộp thoại:

![Galactic Invaders hiển thị flag](/images/imported/galactic-invaders/flag.png)

```text
PTITHCM{h4ck_7h3_pl4n37_$4v3_7h3__0x386c8c}
```

Obfuscation chỉ làm việc đọc mã chậm hơn; nó không bảo vệ được trạng thái và bí mật đã gửi xuống trình duyệt. Trong challenge này, debug hook là đường ngắn nhất để đi qua điều kiện có sẵn thay vì sửa trực tiếp hàm giải mã.
