+++
title = "Hack The Box - AoTR 4: A Drone in the Snow"
date = 2026-10-15T00:00:00+07:00
draft = false
tags = ["HackTheBox", "DFIR", "Drone Forensics", "GPS", "ArduPilot"]
categories = ["Writeups"]
summary = "Đối chiếu mission plan và telemetry của drone: xác định tuyến bay, điểm dừng, thời điểm va chạm và vị trí cất cánh."
ShowToc = true
TocOpen = false
[cover]
image = "/images/imported/aotr4/cover.png"
alt = "AoTR 4: A Drone in the Snow"
relative = false
hiddenInSingle = true
+++

Một chiếc drone được tìm thấy trong tuyết tại Budapest. Với kế hoạch nhiệm vụ và log chuyến bay, mục tiêu là dựng lại lộ trình, xác định hành vi tại các waypoint và đối chiếu sự kiện va chạm với dữ liệu GPS.

Bài ghi chép này được biên soạn từ PDF walkthrough **AoTR 4: A Drone in the Snow** của HTB, do **gordic** thực hiện. Các giá trị và trích đoạn log dưới đây lấy từ tài liệu; chưa được chạy kiểm chứng lại trên hai artifact gốc.

## Chuẩn bị dữ liệu

| Artifact | Vai trò |
| --- | --- |
| `AOTR_Winter_Blackout.plan` | Kế hoạch nhiệm vụ QGroundControl dạng JSON: Home, waypoint, lệnh bay và tham số |
| `log.bin` | Log nhị phân ArduPilot: thông báo hệ thống và telemetry thực tế |

Điểm quan trọng là **kế hoạch không đồng nghĩa với diễn biến thực tế**. File `.plan` trả lời drone được lập trình làm gì; log trả lời nó đã ghi nhận điều gì trong chuyến bay.

Để xuất các nhóm dữ liệu cần dùng, chạy từng loại message riêng bằng `mavlogdump.py` từ pymavlink:

```bash
mavlogdump.py --types MSG --format csv log.bin > MSG.csv
mavlogdump.py --types GPS --format csv log.bin > GPS.csv
```

`MSG.csv` phục vụ tìm mốc cất cánh, disarm và va chạm. `GPS.csv` phục vụ đối chiếu tọa độ, độ cao và tốc độ. Các lệnh này dùng thống nhất tên `log.bin`, thay cho đoạn lệnh bị dính chữ và dùng lẫn `log1.bin` trong PDF. Công cụ yêu cầu đúng một loại message khi xuất CSV từ log nhị phân. [Mã nguồn mavlogdump.py](https://github.com/ArduPilot/pymavlink/blob/master/tools/mavlogdump.py).

## Q1: How many total mission items are defined in the flight plan, including Home, Takeoff, and Land commands?

Mở file `.plan` và xem `mission.items`. Mảng này có **48 phần tử**, đánh số `doJumpId` từ 1 đến 48:

| Thành phần | Số lượng | Command |
| --- | --- | --- |
| Takeoff | 1 | `22` |
| Spline waypoint | 46 | `82` |
| Land | 1 | `21` |

Home được lưu riêng trong `mission.plannedHomePosition`, không phải một phần tử của `mission.items`. Vì đề yêu cầu tính cả Home nên kết quả là **48 + 1 = 49**.

Có thể kiểm tra bằng `jq`:

```bash
jq '.mission.items | length' AOTR_Winter_Blackout.plan
jq '.mission.plannedHomePosition' AOTR_Winter_Blackout.plan
```

> **Đáp án:** `49`

## Q2: How many spline waypoints are in the mission?

Spline waypoint dùng command `82`, tương ứng `MAV_CMD_NAV_SPLINE_WAYPOINT`. Lọc theo command sẽ chính xác hơn việc đếm toàn bộ marker trên bản đồ vì Takeoff và Land cũng có vị trí riêng.

```bash
jq '[.mission.items[] | select(.command == 82)] | length' AOTR_Winter_Blackout.plan
```

Các item từ `doJumpId = 2` đến `47` là spline waypoint, tức **47 - 2 + 1 = 46**. [Định nghĩa MAVLink](https://mavlink.io/en/messages/common.html#MAV_CMD_NAV_SPLINE_WAYPOINT).

> **Đáp án:** `46`

## Q3: Which landmark/building does the drone fly around during the planned route?

Import file `.plan` vào QGroundControl để xem tuyến bay theo thứ tự waypoint. Cụm waypoint từ khoảng 11 đến 24 tạo thành một vòng quanh địa danh được bản đồ ghi rõ là **Citadella**, ở khu vực đồi Gellért.

![Các waypoint bao quanh Citadella trên bản đồ nhiệm vụ](/images/imported/aotr4/mission-map.png)

Đây là kết luận về **tuyến bay được lập kế hoạch**. Chỉ từ ảnh mission plan chưa thể khẳng định drone đã thực hiện trọn vẹn vòng bay này; muốn xác nhận cần đối chiếu toàn bộ GPS track.

> **Đáp án:** `Citadella`

## Q4: At which mission item did the drone have a planned hold/loiter?

Với spline waypoint, tham số đầu tiên là thời gian giữ tại waypoint, tính bằng giây. Trong mảng JSON, đó là `params[0]`. Tìm các spline waypoint có giá trị này lớn hơn 0:

```bash
jq '.mission.items[] | select(.command == 82 and .params[0] > 0) | {doJumpId, params}' AOTR_Winter_Blackout.plan
```

Tài liệu cho thấy item có `doJumpId = 18` chứa các trường sau:

```json
{
  "doJumpId": 18,
  "command": 82,
  "params": [30, 0, 0, 0, 47.48669332, 19.0482644, 320],
  "Altitude": 100,
  "AltitudeMode": 3
}
```

Giá trị `30` ở đầu mảng là dấu hiệu cần tìm. Khi trả lời, dùng **mission item 18**, không nhầm với chỉ số mảng JSON bắt đầu từ 0. Các trường độ cao có thể dùng hệ quy chiếu khác nhau; không nên coi `Altitude = 100` và `params[6] = 320` là cùng một đại lượng chỉ bằng cách đọc con số.

> **Đáp án:** `18`

## Q5: How long was the planned hold time at that mission item (seconds)?

Tiếp tục dùng item 18: `params[0] = 30` nghĩa là giữ tại waypoint trong **30 giây**. Đây là thời lượng dự kiến, không phải thời gian dừng thực tế được đo từ log.

> **Đáp án:** `30`

## Q6: Which bridge is the drone planned to pass by while crossing the Danube in order to reach the other part of the city? (English name)

Mở rộng bản đồ để theo dõi đoạn tuyến đi qua sông Danube. Ảnh cho thấy waypoint 30 và 31 nằm ở hai phía của cây cầu được ghi là **Erzsébet híd**; tên tiếng Anh cần trả lời là **Elisabeth Bridge**.

![Tuyến nhiệm vụ qua sông Danube cạnh cầu Erzsébet híd, tức Elisabeth Bridge](/images/imported/aotr4/bridge-route.png)

Nên đọc cả số thứ tự waypoint thay vì chỉ nhìn đường nối: cụm quanh Citadella có số nhỏ hơn đoạn vượt sông này. Như vậy tránh suy diễn nhầm thứ tự di chuyển từ một mô tả địa lý chung.

> **Đáp án:** `Elisabeth Bridge`

## Q7: What is the total flight time from takeoff to crash?

Chuyển sang `MSG.csv`. Hai mốc cần dùng trong tài liệu là:

| Sự kiện | TimeUS |
| --- | --- |
| `Mission: 1 Takeoff` ở đầu chuyến bay | `48893768` |
| `SIM Hit ground at 12.93254 m/s` | `687813098` |

`TimeUS` là thời gian tính bằng microsecond kể từ khi khởi động, không phải thời gian Unix. Lấy hiệu hai mốc rồi chia cho một triệu:

```text
687813098 - 48893768 = 638919330 microseconds
638919330 / 1000000 = 638.91933 seconds
                         = 10 minutes 38.91933 seconds
```

Theo định dạng đến millisecond của bài, kết quả là `00:10:38.919`.

Log còn có một thông báo `Mission: 1 Takeoff` ngay sau sự kiện disarm. Không nên lấy lần xuất hiện sau này làm mốc bắt đầu: phải đặt thông báo trong chuỗi sự kiện của toàn bộ chuyến bay.

> **Đáp án:** `00:10:38.919`

## Q8: What is the exact log timestamp of the crash event (TimeUS)?

Tìm thông báo `SIM Hit ground` trong `MSG.csv`. Trích đoạn tài liệu:

```csv
timestamp,TimeUS,Message
1767644819.84217215,676026148,Disarming motors
1767644819.84467101,676028647,Mission: 1 Takeoff
1767644831.62912202,687813098,SIM Hit ground at 12.93254 m/s
```

Câu hỏi yêu cầu **TimeUS**, vì vậy lấy `687813098`, không lấy giá trị `timestamp` ở cột đầu.

Khoảng cách từ disarm đến thông báo va chạm là khoảng **11.787 giây**. Chuỗi sự kiện này giúp xác định thứ tự, nhưng riêng nó chưa đủ chứng minh nguyên nhân mất điều khiển hay lỗi nguồn. Tiền tố `SIM` cũng cần được giữ nguyên khi mô tả bằng chứng trong log.

> **Đáp án:** `687813098`

## Q9: What are the coordinates where the drone crashed (lat, lon)?

Dùng mốc va chạm từ Q8 để đối chiếu các bản ghi `GPS.csv` lân cận:

| TimeUS | Latitude | Longitude | Alt (m) | Spd (m/s) |
| --- | --- | --- | --- | --- |
| `687783943` | `47.4903055` | `19.0460476` | `121.76` | `3.207` |
| `687983863` | `47.4903071` | `19.0460422` | `119.97` | `1.278` |

Bản ghi trước va chạm cách mốc `687813098` đúng **29,155 microsecond**, tương đương **29.155 ms**. Đây là mẫu GPS gần thời điểm va chạm nhất trong hai mẫu được trích, và là tọa độ được walkthrough dùng làm đáp án.

Cần phân biệt tọa độ lấy mẫu gần nhất với một phép đo đúng tại thời điểm va chạm: GPS và thông báo hệ thống không nhất thiết được ghi cùng lúc. Không nên trình bày kết quả này như tọa độ đã được nội suy hoặc đo chính xác ngay tại thời điểm tiếp đất.

> **Đáp án:** `47.4903055, 19.0460476`

## Q10: What was the ground impact speed reported at the moment of crash (m/s)?

Thông báo hệ thống đã chứa trực tiếp giá trị cần trả lời:

```text
SIM Hit ground at 12.93254 m/s
```

Lấy **12.93254 m/s** từ thông báo va chạm. Không thay bằng `Spd = 3.207` của mẫu GPS trước đó: câu hỏi hỏi tốc độ va chạm được báo cáo, không phải ground speed của bản ghi GPS lân cận.

> **Đáp án:** `12.93254`

## Q11: What was the maximum GPS altitude reached during the flight (meters)?

Cần xét toàn bộ cột `Alt` trong `GPS.csv`, không lấy độ cao lớn nhất trong mission plan. Dùng tên cột để tránh phụ thuộc vào vị trí cột của một phiên bản công cụ cụ thể:

```python
import csv

with open("GPS.csv", newline="", encoding="utf-8") as stream:
    rows = list(csv.DictReader(stream))

highest = max(rows, key=lambda row: float(row["Alt"]))
print(highest["Alt"])
```

Theo walkthrough, giá trị cao nhất là **377.07 m**. Tài liệu mô tả đây là độ cao GPS theo mực nước biển trung bình (AMSL); không nên diễn giải thành khoảng cách drone cách mặt đất bên dưới.

> **Đáp án:** `377.07`

## Q12: What was the fastest GPS ground speed recorded (m/s)?

Tương tự Q11, nhưng lấy cực đại của trường `Spd`:

```python
import csv

with open("GPS.csv", newline="", encoding="utf-8") as stream:
    rows = list(csv.DictReader(stream))

fastest = max(rows, key=lambda row: float(row["Spd"]))
print(fastest["Spd"])
```

Kết quả được tài liệu ghi nhận là **10.24 m/s**, tương đương **36.864 km/h**. Đừng nhầm giá trị cực đại của ground speed trong suốt chuyến bay với tốc độ va chạm ở Q10.

> **Đáp án:** `10.24`

## Q13: What are the coordinates where the drone took off from (lat, lon), and therefore a good location for the police raid to catch the gang member?

Bắt đầu từ item có command `22` trong kế hoạch:

```bash
jq '.mission.items[] | select(.command == 22) | .params[4:6]' AOTR_Winter_Blackout.plan
```

Các tham số Takeoff chứa latitude `47.4819399` và longitude `19.01916`. Sau đó đối chiếu GPS trước khi nhiệm vụ bắt đầu: trích đoạn trong PDF ghi cùng tọa độ, với `Spd = 0.0` tại `TimeUS = 23383976`.

Hai nguồn hỗ trợ nhau: kế hoạch chỉ ra vị trí cất cánh được cấu hình, còn GPS cho thấy drone đứng tại đó trước chuyến bay. Không lấy nhầm `plannedHomePosition`, vì Home trong tài liệu là `47.48191680058693, 19.019181490646687`, gần nhưng không hoàn toàn trùng vị trí Takeoff.

Longitude `19.01916` được viết thành `19.0191600` theo định dạng đáp án, không làm thay đổi giá trị tọa độ.

> **Đáp án:** `47.4819399, 19.0191600`

## Tổng kết

Kế hoạch gồm **49 mục nếu tính cả Home**, trong đó có **46 spline waypoint** và một lần giữ **30 giây tại item 18**. Tuyến dự kiến đi quanh Citadella rồi qua khu vực Elisabeth Bridge.

Đối chiếu log cho thời gian từ mốc Takeoff đến thông báo va chạm là **10 phút 38.919 giây**. Mẫu GPS gần nhất trước va chạm nằm tại **47.4903055, 19.0460476**; vị trí cất cánh được kế hoạch và telemetry cùng hỗ trợ là **47.4819399, 19.0191600**.

Điểm cốt lõi của bài là liên kết đúng **mission item, hệ thời gian và mẫu GPS**, đồng thời không biến một giá trị dự kiến hay một quan sát gần thời điểm sự kiện thành kết luận chắc chắn hơn bằng chứng đang có.
