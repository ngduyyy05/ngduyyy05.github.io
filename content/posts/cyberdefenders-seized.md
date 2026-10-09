+++
title = "CyberDefenders - Seized Lab Writeup"
date = 2026-10-09T00:00:00+07:00
draft = false
tags = ["CyberDefenders", "Memory Forensics", "Linux", "Volatility", "Rootkit"]
categories = ["Writeups"]
summary = "Phân tích bộ nhớ Linux với Volatility: lần theo lịch sử Bash, kết nối Ncat, cơ chế duy trì truy cập và dấu vết rootkit."
ShowToc = true
TocOpen = false
+++

Seized là bài lab phân tích bộ nhớ Linux. Từ bản dump bộ nhớ, ta sử dụng Volatility và CyberChef để lần theo hoạt động của kẻ tấn công, xác định backdoor, cơ chế duy trì truy cập và rootkit.

## Q1: What is the CentOS version installed on the machine?

Trong trường hợp này, chúng ta sử dụng Volatility. Cấu hình bộ nhớ là một tập hợp các ký hiệu kernel và thông tin gỡ lỗi cho phép các công cụ pháp y trích xuất dữ liệu có ý nghĩa, chẳng hạn như các tiến trình đang chạy, các tệp đang mở và cấu hình hệ thống. Khi làm việc với các hệ thống Linux, thường cần có một cấu hình bộ nhớ tùy chỉnh vì các bản phân phối Linux có các phiên bản kernel khác nhau, khiến việc sử dụng một cấu hình chung trở nên không thực tế. Trong trường hợp này, cấu hình bộ nhớ được gắn nhãn là `Centos7.3.10.1062`

![Seized Lab Q1 - ảnh 01](/images/imported/seized/seized-01.png)

![Seized Lab Q1 - ảnh 02](/images/imported/seized/seized-02.png)

## Q2: There is a command containing a strange message in the bash history. Will you be able to read it?

Plugin `linux_bash` trong Volatility được thiết kế đặc biệt để trích xuất lịch sử dòng lệnh từ bản sao bộ nhớ Linux, cho phép các nhà phân tích tái tạo lại hành động của kẻ tấn công và xác định các lệnh có khả năng độc hại.

Trước khi chạy Volatility, điều quan trọng là phải đảm bảo rằng cấu hình bộ nhớ tùy chỉnh chính xác đã có sẵn. Cấu hình tùy chỉnh cho phép Volatility diễn giải cấu trúc bên trong của bộ nhớ đã được ghi lại, giúp trích xuất các thông tin liên quan như các tiến trình đang hoạt động, các kết nối mạng đang mở và các lệnh đã thực thi. Trong trường hợp này, cấu hình tùy chỉnh là `LinuxCentos7_3_10_1062x64`, phù hợp với bản sao bộ nhớ và phiên bản kernel.

Sau khi thiết lập cấu hình chính xác, chúng ta tiến hành thực thi lệnh Volatility để truy xuất lịch sử Bash:

```bash
volatility -f dump.mem --profile=LinuxCentOS7_3_10_1062x64 linux_bash
```

Kết quả hiển thị danh sách các lệnh đã được thực thi trong terminal, cho thấy nhiều hành động khác nhau được thực hiện trên hệ thống. Trong số các lệnh được trích xuất, có một mục đáng ngờ.

![Seized Lab Q2 - ảnh 03](/images/imported/seized/seized-03.png)

Lệnh này sử dụng lệnh `echo` để in một chuỗi được mã hóa Base64 và chuyển hướng đầu ra vào một tệp văn bản có tên `youShouldr34dTh1s.txt`. Mã hóa Base64 thường được sử dụng để làm mờ dữ liệu, do đó cần phải giải mã chuỗi để hiểu nội dung của nó. Kẻ tấn công đôi khi sử dụng các kỹ thuật mã hóa như thế này để che giấu thông tin hoặc giao tiếp theo cách tránh bị phát hiện bởi các công cụ giám sát an ninh. Để giải mã thông điệp, chúng tôi sử dụng CyberChef, một công cụ pháp y mã nguồn mở mạnh mẽ cung cấp nhiều khả năng chuyển đổi dữ liệu. Bằng cách nhập chuỗi Base64 vào CyberChef và áp dụng thao tác "Từ Base64", chúng tôi đã khôi phục thành công thông điệp đã được giải mã `shkCTF{l3ts_st4rt_th3_1nv3st_75cc55476f3dfe1629ac60}`

![Seized Lab Q2 - ảnh 04](/images/imported/seized/seized-04.png)

## Q3: What is the PID of the suspicious process?

Chạy lệnh sau trong Volatility sẽ trích xuất cây tiến trình bằng plugin `linux_pstree`:

```bash
volatility -f dump.mem --profile=LinuxCentos7_3_10_1062x64 linux_pstree
```

Sau khi phân tích danh sách các tiến trình đã trích xuất, tôi xác định được một trường hợp `ncat` đang chạy trên hệ thống. Ncat, thường được gọi là Netcat, là một công cụ mạng dòng lệnh mạnh mẽ có thể đọc và ghi dữ liệu qua các kết nối mạng bằng TCP hoặc UDP. Mặc dù Ncat được các quản trị viên sử dụng rộng rãi để gỡ lỗi, kiểm tra dịch vụ mạng và tạo đường hầm bảo mật, nhưng nó cũng là một trong những tiện ích bị tin tặc lạm dụng nhiều nhất. Các tác nhân đe dọa sử dụng Ncat để tạo shell đảo ngược, thiết lập kết nối cửa hậu hoặc tạo điều kiện cho việc đánh cắp dữ liệu bằng cách truyền thông tin bị đánh cắp qua mạng. Mã định danh tiến trình (PID) của tiến trình `ncat` là 2854, đánh dấu nó là một mục đáng ngờ cần được phân tích thêm

![Seized Lab Q3 - ảnh 05](/images/imported/seized/seized-05.png)

## Q4: The attacker downloaded a backdoor to gain persistence. What is the hidden message in this backdoor?

Các cơ chế duy trì quyền truy cập cho phép kẻ tấn công giữ quyền truy cập vào hệ thống ngay cả sau khi khởi động lại hoặc các biện pháp bảo mật được áp dụng. Để đạt được điều này, kẻ tấn công thường tải xuống và thực thi các tập lệnh cho phép truy cập từ xa mà không bị phát hiện. Bằng cách xem xét lịch sử Bash được trích xuất từ bản sao bộ nhớ bằng plugin `linux_bash` của Volatility, tôi đã xác định rằng kẻ tấn công đã sao chép một kho lưu trữ GitHub có tên PythonBackup.

![Seized Lab Q4 - ảnh 06](/images/imported/seized/seized-06.png)

Việc điều tra kho lưu trữ cho thấy nhiều tập lệnh Python. Khi xem xét nội dung của tệp `snapshot.py`, tôi phát hiện một dòng mã tải xuống và thực thi một tập lệnh khác từ Pastebin.

![Seized Lab Q4 - ảnh 07](/images/imported/seized/seized-07.png)

Lệnh này tải một tập lệnh được lưu trữ trên Pastebin và chuyển trực tiếp đến shell để thực thi. Kỹ thuật này cho phép kẻ tấn công triển khai các payload độc hại từ xa mà không để lại tệp tin tồn tại lâu dài trên ổ đĩa. Để phân tích sâu hơn bản chất của backdoor này, chúng ta truy cập URL Pastebin và kiểm tra nội dung của nó. Tập lệnh chứa một thông điệp được mã hóa Base64. Giải mã chuỗi Base64 bằng CyberChef cho thấy thông điệp sau

![Seized Lab Q4 - ảnh 08](/images/imported/seized/seized-08.png)

## Q5: What are the attacker's IP address and the local port on the targeted machine?

Trong cuộc điều tra này, trước đây tôi đã phát hiện ra rằng kẻ tấn công đã triển khai một cửa hậu bằng cách thực thi lệnh Ncat lắng nghe trên cổng 12345. Cửa hậu này được cấu hình để thiết lập kết nối với một hệ thống từ xa, cho phép kẻ tấn công tương tác với máy bị xâm nhập một cách bí mật. Để xác định địa chỉ IP của kẻ tấn công và xác nhận cổng cục bộ đang được sử dụng cho kết nối, tôi sử dụng plugin của Volatility, plugin này trích xuất thông tin liên quan đến mạng từ bản sao bộ nhớ. Plugin này cung cấp một danh sách các phiên mạng đang hoạt động, bao gồm địa chỉ cục bộ và từ xa, cổng và các tiến trình liên quan. Lọc kết quả theo cổng đáng ngờ đã biết, cho phép tôi xác định chính xác kết nối mạng cụ thể mà kẻ tấn công đã lợi dụng.

![Seized Lab Q5 - ảnh 09](/images/imported/seized/seized-09.png)

Điều này xác nhận rằng hệ thống bị xâm nhập, đóng vai trò là nạn nhân, đang lắng nghe trên cổng 12345, trong khi hệ thống của kẻ tấn công, được xác định là `192.168.49.1`, là thực thể từ xa kết nối với nó

## Q6: What is the first command that the attacker executed?

Bằng cách tái tạo lại trình tự các lệnh đã thực thi, chúng ta có thể hiểu được cách kẻ tấn công điều hướng hệ thống bị xâm nhập, leo thang đặc quyền và thiết lập khả năng duy trì quyền truy cập. Để đạt được điều này, chúng ta cần phân tích danh sách tiến trình và các đối số dòng lệnh bằng cách sử dụng plugin `linux_psaux` của Volatility, cung cấp thông tin chi tiết về các tiến trình đang chạy và chi tiết thực thi của chúng. Chạy plugin `linux_psaux` sẽ trích xuất chính xác các dòng lệnh được sử dụng để khởi tạo từng tiến trình. Kiểm tra đầu ra, chúng ta thấy rằng Ncat đã được thực thi với lệnh `-lvp 12345 -e /bin/bash`, xác nhận rằng nó đã được thiết lập để lắng nghe các kết nối đến và thực thi shell Bash khi kết nối

![Seized Lab Q6 - ảnh 10](/images/imported/seized/seized-10.png)

Lệnh này là một kỹ thuật nổi tiếng được kẻ tấn công sử dụng để tạo ra một shell TTY tương tác. Khi kẻ tấn công giành được quyền truy cập ngược thông qua Ncat hoặc các công cụ tương tự, phiên shell mặc định thường thiếu đầy đủ các chức năng của thiết bị đầu cuối, khiến việc thực thi lệnh trở nên khó khăn. Bằng cách gọi Python và sử dụng hàm `pty.spawn("/bin/bash")`, kẻ tấn công nâng cấp shell lên một shell tương tác hoàn chỉnh, cho phép kiểm soát dòng lệnh tốt hơn, tự động hoàn thành bằng phím Tab và xử lý tín hiệu.

## Q7: After changing the user password, we found that the attacker still has access. Can you find out how?

Một trong những khía cạnh đáng lo ngại nhất của một vụ vi phạm an ninh là khả năng kẻ tấn công duy trì quyền truy cập ngay cả sau khi đã có những nỗ lực khắc phục ban đầu, chẳng hạn như thay đổi mật khẩu người dùng. Khả năng duy trì này cho thấy kẻ tấn công đã tạo một tài khoản đặc quyền mới, sửa đổi cơ chế xác thực hoặc cài đặt một cửa hậu cho phép tiếp tục truy cập. Trong môi trường Linux, xác thực dựa trên khóa SSH là một phương pháp phổ biến mà kẻ tấn công sử dụng để thiết lập quyền truy cập lâu dài. Bằng cách thêm khóa công khai của chúng vào tệp `~/.ssh/authorized_keys` của nạn nhân, chúng có thể bỏ qua xác thực mật khẩu và truy cập bất cứ lúc nào. Để điều tra cơ chế duy trì này, chúng tôi bắt đầu bằng cách phân tích các hoạt động của kẻ tấn công dựa trên lịch sử thực thi tiến trình của chúng. Từ những phát hiện pháp y trước đó, tôi đã xác định rằng kẻ tấn công đã sử dụng Vim tại một thời điểm nào đó, cho thấy việc sửa đổi tệp.

![Seized Lab Q7 - ảnh 11](/images/imported/seized/seized-11.png)

Vim là một trình soạn thảo văn bản mạnh mẽ có thể được sử dụng để chỉnh sửa các tệp cấu hình hệ thống, và trong trường hợp này, nó có khả năng được sử dụng để sửa đổi một tệp liên quan đến xác thực. Để xác nhận nghi ngờ này, chúng ta phải trích xuất và phân tích nội dung bộ nhớ của tiến trình Vim. Sử dụng plugin `linux_dump_map` của Volatility, chúng ta trích xuất bộ nhớ liên quan đến tiến trình Vim, đang chạy với PID 3196.

![Seized Lab Q7 - ảnh 12](/images/imported/seized/seized-12.png)

trong nội dung bộ nhớ Vim được trích xuất, tôi phát hiện một chuỗi được mã hóa Base64. Để giải mã thông điệp, chúng tôi sử dụng CyberChef. Giải mã chuỗi Base64 cho ra đoạn văn bản sau

![Seized Lab Q7 - ảnh 13](/images/imported/seized/seized-13.png)

## Q8: What is the name of the rootkit that the attacker used?

Rootkit là một trong những dạng phần mềm độc hại khó phát hiện nhất, được thiết kế để hoạt động ở cấp độ nhân hệ điều hành nhằm cung cấp cho kẻ tấn công khả năng kiểm soát hệ thống sâu rộng trong khi né tránh sự phát hiện. Các chương trình độc hại này thao túng các thành phần cốt lõi của hệ điều hành, thường bằng cách móc nối các lệnh gọi hệ thống, cho phép chúng chặn và sửa đổi các yêu cầu do ứng dụng gửi đến nhân hệ điều hành. Bằng cách thay đổi cách thức thực thi các chức năng hệ thống, rootkit có thể ẩn các tiến trình, tập tin, kết nối mạng và thậm chí cả sự hiện diện của chính chúng khỏi các công cụ bảo mật, khiến chúng cực kỳ khó phát hiện bằng phần mềm chống virus thông thường. Một trong những kỹ thuật chính được rootkit sử dụng để đạt được khả năng ẩn mình là syscall hooking, sửa đổi bảng lệnh gọi hệ thống để chuyển hướng các chức năng hợp pháp sang các chức năng độc hại. Các lệnh gọi hệ thống (syscalls) hoạt động như các trung gian giữa các ứng dụng không gian người dùng và nhân hệ điều hành, xử lý các tác vụ như truy cập tập tin, hoạt động mạng và quản lý tiến trình. Nếu rootkit thay thế một mục nhập trong bảng lệnh gọi hệ thống, nó có thể thao túng các tương tác này—cho phép nó ẩn các tiến trình, chặn các cơ chế xác thực hoặc thậm chí cài đặt thêm các phần mềm độc hại mà không gây ra cảnh báo bảo mật.

Để phát hiện bất kỳ hook syscall nào, tôi sử dụng plugin `linux_check_syscall` của Volatility, plugin này phân tích bảng gọi hệ thống và làm nổi bật bất kỳ sự không nhất quán nào.

![Seized Lab Q8 - ảnh 14](/images/imported/seized/seized-14.png)

Kết quả đầu ra cho thấy một lệnh gọi hệ thống bị can thiệp tại địa chỉ `0xffffffffc0a12470`, được gắn nhãn `sysemptyrect/syscall_callback`. Kết quả này chỉ ra rằng một hàm nhân hệ điều hành đã bị sửa đổi để chuyển hướng thực thi thông qua một hàm gọi lại, một dấu hiệu mạnh mẽ của hoạt động rootkit. Dựa trên hành vi này, chúng ta có thể tự tin quy kết cuộc tấn công cho một rootkit có tên `sysemptyrect`

## Q9: The rootkit uses crc65 encryption. What is the key?

Rootkit thường sử dụng mã hóa để bảo vệ các kênh liên lạc, làm rối mã nguồn và che giấu thông tin quan trọng khỏi sự phân tích pháp y. Một trong những phương pháp phổ biến được sử dụng cho mục đích này là mã hóa dựa trên kiểm tra dư tuần hoàn (CRC), một thuật toán nhẹ chủ yếu được sử dụng để kiểm tra tính toàn vẹn nhưng đôi khi được điều chỉnh để làm rối mã nguồn trong quá trình phát triển phần mềm độc hại. Trong trường hợp này, rootkit sử dụng mã hóa `crc65`, một cách triển khai tùy chỉnh nhưng không phổ biến của phương pháp làm rối mã nguồn dựa trên CRC được thiết kế để mã hóa các chuỗi nhạy cảm như thông tin đăng nhập cửa hậu, tên tiến trình ẩn hoặc lưu lượng mạng. Để tìm ra khóa mã hóa được rootkit sử dụng, tôi tận dụng plugin `linux_lsmod` của Volatility với cờ -P. Plugin này liệt kê tất cả các mô-đun kernel đã được tải cùng với các tham số của chúng, cho phép chúng tôi kiểm tra các giá trị ẩn được truyền trong quá trình khởi tạo mô-đun. Các mô-đun kernel có thể chấp nhận các tham số kiểm soát hành vi của chúng, và trong trường hợp rootkit, các tham số này có thể bao gồm khóa mã hóa, cài đặt làm rối mã nguồn hoặc địa chỉ máy chủ điều khiển (C2).

![Seized Lab Q9 - ảnh 15](/images/imported/seized/seized-15.png)

Kết quả đầu ra liệt kê nhiều mô-đun kernel, bao gồm một mục đáng ngờ liên quan đến `sysemptyrect`, mà trước đây chúng tôi đã xác định là một lệnh gọi hệ thống bị can thiệp liên kết với rootkit. Trong số các tham số được liệt kê, tôi tìm thấy một mục có nhãn `crc65 key=1337tibbartibbar`
