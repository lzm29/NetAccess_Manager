# NetAccess Manager — Nhóm 13 / đề tài 14

Phiên bản Lab 0.1, Flask + MySQL 8.4 LTS, chạy bằng Docker Compose trên Windows. Dùng **nguyên vẹn** file SQL đã thống nhất (6 bảng, 10 FK); không có dữ liệu giả định sẵn ngoài 3 vai trò. CSDL Docker độc lập với MySQL84 trên Windows (3307). Chỉ mô phỏng áp dụng trong CSDL, không điều khiển firewall/proxy, không bắt gói tin, không phân giải DNS. Không dùng cho mạng thật.

## 1. Chuẩn bị

- Docker Desktop for Windows: https://docs.docker.com/desktop/setup/install/windows-install/ (WSL 2, Linux containers). Nếu WSL chưa có, PowerShell quản trị: `wsl --install`, khởi động lại nếu được yêu cầu, `wsl --update`.
- VS Code: https://code.visualstudio.com/ (không bắt buộc).
- Mở Docker Desktop. Mở PowerShell/Terminal tại thư mục chứa `compose.yaml` (sau khi giải nén ZIP). Kiểm tra `docker version` và `docker compose version`.

## 2. Khởi chạy lần đầu

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\setup-env.ps1
docker compose up -d --build
docker compose ps
docker compose exec web flask --app app verify-db
docker compose exec web flask --app app seed-demo
```

Script PowerShell chỉ tạo `.env` với ba bí mật ngẫu nhiên và không ghi đè khi chạy lại. Không chia sẻ `.env` hoặc đăng lên Git. Lệnh seed-demo yêu cầu nhập và xác nhận ba mật khẩu riêng (12–128 ký tự), không hiển thị khi gõ. Tên đăng nhập: `requester`, `approver`, `admin`. Không dùng mật khẩu root MySQL làm mật khẩu Web. Lệnh seed chỉ chạy một lần trên CSDL chưa có users. Nếu bỏ dở trước commit, có thể chạy lại.

Truy cập http://localhost:8080. Kiểm tra kết nối tại http://localhost:8080/health (JSON `status: ok`). Nếu dịch vụ chưa khỏe, chạy `docker compose logs --tail=100 db web` và `docker compose ps`. Không xóa volume để thử sửa lỗi.

## 3. Demo từ đầu tới cuối

1. Đăng nhập `requester`; tạo đề xuất ADD, WHITELIST, DOMAIN, `docs.example.test`, mô tả `Tài liệu kỹ thuật`, lý do `Phục vụ công việc`. Xác nhận trạng thái PENDING; danh sách vẫn chưa có quy tắc.
2. Đăng xuất, đăng nhập `approver`; mở hàng đợi, chọn đề xuất và phê duyệt. Trạng thái APPROVED; danh sách vẫn chưa đổi.
3. Đăng xuất, đăng nhập `admin`; mở hàng đợi áp dụng; nếu muốn kiểm thử lỗi, tích ô lỗi mô phỏng và áp dụng. Xác nhận APPLY_FAILED, log lần 1 FAILED, chưa có quy tắc. Bỏ tích và thử lại; xác nhận APPLIED, log lần 2 SUCCESS, quy tắc ACTIVE.
4. Admin mở kiểm chứng, nhập DOMAIN `docs.example.test` -> ALLOW; nhập `unknown.example.test` -> BLOCK. Đây chỉ là kết quả mô phỏng, không kiểm tra truy cập website thật.
5. Kiểm tra nhật ký kiểm toán, lịch sử trước/sau. Lặp với ADD BLACKLIST cùng tên miền, đánh dấu xác nhận xung đột và ghi nhận xét khi duyệt -> BLOCK. Gỡ Blacklist qua đề xuất REMOVE -> ALLOW nếu Whitelist vẫn hiệu lực. UPDATE chỉ đổi mô tả. Không sửa trực tiếp dữ liệu bằng Workbench.
6. Thử từ chối đề xuất (bắt buộc lý do), tạo đề xuất trùng, nhập IP/domain sai, thử URL, thử quyền không đúng. Dùng hai tài khoản Requester khác nhau kiểm tra phạm vi lịch sử. Khóa tài khoản để kiểm tra phiên cũ bị từ chối ở yêu cầu tiếp theo.

## 4. Kết nối Workbench tới CSDL Docker

Tạo kết nối mới, Caption `NetAccess Docker Lab`, Host `127.0.0.1`, Port `3308`, User `netaccess_app`, Password là giá trị `DB_PASSWORD` trong `.env`, Default Schema `netaccess_manager`. Dùng kết nối này để xem cấu trúc và dữ liệu, không trực tiếp sửa danh sách/nhật ký. Kết nối Windows cũ tại 3307 vẫn giữ nguyên. Tài khoản ứng dụng không có quyền xóa bảng hoặc sửa/xóa audit_logs; tài khoản root DB dành cho quản trị, không dùng trong Flask.

```sql
SELECT VERSION(), @@port;
SHOW TABLES FROM netaccess_manager;
SELECT * FROM netaccess_manager.roles;
SELECT request_code, request_status FROM netaccess_manager.change_requests;
```
`@@port` trong container trả 3306 (cổng bên trong), Workbench kết nối từ Windows qua 3308.

## 5. Dừng / chạy lại / cập nhật mã

- `docker compose stop` để dừng; `docker compose start` để chạy lại.
- `docker compose down` xóa container/network nhưng giữ named volume mặc định; `docker compose up -d --build` để tạo lại.
- Không dùng `docker compose down -v` nếu muốn giữ dữ liệu. Các script init SQL chỉ chạy khi volume MySQL mới trống; thay file SQL không tự sửa DB đang có.
- Nếu chỉnh code: `docker compose up -d --build web`.
- Nếu cổng 8080 hoặc 3308 bị chiếm, sửa phần bên trái ánh xạ `ports` trong compose.yaml, không đổi cổng nội bộ. Nếu thay bí mật sau khi DB đã tạo, phải đổi mật khẩu trong DB tương ứng; không xóa volume.

## 6. Mức hoàn thành và giới hạn

- FR-01 đến FR-11: đã viết mã cho luồng Lab: xác thực, phân quyền, danh sách, đề xuất ADD/UPDATE/REMOVE, duyệt/từ chối, áp dụng mô phỏng, thất bại có chủ đích/thử lại, lịch sử, nhật ký và kiểm chứng chính sách. UC13 xem kết quả từng lần và dữ liệu trước/sau; chưa có đối soát thực thi ngoài CSDL. Trạng thái UNVERIFIED và execution_mode LIVE vẫn giữ trong SQL nhưng không được sinh bởi phiên bản mô phỏng này. APPLYING/RUNNING là trạng thái trung gian trong giao dịch nguyên tử nên không nhất thiết quan sát được từ phiên khác.
- RBAC kiểm tra lại tài khoản/vai trò ở mỗi request, POST có CSRF, mật khẩu băm scrypt, truy vấn tham số hóa, khóa ghi tuần tự trong MySQL, lưu snapshot, không ghi password/hash/token trong audit. Tách ba ID người đề xuất/duyệt/áp dụng. Chưa có kiểm thử tấn công, giới hạn đăng nhập, HTTPS, phân trang đầy đủ (giới hạn 200 dòng), sao lưu tự động hoặc triển khai production. Dịch vụ chỉ bind localhost. Mọi người dùng demo đều phải dùng mật khẩu riêng.
- Đã kiểm tra Python compile, cú pháp Jinja, cấu trúc YAML và 4 unit test (chuẩn hóa IP/domain, kiểm tra định dạng, chính sách, snapshot JSON). Chưa chạy Docker/Flask/MySQL thực tế trong môi trường tạo file, chưa kiểm chứng end-to-end. Chạy `verify-db` và các kịch bản mục 3 trên máy Windows để xác nhận. Mục tiêu hiệu năng NFR-06 chưa đo. Không dùng báo cáo để khẳng định đã triển khai/kiểm thử trước khi có kết quả thực tế.
- Nếu muốn kiểm thử đơn vị trong container: `docker compose exec web python -c "from domain import normalize_target; print(normalize_target('DOMAIN','Docs.Example.TEST.'))"`. Bộ test đầy đủ trong `tests/` có thể chạy từ thư mục dự án bằng Python local `python -m unittest discover -s tests -v` (không cần Flask cho test này).
