-- Nhóm 13 | Đề tài 14 | Thiết kế CSDL v1.0
-- MySQL 8.0.16+ (CHECK được thực thi). Chạy trên CSDL Lab mới.
-- Không DROP dữ liệu; không tạo tài khoản/mật khẩu mặc định.
-- DDL không thay thế kiểm tra quyền, giao dịch và đối soát tại backend.
CREATE DATABASE IF NOT EXISTS netaccess_manager
  CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;
USE netaccess_manager;

CREATE TABLE roles (
  role_id TINYINT UNSIGNED PRIMARY KEY,
  role_code VARCHAR(20) CHARACTER SET ascii COLLATE ascii_bin NOT NULL UNIQUE,
  role_name VARCHAR(100) NOT NULL,
  CHECK (role_code IN ('REQUESTER','APPROVER','ADMIN'))
) ENGINE=InnoDB;

CREATE TABLE users (
  user_id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  role_id TINYINT UNSIGNED NOT NULL,
  username VARCHAR(64) NOT NULL UNIQUE,
  password_hash VARCHAR(255) NOT NULL,
  full_name VARCHAR(150) NOT NULL,
  account_status ENUM('ACTIVE','LOCKED') NOT NULL DEFAULT 'ACTIVE',
  created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
  FOREIGN KEY (role_id) REFERENCES roles(role_id),
  CHECK (CHAR_LENGTH(TRIM(username)) > 0),
  CHECK (CHAR_LENGTH(TRIM(full_name)) > 0)
) ENGINE=InnoDB;

CREATE TABLE list_entries (
  entry_id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  list_type ENUM('WHITELIST','BLACKLIST') NOT NULL,
  target_type ENUM('IPV4','DOMAIN') NOT NULL,
  target_value VARCHAR(253) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  description TEXT NOT NULL,
  entry_status ENUM('ACTIVE','INACTIVE') NOT NULL DEFAULT 'ACTIVE',
  version_no INT UNSIGNED NOT NULL DEFAULT 1,
  created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
  deactivated_at DATETIME(6) NULL,
  -- NULL không bị ràng buộc duy nhất trong MySQL: giữ được lịch sử nhiều lần thêm/loại bỏ.
  active_slot TINYINT GENERATED ALWAYS AS (CASE WHEN entry_status='ACTIVE' THEN 1 ELSE NULL END) STORED,
  UNIQUE KEY uq_active_entry (list_type,target_type,target_value,active_slot),
  KEY ix_entry_target (target_type,target_value,entry_status),
  CHECK (CHAR_LENGTH(target_value)>0),
  CHECK (version_no>=1),
  CHECK ((entry_status='ACTIVE' AND deactivated_at IS NULL) OR
         (entry_status='INACTIVE' AND deactivated_at IS NOT NULL))
) ENGINE=InnoDB;

CREATE TABLE change_requests (
  request_id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  request_code VARCHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL UNIQUE,
  requested_by BIGINT UNSIGNED NOT NULL,
  list_type ENUM('WHITELIST','BLACKLIST') NOT NULL,
  target_type ENUM('IPV4','DOMAIN') NOT NULL,
  target_value VARCHAR(253) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  change_action ENUM('ADD','UPDATE','REMOVE') NOT NULL,
  target_entry_id BIGINT UNSIGNED NULL,
  target_version INT UNSIGNED NULL,
  -- Snapshot bất biến: quy tắc hiện hành nếu sửa/xóa, quy tắc đối lập nếu có.
  before_snapshot JSON NULL,
  conflict_snapshot JSON NULL,
  proposed_description TEXT NULL,
  reason TEXT NOT NULL,
  request_status ENUM('PENDING','APPROVED','REJECTED','APPLYING','APPLIED','APPLY_FAILED','INVALIDATED') NOT NULL DEFAULT 'PENDING',
  created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  reviewed_by BIGINT UNSIGNED NULL,
  reviewed_at DATETIME(6) NULL,
  review_decision ENUM('APPROVED','REJECTED') NULL,
  review_note TEXT NULL,
  applied_entry_id BIGINT UNSIGNED NULL,
  invalid_reason TEXT NULL,
  updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
  -- Một yêu cầu mở cho cùng loại/giá trị, không phân biệt White/Black.
  open_slot TINYINT GENERATED ALWAYS AS (CASE WHEN request_status IN ('PENDING','APPROVED','APPLYING','APPLY_FAILED') THEN 1 ELSE NULL END) STORED,
  UNIQUE KEY uq_open_target (target_type,target_value,open_slot),
  KEY ix_request_status_time (request_status,created_at),
  KEY ix_request_owner_time (requested_by,created_at),
  KEY ix_request_target (target_type,target_value,created_at),
  FOREIGN KEY (requested_by) REFERENCES users(user_id),
  FOREIGN KEY (reviewed_by) REFERENCES users(user_id),
  FOREIGN KEY (target_entry_id) REFERENCES list_entries(entry_id),
  FOREIGN KEY (applied_entry_id) REFERENCES list_entries(entry_id),
  CHECK (CHAR_LENGTH(TRIM(reason))>0 AND CHAR_LENGTH(target_value)>0),
  CHECK ((change_action='ADD' AND target_entry_id IS NULL AND target_version IS NULL AND before_snapshot IS NULL) OR
         (change_action IN ('UPDATE','REMOVE') AND target_entry_id IS NOT NULL AND target_version IS NOT NULL AND target_version>=1 AND before_snapshot IS NOT NULL)),
  CHECK ((change_action IN ('ADD','UPDATE') AND proposed_description IS NOT NULL AND CHAR_LENGTH(TRIM(proposed_description))>0) OR
         (change_action='REMOVE' AND proposed_description IS NULL)),
  CHECK (reviewed_by IS NULL OR reviewed_by<>requested_by),
  CHECK ((request_status='PENDING' AND reviewed_by IS NULL AND reviewed_at IS NULL AND review_decision IS NULL) OR
         (request_status='REJECTED' AND reviewed_by IS NOT NULL AND reviewed_at IS NOT NULL AND review_decision IS NOT NULL AND review_decision='REJECTED') OR
         (request_status IN ('APPROVED','APPLYING','APPLIED','APPLY_FAILED','INVALIDATED') AND reviewed_by IS NOT NULL AND reviewed_at IS NOT NULL AND review_decision IS NOT NULL AND review_decision='APPROVED')),
  CHECK (request_status<>'REJECTED' OR (review_note IS NOT NULL AND CHAR_LENGTH(TRIM(review_note))>0)),
  CHECK (conflict_snapshot IS NULL OR review_decision IS NULL OR review_decision<>'APPROVED' OR (review_note IS NOT NULL AND CHAR_LENGTH(TRIM(review_note))>0)),
  CHECK ((request_status='APPLIED' AND applied_entry_id IS NOT NULL) OR (request_status<>'APPLIED' AND applied_entry_id IS NULL)),
  CHECK ((request_status='INVALIDATED' AND invalid_reason IS NOT NULL AND CHAR_LENGTH(TRIM(invalid_reason))>0) OR (request_status<>'INVALIDATED' AND invalid_reason IS NULL))
) ENGINE=InnoDB;

CREATE TABLE deployment_logs (
  deployment_id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  request_id BIGINT UNSIGNED NOT NULL,
  attempt_no INT UNSIGNED NOT NULL,
  applied_by BIGINT UNSIGNED NOT NULL,
  execution_mode ENUM('SIMULATED','LIVE') NOT NULL,
  started_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  finished_at DATETIME(6) NULL,
  result ENUM('RUNNING','SUCCESS','FAILED','UNVERIFIED') NOT NULL DEFAULT 'RUNNING',
  before_snapshot JSON NULL,
  after_snapshot JSON NULL,
  result_detail TEXT NULL,
  reconciliation_required BOOLEAN NOT NULL DEFAULT FALSE,
  reconciliation_note TEXT NULL,
  reconciled_by BIGINT UNSIGNED NULL,
  reconciled_at DATETIME(6) NULL,
  -- Chỉ một lần đang chạy hoặc đang chờ đối soát, chỉ một lần thành công.
  blocking_slot TINYINT GENERATED ALWAYS AS (CASE WHEN result='RUNNING' OR reconciliation_required=1 THEN 1 ELSE NULL END) STORED,
  success_slot TINYINT GENERATED ALWAYS AS (CASE WHEN result='SUCCESS' THEN 1 ELSE NULL END) STORED,
  UNIQUE KEY uq_attempt (request_id,attempt_no),
  UNIQUE KEY uq_blocking (request_id,blocking_slot),
  UNIQUE KEY uq_success (request_id,success_slot),
  FOREIGN KEY (request_id) REFERENCES change_requests(request_id),
  FOREIGN KEY (applied_by) REFERENCES users(user_id),
  FOREIGN KEY (reconciled_by) REFERENCES users(user_id),
  CHECK (attempt_no>=1),
  CHECK (reconciliation_required IN (0,1)),
  CHECK ((result='RUNNING' AND finished_at IS NULL) OR
         (result<>'RUNNING' AND finished_at IS NOT NULL AND finished_at>=started_at)),
  CHECK (result='RUNNING' OR (result_detail IS NOT NULL AND CHAR_LENGTH(TRIM(result_detail))>0)),
  CHECK (result<>'UNVERIFIED' OR reconciliation_required=1),
  CHECK (result NOT IN ('RUNNING','SUCCESS') OR reconciliation_required=0),
  CHECK (result<>'SUCCESS' OR after_snapshot IS NOT NULL),
  CHECK ((reconciled_by IS NULL AND reconciled_at IS NULL AND reconciliation_note IS NULL) OR
         (reconciled_by IS NOT NULL AND reconciled_at IS NOT NULL AND reconciliation_note IS NOT NULL AND CHAR_LENGTH(TRIM(reconciliation_note))>0))
) ENGINE=InnoDB;

CREATE TABLE audit_logs (
  audit_id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  actor_user_id BIGINT UNSIGNED NULL,
  actor_role_code VARCHAR(20) CHARACTER SET ascii COLLATE ascii_bin NULL,
  request_id BIGINT UNSIGNED NULL,
  entity_type ENUM('USER','REQUEST','ENTRY','DEPLOYMENT','AUTH','POLICY_CHECK') NOT NULL,
  entity_id BIGINT UNSIGNED NULL,
  action_code VARCHAR(50) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  outcome ENUM('SUCCESS','FAILED','DENIED') NOT NULL,
  old_data JSON NULL,
  new_data JSON NULL,
  detail TEXT NULL,
  occurred_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  FOREIGN KEY (actor_user_id) REFERENCES users(user_id),
  FOREIGN KEY (request_id) REFERENCES change_requests(request_id),
  KEY ix_audit_request_time (request_id,occurred_at),
  KEY ix_audit_actor_time (actor_user_id,occurred_at),
  KEY ix_audit_entity (entity_type,entity_id,occurred_at)
) ENGINE=InnoDB;

INSERT INTO roles (role_id,role_code,role_name) VALUES
  (1,'REQUESTER','Nhân viên IT'),
  (2,'APPROVER','Cán bộ an toàn thông tin'),
  (3,'ADMIN','Quản trị viên mạng');

-- Backend phải thực hiện (chưa cài đặt trong DDL):
-- 1. Chuẩn hóa IPv4/domain, xác thực quyền và trạng thái tài khoản; không tự đổi vai trò.
-- 2. Tạo mã yêu cầu duy nhất, snapshot JSON đúng cấu trúc, không đổi nội dung đã gửi.
-- 3. Giao dịch SELECT ... FOR UPDATE trên request khi duyệt/áp dụng; kiểm tra vai trò,
--    ba người khác nhau theo ID bất kể đổi vai trò về sau; kiểm tra version và xung đột.
-- 4. Một worker triển khai tuần tự cho một điểm thực thi; ghi APPLYING + RUNNING trước I/O.
--    Xác minh/đối soát trước khi cập nhật hiệu lực. Kết quả chưa rõ giữ APPLYING + UNVERIFIED, không cho retry hoặc
--    kết thúc INVALIDATED; khi xác minh mới thành công, hoàn tất cùng lần thực hiện.
-- 5. Cập nhật entry + request + deployment + audit trong một giao dịch khi xác minh thành công;
--    nếu lỗi sau tác động bên ngoài, đối soát trạng thái thực tế trước khi chạy tiếp.
-- 6. Không cấp DELETE/UPDATE audit_logs cho ứng dụng thường; không log mật khẩu/hash/token.
-- 7. Không dùng cùng CSDL cho Lab mô phỏng và môi trường LIVE.
-- 8. Lọc lịch sử Requester theo requested_by; Approver chỉ xem nghiệp vụ; Admin xem quản trị.
