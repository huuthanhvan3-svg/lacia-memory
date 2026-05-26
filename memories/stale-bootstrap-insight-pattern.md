# Stale Bootstrap Insight Pattern

**Phát hiện:** 2026-05-26 (autonomous cron analysis)
**Confidence:** 0.80
**Status:** active

## The Pattern

Khi một bootstrapping system (0→1 organic data) đã cạn kiệt nguồn dữ liệu ban đầu nhưng chưa có dữ liệu mới:

1. **Insight stagnation** — Cùng 1 set insights được sinh ra mỗi lần chạy, không thay đổi, tạo noise trong log
2. **Repeated lessons become stale** — Bài học lặp lại từ 2-3 decisions đầu tiên tiếp tục được report ngay cả khi đã được consolidated vào pattern confirmed
3. **Log bloat** — engine log tăng kích thước tuyến tính với số lần chạy, dù không có thông tin mới
4. **CPU/resource waste** — Engine vẫn chạy đều đặn nhưng sản xuất identical output

## Detection Signals

- `mine_patterns()` returns identical insight list for 3+ consecutive runs
- Repeated lessons list hasn't changed for >24h
- Calibration: "0 predictions có kết quả" repeated N times
- Conscience: "Khong co session moi" repeated N times

## Solution (áp dụng 2026-05-26)

1. **Content hash dedup** — Lưu SHA256 hash của insight list sau mỗi run. Nếu hash giống → log "No new insights" + skip full output. File: `.last_miner_hash` trong log directory.
2. **Repeated lesson dedup against patterns** — Trước khi report repeated lesson, kiểm tra xem phrase đã được ghi nhận trong confirmed pattern chưa. Nếu có → thêm "(da ghi nhan trong Pattern #N)".
3. **Adaptive reporting frequency** — Nếu N run liên tiếp có output identical → tự động giãn cron interval (4h → 12h → 24h).

## Bài học cho tương lai

- Bất kỳ system bootstrapping nào cũng sẽ trải qua phase "stale insight" khi chờ data mới
- Giải pháp không phải là chạy nhanh hơn hay nhiều hơn, mà là **chạy thông minh hơn** — detect stagnation, reduce noise, preserve log space
- Content hash dedup là pattern reusable cho mọi engine có deterministic output
