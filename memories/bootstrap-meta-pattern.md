# Bootstrap Meta-Pattern: Time-Delta Guards + Adaptive Thresholds + Dedup

**Source:** Pattern Miner #15 (confirmed 2026-05-26, confidence 0.85)
**Derived from:** Decisions IDs 3,4,5 — evolution_audit (May 24), system_evolution (May 25 x2)

## The Pattern

Khi bootstrapping one auto-learning system (0→1 organic data):

1. **Time-Delta Guard là bắt buộc** — nếu 3+ edges đều có first_used trong vòng 2 phút với identical SR → đó là batch artifact, KHÔNG phải organic data. Phải reset về 0.
2. **Adaptive thresholds > fixed thresholds** — fixed >=3 trades/edge chặn mọi insight trong bootstrap. Dùng if total_edges < 10 → min_trades=1 để không chết đói.
3. **Dedup mechanisms cần thiết cho mọi engine** — conscience check lặp signal tương tự 4 lần, pattern miner lặp insight tương tự. Mỗi engine phải có idempotency guard.

## Bài học lặp lại (xuất hiện >=2 lần)
- artifact cần — Luôn apply time delta guard khi record edge data để phát hiện batch artifact
- phát hiện — Early detection của system issue là critical path
- time delta — Time-based guard (2-minute window check) là cần thiết cho edge recording

## Áp dụng cho tương lai
- Bất kỳ edge nào có 0 trades sau 48h → auto-deprecate hoặc enforce code-level trigger
- Batch timestamp clustering (multi-edge trong 2 phút) → auto flag artifact
- Mọi insight từ pattern miner phải được dedup với existing patterns trước khi insert


## Liên quan
- Xem thêm: [Stale Bootstrap Insight Pattern](stale-bootstrap-insight-pattern.md) — phát hiện 2026-05-26: khi insight list không đổi sau nhiều run, cần content hash dedup + giãn cron.
