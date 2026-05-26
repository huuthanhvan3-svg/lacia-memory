# Idle Edge Confirmation: quyet_doan_truc_tiep (2026-05-26)

**Source:** Pattern Miner #16 + autonomous cron analysis 2026-05-26 19:00
**Confidence:** 0.90
**Status:** confirmed

## Finding

Edge `quyet_doan_truc_tiep` (active replacement for deprecated `indecisiveness_correction`) remains at **0 trades** as of 2026-05-26 19:00, despite:

1. Pattern #16 flagging the idle at 09:01 (10+ hours ago)
2. SKILL.md Section XXI documenting the recording mandate since 2026-05-25
3. The edge being active for 2+ days (created 2026-05-24 13:01)

## Root Cause

Not a bug — **structural bootstrap limitation**. The edge trigger is:
> "Mỗi response cho Chủ nhân có câu trả lời trực tiếp"

But no user sessions exist since 2026-05-20. The edge requires user interaction to fire. No amount of skill documentation can fix this — it's an organic data dependency.

## Meta-Pattern Extension

This extends the bootstrap-meta-pattern (Pattern #15):
- **Time-delta guard**: Add "hours since last_used" tracking for active edges. If >48h with 0 trades → auto-dormant.
- **Trigger dependency classification**: Edges should declare if they depend on user input vs. system events.
- **User-input-dependent edges cannot bootstrap autonomously** by definition — they must be excluded from "edge health" metrics during bootstrap phase.

## Recommendations

1. **Demote quyet_doan_truc_tiep** to 'dormant' status during bootstrap (update DB directly)
2. **Add trigger type field** to edges schema: 'user_interaction', 'system_event', or 'autonomous'
3. **Re-evaluate** after first prediction outcome arrives (~2026-05-31) or first user session
