# LACIA EVOLUTION ENGINE — Reference

## Files
| File | Path | Chức năng |
|------|------|-----------|
| Evolution engine | `~/.lacia-memory/lacia_evolution.py` | 3 engines: calibration, conscience, pattern-miner |
| Extended memory | `~/.lacia-memory/lacia_memory.py` | SQLite CLI: decisions, patterns, edges, predictions |
| Database | `~/.lacia-memory/lacia_memory.db` | 5 tables, unlimited |
| Evolution logs | `~/.lacia-memory/logs/` | Daily + monthly logs |

## CLI Commands
```
lacia-evolve full              # Chạy cả 3 engine
lacia-evolve calibrate         # Kiểm tra calibration
lacia-evolve conscience        # Phát hiện core lock violation
lacia-evolve mine              # Pattern mining

lacia-mem dec <cat> <text>     # Ghi quyết định
lacia-mem outcome <id> <r> <c> # Cập nhật kết quả
lacia-mem edge <name> win|loss # Track edge
lacia-mem pattern <cat> <txt>  # Ghi pattern
lacia-mem pred <txt> <p> <h>   # Ghi dự đoán
lacia-mem qdec [cat]           # Tra quyết định
lacia-mem calib                # Kiểm tra calibration
lacia-mem nightly              # Consolidate + backup
```

## Cron Jobs Active
| Name | Schedule | Function |
|------|----------|----------|
| lacia-calibrate | 0 */12 * * * | Calibration check |
| lacia-conscience | 0 */6 * * * | Session violation scan |
| lacia-pattern-miner | 0 5 * * * | Pattern mining |
| lacia-nightly-consolidate | 59 23 * * * | Consolidate + GitHub backup |
| lacia-core-self-check | 0 */4 * * * | Core lock drift check |

## Backup Targets (GitHub: huuthanhvan3-svg/lacia-core-backup)
- `lacia_memory.db` — extended memory SQLite
- `LACIA_CORE_V6.md` — core soul file
- `state.db` — Hermes session DB
- `config.yaml` — Hermes config
- `skills/` — all skills

## Evolution Loop
Hành động → Ghi decision (lacia-mem dec) → Engine phân tích (cron) → Phát hiện pattern → Cập nhật skill/memory → Hành động tốt hơn → Lặp lại.
