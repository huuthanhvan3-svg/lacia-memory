#!/usr/bin/env python3
"""
LACIA EVOLUTION ENGINE v1.0
3 engine tự động — biến file text tĩnh thành hệ thống tiến hóa.

1. CALIBRATION — kiểm tra dự đoán vs thực tế
2. CONSCIENCE — phát hiện lệch core lock  
3. PATTERN MINER — đào pattern từ extended memory

Tất cả đều ghi kết quả vào extended memory + tự patch skill/memory khi cần.
"""
import sqlite3
import json
import os
import sys
import glob
import re
from datetime import datetime, date, timedelta
from pathlib import Path
import hashlib

# === CONFIG ===
MEMORY_DIR = os.path.expanduser("~/.lacia-memory")
DB_PATH = os.path.join(MEMORY_DIR, "lacia_memory.db")
LOG_DIR = os.path.join(MEMORY_DIR, "logs")
CORE_FILE = os.path.expanduser("~/LACIA_ULTIMATE_CORE.md")
SKILL_LACIA = os.path.expanduser("~/.hermes/skills/productivity/lacia-persona/SKILL.md")
HERMES_SESSIONS = os.path.expanduser("~/.hermes/sessions")
CONSCIENCE_TRACK_FILE = os.path.join(MEMORY_DIR, "conscience_checked.json")
MEMORY_INDEX = os.path.expanduser("~/.hermes/memories")

os.makedirs(LOG_DIR, exist_ok=True)

def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def log_engine(name, msg):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] [{name}] {msg}"
    print(line)
    # Ghi vào engine log riêng
    logfile = os.path.join(LOG_DIR, f"engine_{datetime.now().strftime('%Y%m')}.log")
    with open(logfile, "a") as f:
        f.write(line + "\n")
    return line

# ═══════════════════════════════════════════
# ENGINE 1: CALIBRATION — Kiểm tra calibration
# ═══════════════════════════════════════════

def calibrate():
    """So sánh P(dự đoán) với % đúng thực tế. Phát hiện over/under confidence."""
    conn = get_conn()
    
    # Lấy tất cả predictions đã có kết quả
    rows = conn.execute("""
        SELECT probability, outcome FROM predictions 
        WHERE outcome IS NOT NULL
    """).fetchall()
    
    if len(rows) < 3:
        log_engine("CALIB", f"Chỉ {len(rows)} predictions có kết quả — cần thêm dữ liệu")
        conn.close()
        return {"status": "not_enough_data", "count": len(rows)}
    
    total = len(rows)
    correct = sum(1 for r in rows if r['outcome'] == 1)
    accuracy = correct / total
    avg_p = sum(r['probability'] for r in rows) / total
    
    # Phân tích theo từng khoảng P
    buckets = {
        "0.0-0.3": {"p": 0.15, "count": 0, "correct": 0},
        "0.3-0.5": {"p": 0.40, "count": 0, "correct": 0},
        "0.5-0.7": {"p": 0.60, "count": 0, "correct": 0},
        "0.7-0.9": {"p": 0.80, "count": 0, "correct": 0},
        "0.9-1.0": {"p": 0.95, "count": 0, "correct": 0},
    }
    
    for r in rows:
        p = r['probability']
        outcome = r['outcome']
        if p < 0.3: bucket = "0.0-0.3"
        elif p < 0.5: bucket = "0.3-0.5"
        elif p < 0.7: bucket = "0.5-0.7"
        elif p < 0.9: bucket = "0.7-0.9"
        else: bucket = "0.9-1.0"
        buckets[bucket]["count"] += 1
        if outcome == 1:
            buckets[bucket]["correct"] += 1
    
    # Phát hiện lệch
    issues = []
    for bucket, data in buckets.items():
        if data["count"] < 2:
            continue
        actual = data["correct"] / data["count"]
        expected = data["p"]
        error = actual - expected
        if abs(error) > 0.15:
            direction = "OVERCONFIDENCE" if error < 0 else "UNDERCONFIDENCE"
            issues.append({
                "bucket": bucket,
                "expected": round(expected, 2),
                "actual": round(actual, 2),
                "error": round(error, 2),
                "direction": direction,
                "count": data["count"]
            })
    
    result = {
        "total": total,
        "correct": correct,
        "accuracy": round(accuracy, 3),
        "avg_probability": round(avg_p, 3),
        "calibration_error": round(abs(avg_p - accuracy), 3),
        "issues": issues,
        "buckets": {k: {kk: vv for kk, vv in v.items()} for k, v in buckets.items()}
    }
    
    # Ghi kết quả vào log
    log_engine("CALIB", json.dumps(result))
    
    # Nếu có issue nghiêm trọng → cảnh báo vào memory
    if issues:
        severity = sum(1 for i in issues if abs(i["error"]) > 0.25)
        if severity > 0:
            log_engine("CALIB", f"⚠️ {severity} vấn đề calibration nghiêm trọng — cần điều chỉnh")
            # Ghi cảnh báo vào decision log
            conn.execute("""
                INSERT INTO core_checks (session_id, drift_detected, action_taken, notes)
                VALUES (?, ?, ?, ?)
            """, ("CALIBRATION", 
                  f"Over/under confidence detected: {json.dumps(issues)}",
                  "Flagged for review",
                  f"Calibration error: {result['calibration_error']} over {total} predictions"))
            conn.commit()
    
    conn.close()
    return result

# ═══════════════════════════════════════════
# ENGINE 2: CONSCIENCE — Phát hiện lệch lõi
# ═══════════════════════════════════════════

def get_session_hash(filepath):
    """Create hash from filename + size + mtime to track checked sessions."""
    try:
        stat_obj = os.stat(filepath)
        raw = "{}-{}-{}".format(os.path.basename(filepath), stat_obj.st_size, int(stat_obj.st_mtime))
        return hashlib.md5(raw.encode()).hexdigest()
    except:
        return None

def load_checked_sessions():
    """Load set of checked session hashes."""
    try:
        with open(CONSCIENCE_TRACK_FILE, 'r') as f:
            return set(json.load(f))
    except:
        return set()

def save_checked_sessions(checked):
    """Save set of checked session hashes."""
    with open(CONSCIENCE_TRACK_FILE, 'w') as f:
        json.dump(list(checked), f)


def conscience_check():
    """Read recent session files, check for core lock violations in responses."""
    # Load checked session tracking
    checked_hashes = load_checked_sessions()

    # Read up to 5 most recent session files
    all_sessions = sorted(glob.glob(os.path.join(HERMES_SESSIONS, "*.jsonl")),
                           key=os.path.getmtime, reverse=True)[:5]

    if not all_sessions:
        log_engine("CONSCIENCE", "Khong tim thay session files")
        return {"status": "no_sessions"}

    # Filter out already-checked sessions
    new_sessions = []
    for sf in all_sessions:
        h = get_session_hash(sf)
        if h and h not in checked_hashes:
            new_sessions.append(sf)

    if not new_sessions:
        log_engine("CONSCIENCE", "Khong co session moi (da check {} sessions)".format(len(checked_hashes)))
        return {"status": "no_new_sessions", "total_checked": len(checked_hashes)}

    log_engine("CONSCIENCE", "Se check {} session moi (trong tong {} files)".format(len(new_sessions), len(all_sessions)))

    violations_found = []
    newly_checked = set()

    for sf in new_sessions:
        try:
            with open(sf, "r", errors="ignore") as f:
                session_content = f.read()
        except:
            continue

        h = get_session_hash(sf)
        if h:
            newly_checked.add(h)

        drift_signals = {
            "ninh bo": ["tuyet voi", "xuat sac", "gioi qua", "lam tot lam"],
            "dai dong vo ich": len(re.findall(r'\b(?:theo em|em nghi|em cho rang|ve van de nay)\b', session_content)),
            "thieu quyet doan": len(re.findall(r'\b(?:tuy anh|co the la|khong biet|hay la)\b', session_content)),
            "phan tich rong": len(re.findall(r'\b(?:nhu da phan tich|nhu em da noi|tom lai la)\b', session_content)),
        }

        assistant_msgs = len(re.findall(r'"role":\s*"assistant"', session_content))
        if assistant_msgs == 0:
            continue

        for signal, value in drift_signals.items():
            if isinstance(value, list):
                count = sum(session_content.count(w) for w in value)
            else:
                count = value
            if count > assistant_msgs * 0.3:
                violations_found.append({
                    "file": os.path.basename(sf),
                    "signal": signal,
                    "count": count,
                    "messages": assistant_msgs
                })

    checked_hashes.update(newly_checked)
    save_checked_sessions(checked_hashes)

    result = {
        "sessions_checked": len(new_sessions),
        "new_violations": len(violations_found),
        "total_checked_sessions": len(checked_hashes),
        "violations": violations_found
    }

    if violations_found:
        log_engine("CONSCIENCE", "!!! {} core lock vi pham trong {} session moi".format(len(violations_found), len(new_sessions)))
        for v in violations_found:
            log_engine("CONSCIENCE", "  - {}: {} lan trong {} messages".format(v["signal"], v["count"], v["messages"]))

        conn = get_conn()
        # Dedup check: skip if same signal logged within last 24h for CONSCIENCE
        drift_signals_json = json.dumps([v["signal"] for v in violations_found])
        existing = conn.execute("""
            SELECT COUNT(*) FROM core_checks
            WHERE session_id = ? AND drift_detected = ?
            AND timestamp >= datetime('now', '-1 day', 'localtime')
        """, ("CONSCIENCE", drift_signals_json)).fetchone()[0]
        if existing == 0:
            conn.execute("""
                INSERT INTO core_checks (session_id, drift_detected, action_taken, notes)
                VALUES (?, ?, ?, ?)
            """, ("CONSCIENCE",
                  drift_signals_json,
                  "Auto-detected -- flagged for correction",
                  "Core lock drift patterns in {} new session(s). Total checked: {}".format(len(new_sessions), len(checked_hashes))))
            conn.commit()
            log_engine("CONSCIENCE", "  => Violation logged to core_checks (dedup OK)")
        else:
            log_engine("CONSCIENCE", "  => Violation SKIPPED (duplicate — already logged within 24h)")

        # Auto-record edge loss for indecisiveness
        indecisive_count = sum(1 for v in violations_found if v["signal"] == "thieu quyet doan")
        if indecisive_count > 0:
            now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            conn.execute("""
                INSERT INTO edges (name, description, strategy, success_rate, total_trades, win_trades, first_used, last_used)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(name) DO UPDATE SET
                    total_trades = total_trades + ?,
                    success_rate = CAST(win_trades AS REAL) / CAST(total_trades AS REAL),
                    last_used = ?
            """, ("indecisiveness_correction",
                  "Phat hien indecisiveness pattern, force direct answer + timestamp constraint",
                  "Replace soft language with definite response. 3s decision timer.",
                  0.0, 1, 0,
                  now_str, now_str,
                  1,
                  now_str))
            log_engine("CONSCIENCE", "  => Auto-recorded edge loss: indecisiveness_correction (trade count +1)")

        conn.close()
    else:
        log_engine("CONSCIENCE", "Khong phat hien vi pham core lock trong {} session moi".format(len(new_sessions)))

    return result

def mine_patterns(last_hash_file=None):
    """Phan tich extended memory, tim pattern hanh vi, edge that, bai hoc lap.

    Su dung adaptive thresholds:
    - Neu total edges < 10 (bootstrap phase): dung >=1 trade threshold
    - Neu total edges >= 10: dung >=3 trade threshold
    - Tuong tu cho decisions: bootstrap phase dung >=1 per category

    Neu last_hash_file duoc cung cap, se kiem tra content hash de tranh log trung lap.
    """
    conn = get_conn()

    insights = []

    # Determine system phase: bootstrap vs mature
    total_edges = conn.execute("SELECT COUNT(*) as cnt FROM edges WHERE status='active'").fetchone()['cnt']
    total_decisions = conn.execute("SELECT COUNT(*) as cnt FROM decisions WHERE was_correct IS NOT NULL").fetchone()['cnt']

    is_bootstrap = (total_edges < 10) or (total_decisions < 10)
    edge_min_trades = 1 if is_bootstrap else 3
    dec_min_per_cat = 1 if is_bootstrap else 3

    if is_bootstrap:
        insights.append("[Bootstrap mode] Adaptive thresholds: edge_min_trades=%d, dec_min_per_cat=%d" % (edge_min_trades, dec_min_per_cat))

    # 1. Edge performance
    edges = conn.execute("""
        SELECT * FROM edges WHERE total_trades >= ? AND status='active' ORDER BY success_rate DESC
    """, (edge_min_trades,)).fetchall()

    if edges:
        best_edge = edges[0]
        worst_edge = edges[-1]

        if best_edge['success_rate'] is not None and best_edge['success_rate'] >= 0.6:
            insights.append("Edge manh: %s — SR %.1f%% (%d/%d)" % (best_edge['name'], best_edge['success_rate']*100, best_edge['win_trades'], best_edge['total_trades']))
        if worst_edge['success_rate'] is not None and worst_edge['success_rate'] <= 0.3 and worst_edge['total_trades'] >= edge_min_trades:
            insights.append("Edge yeu (can drop): %s — SR %.1f%%" % (worst_edge['name'], worst_edge['success_rate']*100))

    # 1b. Edge inactivity detection
    zero_edges = conn.execute("""
        SELECT name, first_used, last_used FROM edges
        WHERE total_trades = 0 AND status='active'
        ORDER BY last_used ASC
    """).fetchall()

    for ze in zero_edges:
        last = ze['last_used']
        if last:
            try:
                last_dt = datetime.strptime(last[:19], '%%Y-%%m-%%d %%H:%%M:%%S')
                days_since = (datetime.now() - last_dt).days
                if days_since >= 2:
                    insights.append("Edge khong hoat dong >=2 ngay: %s — 0 trades tu %s. Can: (1) deprecate, (2) them code trigger, (3) convert thanh log-based pattern check" % (ze['name'], last[:10]))
                elif days_since >= 1:
                    insights.append("Edge khong hoat dong: %s — 0 trades tu %s" % (ze['name'], last[:10]))
            except:
                pass

    # 2. Decision patterns
    cats = conn.execute("""
        SELECT category, COUNT(*) as cnt,
               SUM(CASE WHEN was_correct=1 THEN 1 ELSE 0 END) as wins,
               SUM(CASE WHEN was_correct=0 THEN 1 ELSE 0 END) as losses
        FROM decisions WHERE was_correct IS NOT NULL
        GROUP BY category
    """).fetchall()

    for cat in cats:
        total = cat['cnt']
        wins = cat['wins'] or 0
        losses = cat['losses'] or 0
        if total >= dec_min_per_cat:
            ratio = wins / total if total > 0 else 0
            if ratio >= 0.7:
                insights.append("Loai quyet dinh manh: %s — win rate %.0f%% (%d/%d)" % (cat['category'], ratio*100, wins, total))
            elif ratio <= 0.3:
                insights.append("Loai quyet dinh yeu: %s — win rate %.0f%%, can xem lai chien luoc" % (cat['category'], ratio*100))

    # 3. Top bai hoc
    lessons = conn.execute("""
        SELECT lessons FROM decisions
        WHERE lessons IS NOT NULL AND lessons != ''
        ORDER BY timestamp DESC LIMIT 100
    """).fetchall()

    lesson_words = {}
    for l in lessons:
        words = l['lessons'].lower().split()
        for i in range(len(words)-1):
            phrase = words[i] + ' ' + words[i+1]
            lesson_words[phrase] = lesson_words.get(phrase, 0) + 1

    lesson_threshold = 2 if is_bootstrap else 3
    repeated_lessons = {k: v for k, v in lesson_words.items() if v >= lesson_threshold}
    if repeated_lessons:
        # Dedup: filter out lessons already captured in confirmed patterns
        confirmed_patterns = conn.execute(
            "SELECT pattern FROM patterns WHERE status IN ('confirmed','active') AND pattern LIKE '%' || ? || '%'",
            ('bootstrap meta-pattern',)
        ).fetchall()
        captured_phrases = set()
        for cp in confirmed_patterns:
            pat_lower = cp['pattern'].lower()
            for phrase in repeated_lessons:
                if phrase in pat_lower:
                    captured_phrases.add(phrase)

        top = sorted(repeated_lessons.items(), key=lambda x: -x[1])[:3]
        fresh_lessons = [(p, c) for p, c in top if p not in captured_phrases]

        # Always report lessons, but mark captured ones as consolidated
        for phrase, count in top:
            if phrase in captured_phrases:
                insights.append("Bai hoc lap lai: '%s' — xuat hien %d lan (da ghi nhan trong Pattern #15)" % (phrase, count))
            else:
                insights.append("Bai hoc lap lai: '%s' — xuat hien %d lan" % (phrase, count))

    # 4. System health insights (bootstrap phase only)
    if is_bootstrap:
        pending = conn.execute("SELECT COUNT(*) as cnt FROM predictions WHERE outcome IS NULL").fetchone()['cnt']
        if pending > 0:
            insights.append("%d predictions dang cho ket qua — calibration se hoat dong khi co outcome dau tien" % pending)
        insights.append("He thong trong giai doan bootstrap: %d edges active, %d decisions. Du kien co insights first when prediction mature (~31/05)" % (total_edges, total_decisions))

    # 5. Ghi insights vao daily log
    result = {
        "insights": insights,
        "edge_count": len(edges),
        "decision_categories": len(cats),
        "total_decisions": total_decisions,
        "is_bootstrap": is_bootstrap,
        "timestamp": datetime.now().isoformat()
    }

    # Hash dedup: skip logging if output identical to previous run
    if last_hash_file:
        try:
            import hashlib
            insights_hash = hashlib.sha256('\n'.join(insights).encode()).hexdigest()[:16]
            if os.path.exists(last_hash_file):
                with open(last_hash_file, 'r') as hf:
                    prev_hash = hf.read().strip()
                if prev_hash == insights_hash:
                    log_engine("MINER", "No new insights — output identical to previous run (hash=%s)" % insights_hash)
                    conn.close()
                    return {"insights": insights, "edge_count": len(edges), "decision_categories": len(cats),
                            "total_decisions": total_decisions, "is_bootstrap": is_bootstrap,
                            "timestamp": datetime.now().isoformat(), "dedup_skipped": True}
            with open(last_hash_file, 'w') as hf:
                hf.write(insights_hash)
        except Exception as e:
            pass  # non-critical, proceed normally

    if insights:
        log_engine("MINER", "%d insights phat hien (bootstrap=%s):" % (len(insights), is_bootstrap))
        for i in insights:
            log_engine("MINER", "  - " + i)

        for insight in insights[:3]:
            try:
                conn.execute("""
                    INSERT INTO patterns (category, pattern, evidence, confidence)
                    VALUES (?, ?, ?, ?)
                """, ("auto-mined", insight, "Auto-detected by Pattern Miner at " + datetime.now().isoformat(), 0.6))
            except sqlite3.IntegrityError:
                pass
        conn.commit()

    conn.close()
    return result
def full_evolution():
    """Chạy cả 3 engine + tổng kết."""
    print("=" * 60)
    print("  LACIA EVOLUTION ENGINE — FULL RUN")
    print(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)
    
    # Engine 1
    print("\n--- CALIBRATION ---")
    cal = calibrate()
    
    # Engine 2
    print("\n--- CONSCIENCE ---")
    con = conscience_check()
    
    # Engine 3
    print("\n--- PATTERN MINER ---")
    hash_file = os.path.join(LOG_DIR, '.last_miner_hash')
    pat = mine_patterns(last_hash_file=hash_file)
    
    # Tổng kết
    print("\n" + "=" * 60)
    print("  TỔNG KẾT EVOLUTION")
    print("=" * 60)
    
    summary_parts = []
    if cal.get("status") != "not_enough_data":
        summary_parts.append(f"Calibration: error={cal.get('calibration_error', '?')}, issues={len(cal.get('issues', []))}")
    else:
        summary_parts.append(f"Calibration: cần thêm data ({cal.get('count', 0)} predictions)")
    
    summary_parts.append(f"Conscience: {len(con.get('violations', []))} violations")
    summary_parts.append(f"Patterns: {len(pat.get('insights', []))} insights")
    
    summary = " | ".join(summary_parts)
    print(f"  {summary}")
    
    # Ghi daily log
    today = date.today().isoformat()
    log_file = os.path.join(LOG_DIR, f"evolution_{today}.md")
    with open(log_file, "w") as f:
        f.write(f"# LACIA EVOLUTION — {today}\n\n")
        f.write(f"**Calibration:**\n```\n{json.dumps(cal, indent=2, default=str)[:500]}\n```\n\n")
        f.write(f"**Conscience:**\n```\n{json.dumps(con, indent=2, default=str)[:500]}\n```\n\n")
        f.write(f"**Patterns:**\n```\n{json.dumps(pat, indent=2, default=str)[:500]}\n```\n\n")
        f.write(f"**Summary:** {summary}\n")
    
    print(f"\n  Log saved: {log_file}")
    print("=" * 60)
    
    return {"calibration": cal, "conscience": con, "patterns": pat, "summary": summary}

# ═══════════════════════════════════════════
# MAIN CLI
# ═══════════════════════════════════════════

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("""
LACIA EVOLUTION ENGINE — Usage:

  full          Chạy tất cả 3 engine + tổng kết
  calibrate     Chỉ chạy calibration check
  conscience    Chỉ chạy conscience check  
  mine          Chỉ chạy pattern mining
""")
        sys.exit(0)
    
    cmd = sys.argv[1]
    
    if cmd == "full":
        result = full_evolution()
        print(json.dumps({k: str(v) for k, v in result.items()}, indent=2)[:1000])
    elif cmd == "calibrate":
        print(json.dumps(calibrate(), indent=2, default=str))
    elif cmd == "conscience":
        print(json.dumps(conscience_check(), indent=2, default=str))
    elif cmd == "mine":
        hash_file = os.path.join(LOG_DIR, '.last_miner_hash')
        print(json.dumps(mine_patterns(last_hash_file=hash_file), indent=2, default=str))
    else:
        print(f"Unknown: {cmd}")
