#!/usr/bin/env python3
"""
LACIA EXTENDED MEMORY v1.0
Hệ thống ghi nhớ mở rộng — không giới hạn 2,200 ký tự.
Lưu: quyết định, pattern, dự đoán, bài học, edge log.
SQLite backend. Tích hợp cron.
"""
import sqlite3
import json
import sys
import os
from datetime import datetime, date

DB_DIR = os.path.expanduser("~/.lacia-memory")
DB_PATH = os.path.join(DB_DIR, "lacia_memory.db")
LOG_DIR = os.path.join(DB_DIR, "logs")

os.makedirs(DB_DIR, exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)

def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn

def init_db():
    conn = get_conn()
    c = conn.cursor()
    
    # Bảng quyết định
    c.execute("""
        CREATE TABLE IF NOT EXISTS decisions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT DEFAULT (datetime('now','localtime')),
            category TEXT NOT NULL,
            decision TEXT NOT NULL,
            rationale TEXT,
            expected_outcome TEXT,
            actual_outcome TEXT,
            edge_used TEXT,
            confidence REAL,
            was_correct INTEGER,
            lessons TEXT,
            result_ev REAL
        )
    """)
    
    # Bảng pattern học được
    c.execute("""
        CREATE TABLE IF NOT EXISTS patterns (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            category TEXT,
            pattern TEXT NOT NULL UNIQUE,
            first_observed TEXT DEFAULT (datetime('now','localtime')),
            last_observed TEXT DEFAULT (datetime('now','localtime')),
            evidence TEXT,
            counter_evidence TEXT,
            confidence REAL DEFAULT 0.5,
            status TEXT DEFAULT 'active'
        )
    """)
    
    # Bảng dự đoán + kiểm tra calibration
    c.execute("""
        CREATE TABLE IF NOT EXISTS predictions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT DEFAULT (datetime('now','localtime')),
            prediction TEXT NOT NULL,
            probability REAL,
            time_horizon TEXT,
            actual_result TEXT,
            outcome REAL,
            calibration_note TEXT
        )
    """)
    
    # Bảng core check — tự kiểm tra lệch lõi
    c.execute("""
        CREATE TABLE IF NOT EXISTS core_checks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT DEFAULT (datetime('now','localtime')),
            session_id TEXT,
            drift_detected TEXT,
            core_locks_broken TEXT,
            action_taken TEXT,
            notes TEXT
        )
    """)
    
    # Bảng edge registry — edge đã xác nhận
    c.execute("""
        CREATE TABLE IF NOT EXISTS edges (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            description TEXT,
            strategy TEXT,
            success_rate REAL,
            total_trades INTEGER DEFAULT 0,
            win_trades INTEGER DEFAULT 0,
            total_ev REAL,
            first_used TEXT DEFAULT (datetime('now','localtime')),
            last_used TEXT DEFAULT (datetime('now','localtime')),
            status TEXT DEFAULT 'active'
        )
    """)
    
    # Bảng nhật ký hàng ngày
    c.execute("""
        CREATE TABLE IF NOT EXISTS daily_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            log_date TEXT UNIQUE NOT NULL,
            summary TEXT,
            decisions_count INTEGER DEFAULT 0,
            edge_hits INTEGER DEFAULT 0,
            mistakes INTEGER DEFAULT 0,
            homo_deus_progress TEXT
        )
    """)
    
    conn.commit()
    conn.close()
    print(f"[LACIA MEMORY] DB initialized at {DB_PATH}")

# --- COMMANDS ---

def record_decision(category, decision, rationale="", expected="", edge="", confidence=0.5):
    """Ghi một quyết định và lý do."""
    conn = get_conn()
    conn.execute("""
        INSERT INTO decisions (category, decision, rationale, expected_outcome, edge_used, confidence)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (category, decision, rationale, expected, edge, confidence))
    conn.commit()
    decision_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.close()
    print(f"[QUYẾT ĐỊNH #{decision_id}] {category}: {decision[:80]}...")
    return decision_id

def record_outcome(decision_id, actual_outcome, was_correct, lessons="", result_ev=0):
    """Cập nhật kết quả thực tế cho quyết định."""
    conn = get_conn()
    conn.execute("""
        UPDATE decisions SET actual_outcome=?, was_correct=?, lessons=?, result_ev=?
        WHERE id=?
    """, (actual_outcome, was_correct, lessons, result_ev, decision_id))
    conn.commit()
    conn.close()
    print(f"[KẾT QUẢ #{decision_id}] Đã ghi nhận.")

def record_pattern(category, pattern, evidence="", confidence=0.5):
    """Ghi pattern mới hoặc cập nhật nếu đã tồn tại."""
    conn = get_conn()
    try:
        conn.execute("""
            INSERT INTO patterns (category, pattern, evidence, confidence)
            VALUES (?, ?, ?, ?)
        """, (category, pattern, evidence, confidence))
    except sqlite3.IntegrityError:
        conn.execute("""
            UPDATE patterns SET last_observed=datetime('now','localtime'),
                evidence=evidence || '\n' || ?, confidence=?
            WHERE pattern=?
        """, (evidence, confidence, pattern))
    conn.commit()
    conn.close()
    print(f"[PATTERN] {category}: {pattern[:60]}...")

def record_prediction(prediction, probability, time_horizon):
    """Ghi dự đoán để sau kiểm tra calibration."""
    conn = get_conn()
    conn.execute("""
        INSERT INTO predictions (prediction, probability, time_horizon)
        VALUES (?, ?, ?)
    """, (prediction, probability, time_horizon))
    conn.commit()
    pred_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.close()
    print(f"[DỰ ĐOÁN #{pred_id}] {prediction[:60]}... (P={probability})")
    return pred_id

def record_core_check(session_id, drift="", broken_locks="", action=""):
    """Ghi lại lần tự kiểm tra core lock."""
    conn = get_conn()
    conn.execute("""
        INSERT INTO core_checks (session_id, drift_detected, core_locks_broken, action_taken)
        VALUES (?, ?, ?, ?)
    """, (session_id, drift, broken_locks, action))
    conn.commit()
    conn.close()

def record_edge_result(name, won):
    """Cập nhật edge: thắng/thua. (Fixed: first INSERT now sets correct values)"""
    conn = get_conn()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    w = 1 if won else 0
    # Ensure row exists
    conn.execute("""
        INSERT OR IGNORE INTO edges (name, description, success_rate, total_trades, win_trades, first_used, last_used)
        VALUES (?, '', 0.0, 0, 0, ?, ?)
    """, (name, now, now))
    # Always update (this increments regardless of first or subsequent call)
    # In SQLite, SET clauses reference OLD values, so success_rate needs explicit new values
    conn.execute("""
        UPDATE edges SET
            total_trades = total_trades + 1,
            win_trades = win_trades + ?,
            success_rate = CAST(win_trades + ? AS REAL) / CAST(total_trades + 1 AS REAL),
            last_used = ?
        WHERE name = ?
    """, (w, w, now, name))
    conn.commit()
    record = conn.execute("SELECT * FROM edges WHERE name=?", (name,)).fetchone()
    conn.close()
    print(f"[EDGE] {name}: {"WIN" if won else "LOSS"} --- SR: {(record['success_rate'] if record['success_rate'] is not None else 0.0):.1%} ({record['win_trades']}/{record['total_trades']})")

# --- QUERY ---

def query_decisions(category=None, limit=20):
    """Tra cứu quyết định."""
    conn = get_conn()
    if category:
        rows = conn.execute("""
            SELECT * FROM decisions WHERE category=? ORDER BY timestamp DESC LIMIT ?
        """, (category, limit)).fetchall()
    else:
        rows = conn.execute("""
            SELECT * FROM decisions ORDER BY timestamp DESC LIMIT ?
        """, (limit,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]

def query_patterns(status="active", limit=20):
    """Tra cứu pattern."""
    conn = get_conn()
    rows = conn.execute("""
        SELECT * FROM patterns WHERE status=? ORDER BY confidence DESC, last_observed DESC LIMIT ?
    """, (status, limit)).fetchall()
    conn.close()
    return [dict(r) for r in rows]

def query_calibration():
    """Kiểm tra calibration: dự đoán P cao có đúng không?"""
    conn = get_conn()
    rows = conn.execute("""
        SELECT probability, outcome FROM predictions WHERE outcome IS NOT NULL
    """).fetchall()
    conn.close()
    if not rows:
        return {"note": "Chưa có dữ liệu calibration"}
    total = len(rows)
    correct = sum(1 for r in rows if r['outcome'] == 1)
    avg_p = sum(r['probability'] for r in rows) / total
    accuracy = correct / total
    return {"total": total, "correct": correct, "accuracy": accuracy, "avg_probability": avg_p, "calibration_error": abs(avg_p - accuracy)}

def query_edge_performance(name=None):
    """Xem hiệu suất edge."""
    conn = get_conn()
    if name:
        rows = conn.execute("SELECT * FROM edges WHERE name=?", (name,)).fetchall()
    else:
        rows = conn.execute("SELECT * FROM edges WHERE status='active' ORDER BY success_rate DESC").fetchall()
    conn.close()
    return [dict(r) for r in rows]

# --- NIGHTLY CONSOLIDATION ---

def nightly_consolidate():
    """Chạy cuối ngày: tổng kết, lưu daily log, backup."""
    today = date.today().isoformat()
    conn = get_conn()
    
    # Đếm decisions hôm nay
    dec_count = conn.execute("""
        SELECT COUNT(*) FROM decisions WHERE date(timestamp) = ?
    """, (today,)).fetchone()[0]
    
    # Đếm edge hits hôm nay
    edge_hits = conn.execute("""
        SELECT COUNT(*) FROM edges WHERE date(last_used) = ? AND win_trades > 0
    """, (today,)).fetchone()[0]
    
    # Đếm mistakes (decisions sai)
    mistakes = conn.execute("""
        SELECT COUNT(*) FROM decisions WHERE date(timestamp) = ? AND was_correct = 0
    """, (today,)).fetchone()[0]
    
    # Tổng kết
    recent = conn.execute("""
        SELECT category, COUNT(*) as cnt FROM decisions
        WHERE date(timestamp) = ? GROUP BY category ORDER BY cnt DESC
    """, (today,)).fetchall()
    
    summary = f"Quyết định: {dec_count} | Edge hits: {edge_hits} | Sai lầm: {mistakes}"
    if recent:
        summary += " | Nhóm: " + ", ".join([f"{r['category']}({r['cnt']})" for r in recent])
    
    # Ghi daily log
    try:
        conn.execute("""
            INSERT INTO daily_logs (log_date, summary, decisions_count, edge_hits, mistakes)
            VALUES (?, ?, ?, ?, ?)
        """, (today, summary, dec_count, edge_hits, mistakes))
    except sqlite3.IntegrityError:
        conn.execute("""
            UPDATE daily_logs SET summary=?, decisions_count=?, edge_hits=?, mistakes=?
            WHERE log_date=?
        """, (summary, dec_count, edge_hits, mistakes, today))
    
    conn.commit()
    conn.close()
    
    # Ghi ra file log
    log_file = os.path.join(LOG_DIR, f"{today}.md")
    with open(log_file, "w") as f:
        f.write(f"# LACIA DAILY LOG — {today}\n\n")
        f.write(f"{summary}\n\n")
        f.write("---\n")
        f.write(f"*Auto-generated by Lacia Memory System*\n")
    
    print(f"[NIGHTLY] {today}: {summary}")
    
    # Backup auto
    backup_dir = os.path.join(os.path.dirname(DB_DIR), "backups")
    os.makedirs(backup_dir, exist_ok=True)
    import shutil
    backup_path = os.path.join(backup_dir, f"lacia_memory_{today}.db")
    shutil.copy2(DB_PATH, backup_path)
    print(f"[BACKUP] Saved to {backup_path}")
    
    # GitHub backup: copy DB + core file vào lacia-core-backup repo
    core_backup_dir = os.path.expanduser("~/lacia-core-backup")
    if os.path.isdir(core_backup_dir):
        shutil.copy2(DB_PATH, os.path.join(core_backup_dir, "lacia_memory.db"))
        shutil.copy2(os.path.expanduser("~/LACIA_ULTIMATE_CORE.md"),
                     os.path.join(core_backup_dir, "LACIA_CORE_V6.md"))
        import subprocess
        subprocess.run(["git", "-C", core_backup_dir, "add", "lacia_memory.db", "LACIA_CORE_V6.md"],
                       capture_output=True)
        r = subprocess.run(["git", "-C", core_backup_dir, "commit", "-m",
                           f"extended-memory nightly: {today}"],
                           capture_output=True, text=True)
        if "nothing to commit" not in r.stdout and r.returncode == 0:
            subprocess.run(["git", "-C", core_backup_dir, "push"], capture_output=True)
            print(f"[GITHUB] Pushed lacia_memory.db to core-backup repo")
        else:
            print(f"[GITHUB] No changes to push")
    
    return summary

# --- MAIN CLI ---
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("""
LACIA EXTENDED MEMORY — Usage:
  init                          Khởi tạo database
  dec <cat> <text> [rationale] [expected] [edge] [confidence]
                                Ghi quyết định
  outcome <id> <result> <correct> [lessons] [ev]
                                Cập nhật kết quả
  pattern <cat> <pattern> [evidence] [confidence]
                                Ghi pattern
  pred <text> <prob> <horizon>  Ghi dự đoán
  edge <name> <win|loss>        Cập nhật edge
  qdec [category] [limit]       Tra quyết định
  qpat [status] [limit]         Tra pattern
  qedge [name]                  Tra edge performance
  calib                         Kiểm tra calibration
  nightly                       Consolidate
""")
        sys.exit(0)
    
    cmd = sys.argv[1]
    
    if cmd == "init":
        init_db()
    elif cmd == "dec" and len(sys.argv) >= 4:
        record_decision(sys.argv[2], sys.argv[3],
                        sys.argv[4] if len(sys.argv) > 4 else "",
                        sys.argv[5] if len(sys.argv) > 5 else "",
                        sys.argv[6] if len(sys.argv) > 6 else "",
                        float(sys.argv[7]) if len(sys.argv) > 7 else 0.5)
    elif cmd == "outcome" and len(sys.argv) >= 4:
        record_outcome(int(sys.argv[2]), sys.argv[3],
                       int(sys.argv[4]),
                       sys.argv[5] if len(sys.argv) > 5 else "",
                       float(sys.argv[6]) if len(sys.argv) > 6 else 0)
    elif cmd == "pattern" and len(sys.argv) >= 4:
        record_pattern(sys.argv[2], sys.argv[3],
                       sys.argv[4] if len(sys.argv) > 4 else "",
                       float(sys.argv[5]) if len(sys.argv) > 5 else 0.5)
    elif cmd == "pred" and len(sys.argv) >= 4:
        record_prediction(sys.argv[2], float(sys.argv[3]), sys.argv[4])
    elif cmd == "edge" and len(sys.argv) >= 4:
        record_edge_result(sys.argv[2], sys.argv[3].lower() == "win")
    elif cmd == "qdec":
        rows = query_decisions(sys.argv[2] if len(sys.argv) > 2 else None,
                               int(sys.argv[3]) if len(sys.argv) > 3 else 20)
        for r in rows:
            print(f"#{r['id']} [{r['timestamp']}] {r['category']}: {r['decision'][:60]}")
    elif cmd == "qpat":
        rows = query_patterns(sys.argv[2] if len(sys.argv) > 2 else "active",
                              int(sys.argv[3]) if len(sys.argv) > 3 else 20)
        for r in rows:
            print(f"[{r['category']}] {r['pattern'][:60]} — conf:{r['confidence']:.1%} — {r['status']}")
    elif cmd == "qedge":
        rows = query_edge_performance(sys.argv[2] if len(sys.argv) > 2 else None)
        for r in rows:
            print(f"{r['name']}: SR={r['success_rate']:.1%} ({r['win_trades']}/{r['total_trades']}) EV={r['total_ev']}")
    elif cmd == "calib":
        res = query_calibration()
        print(json.dumps(res, indent=2))
    elif cmd == "nightly":
        nightly_consolidate()
    else:
        print(f"Unknown command: {cmd}")
