import sqlite3
import os

DB_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "data")
os.makedirs(DB_DIR, exist_ok=True)
DB_PATH = os.path.join(DB_DIR, "feedback.db")

def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute('''CREATE TABLE IF NOT EXISTS feedback (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        target TEXT,
                        score INTEGER,
                        category TEXT,
                        feedback_value TEXT,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                      )''')
init_db()

def save_feedback(target: str, score: int, category: str, feedback_value: str):
    """Store user feedback locally on the backend database."""
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("INSERT INTO feedback (target, score, category, feedback_value) VALUES (?, ?, ?, ?)",
                     (target, score, category, feedback_value))
        conn.commit()
