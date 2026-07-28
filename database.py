import sqlite3

conn = sqlite3.connect("videos.db")
cur = conn.cursor()

cur.execute("""
CREATE TABLE IF NOT EXISTS videos(
id INTEGER PRIMARY KEY AUTOINCREMENT,
title TEXT,
filename TEXT,
views INTEGER DEFAULT 0,
likes INTEGER DEFAULT 0
)
""")

conn.commit()
conn.close()
