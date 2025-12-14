from app.data.db import connect_database

def insert_dataset(name, category, size_gb):
    conn = connect_database()
    cur = conn.cursor()

    cur.execute("""
        INSERT INTO datasets_metadata (name, category, size_gb)
        VALUES (?, ?, ?)
    """, (name, category, size_gb))

    conn.commit()
    new_id = cur.lastrowid
    conn.close()
    return new_id

def get_all_datasets():
    conn = connect_database()
    cur = conn.cursor()
    cur.execute("""
        SELECT id, name, category, size_gb
        FROM datasets_metadata
    """)
    rows = cur.fetchall()
    conn.close()
    return rows
