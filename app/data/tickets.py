from app.data.db import connect_database

def insert_ticket(title, priority, status, description, created_by):
    conn = connect_database()
    cur = conn.cursor()

    cur.execute("""
        INSERT INTO it_tickets (title, priority, status, description, created_by)
        VALUES (?, ?, ?, ?, ?)
    """, (title, priority, status, description, created_by))

    conn.commit()
    new_id = cur.lastrowid
    conn.close()
    return new_id

def get_all_tickets():
    conn = connect_database()
    cur = conn.cursor()
    cur.execute("""
        SELECT id, title, priority, status, description, created_by
        FROM it_tickets
    """)
    rows = cur.fetchall()
    conn.close()
    return rows
