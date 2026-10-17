"""
Vulnerable Sample: Database & Cache Handler
Demonstrates SQL injection via string formatting, concatenation, and f-strings, plus pickle deserialization.
"""

import sqlite3
import pickle


def find_user_by_name(cursor: sqlite3.Cursor, user_name: str):
    # Flagged: AST-SQL-001 - String Concatenation (+)
    query = "SELECT id, username, email FROM users WHERE username = '" + user_name + "'"
    cursor.execute(query)
    return cursor.fetchall()


def find_user_by_email(cursor: sqlite3.Cursor, email: str):
    # Flagged: AST-SQL-001 - Modulo Formatting (%)
    query = "SELECT id, username, email FROM users WHERE email = '%s'" % email
    cursor.execute(query)
    return cursor.fetchone()


def delete_record(cursor: sqlite3.Cursor, record_id: str):
    # Flagged: AST-SQL-001 - Formatted String Literal (f-string)
    cursor.execute(f"DELETE FROM records WHERE id = {record_id}")


def update_status(cursor: sqlite3.Cursor, record_id: str, status: str):
    # Flagged: AST-SQL-001 - str.format() Call
    cursor.execute("UPDATE records SET status = '{}' WHERE id = {}".format(status, record_id))


def restore_session_state(raw_session_bytes: bytes):
    # Flagged: AST-DESER-001 - Insecure pickle.loads()
    state = pickle.loads(raw_session_bytes)
    return state
