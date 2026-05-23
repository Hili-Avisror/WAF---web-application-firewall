# מנקה את טבלת ההתראות של ה-WAF

import sqlite3

DB_NAME = "waf_logs.db"

def main():
    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM attack_logs")
    count = cur.fetchone()[0]

    if count == 0:
        print("Table is already empty.")
    else:
        cur.execute("DELETE FROM attack_logs")
        conn.commit()
        print("Deleted " + str(count) + " alerts.")

    conn.close()


if __name__ == "__main__":
    main()
