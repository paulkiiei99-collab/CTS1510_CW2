from pathlib import Path
import pandas as pd

from app.data.db import connect_database
from app.data.schema import create_all_tables

from app.services.user_service import (
    register_user,
    login_user,
    migrate_users_from_file,
)

from app.data.incidents import insert_incident, get_all_incidents
from app.data.datasets import insert_dataset, get_all_datasets
from app.data.tickets import insert_ticket, get_all_tickets


def load_csv_to_table(conn, csv_file, table):
    """Read a CSV file and append its contents to a database table."""
    if not csv_file.exists():
        print(f"[INFO] File missing -> {csv_file}")
        return 0

    df = pd.read_csv(csv_file)
    df.to_sql(table, conn, if_exists="append", index=False)
    print(f"[DATA] {len(df)} entries inserted into '{table}'")
    return len(df)


def setup_database_complete():
    print("\n=== INITIALIZING FULL DATABASE SETUP ===")

    db = connect_database()
    print("Database connection established.")

    create_all_tables(db)
    print("All required tables have been created.")

    migrated_count = migrate_users_from_file()
    print(f"{migrated_count} user records imported from text file.")

    source_folder = Path("DATA")
    csv_map = {
        "cyber_incidents": source_folder / "cyber_incidents.csv",
        "datasets_metadata": source_folder / "datasets_metadata.csv",
        "it_tickets": source_folder / "it_tickets.csv",
    }

    total = 0
    for tbl, file in csv_map.items():
        total += load_csv_to_table(db, file, tbl)

    print(f"Imported a total of {total} rows from all CSV files.")

    cur = db.cursor()
    print("\n--- TABLE COUNT REPORT ---")
    for tbl in ["users", "cyber_incidents", "datasets_metadata", "it_tickets"]:
        cur.execute(f"SELECT COUNT(*) FROM {tbl}")
        count = cur.fetchone()[0]
        print(f"Table '{tbl}': {count} rows")

    db.close()
    print("=== DATABASE SETUP COMPLETED ===\n")


def run_comprehensive_tests():
    print("\n===== STARTING SYSTEM VERIFICATION TESTS =====")

    created, reg_msg = register_user("test_user", "TestPass123!", "user")
    print("[USER SIGNUP]", reg_msg)

    logged, login_msg = login_user("test_user", "TestPass123!")
    print("[USER LOGIN]", login_msg)

    _ = connect_database()  # keeps behavior identical to original
    print("\nCreating a sample incident for validation...")

    new_id = insert_incident(
        "2024-11-05",
        "Test Incident",
        "Low",
        "Open",
        "This is only a validation entry.",
        "test_user",
    )
    print(f"Sample incident created with ID: {new_id}")


def main():
    print("======================================")
    print("        WEEK 8 — DB DEMO MODULE       ")
    print("======================================")

    setup_database_complete()
    run_comprehensive_tests()

    print("\n=== ADDING STANDARD INCIDENT EXAMPLE ===")
    new_incident = insert_incident(
        "2024-11-10",
        "Phishing Attempt",
        "High",
        "Open",
        "User interacted with a suspicious hyperlink.",
        "alice",
    )
    print("Incident successfully saved with ID:", new_incident)

    print("\n=== DISPLAYING ALL INCIDENT RECORDS ===")
    print(get_all_incidents())


if __name__ == "__main__":
    main()