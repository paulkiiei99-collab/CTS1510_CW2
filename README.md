# Multi-Domain Intelligence Platform – CTS1510 Coursework 2

This project is a Streamlit web application that simulates a Multi-Domain Intelligence Platform
for three domains:

- **Cyber Security** – cyber_incidents dashboard
- **Data Science** – datasets metadata dashboard
- **IT Operations** – IT ticket performance dashboard

## Project Structure

- `app.py` – main Streamlit application
- `app/data` – database helpers and CRUD for incidents, datasets, and tickets
- `app/models` – simple Python classes (User, Incident, Dataset, Ticket)
- `app/services` – service layer for authentication and business logic
- `DATA/` – CSV files for the three domains
- `database.py` – SQLite database setup (if used)
- `authorize.py` – CLI authentication tool (Week 7)
- `create_sample_data.py` – generates the CSV files in `DATA/`

## How to run

1. Create and activate a virtual environment (optional but recommended)
2. Install requirements:

```bash
pip install -r requirements.txt
