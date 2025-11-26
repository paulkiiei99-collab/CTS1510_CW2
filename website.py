import streamlit as st
import pandas as pd
import random

# Basic page setup
st.set_page_config(
    page_title="Multi-Domain Intelligence Platform",
    layout="wide",
    initial_sidebar_state="collapsed"
)

st.title("Multi-Domain Intelligence Platform")
st.write("---")

# ---------- Session State Setup ----------

if "users" not in st.session_state:
    # simple in-memory users (demo only, not secure)
    st.session_state.users = {
        "admin": "admin",   # default accounts
        "user": "123456"
    }

if "logged_in" not in st.session_state:
    st.session_state.logged_in = False

if "username" not in st.session_state:
    st.session_state.username = ""

if "cyber_incidents" not in st.session_state:
    st.session_state.cyber_incidents = [
        {"title": "Phishing Campaign", "severity": "High", "status": "In Progress"},
        {"title": "DDoS Attack", "severity": "Critical", "status": "Resolved"},
    ]

if "datasets" not in st.session_state:
    st.session_state.datasets = [
        {"name": "Customer Data 2025", "category": "Sensitive", "size_gb": 45.8},
    ]

if "it_tickets" not in st.session_state:
    st.session_state.it_tickets = [
        {"title": "Server Down", "priority": "High", "status": "Open"},
    ]


# ---------- Dashboard (after login) ----------

if st.session_state.logged_in:
    st.success(f"Logged in as **{st.session_state.username}**")

    # Sidebar for user info + logout
    with st.sidebar:
        st.header("User Panel")
        st.write(f"User: `{st.session_state.username}`")
        if st.button("Logout"):
            st.session_state.logged_in = False
            st.session_state.username = ""
            st.experimental_rerun()

    # Tabs for the three domains
    tab_cyber, tab_data, tab_it = st.tabs(["Cybersecurity", "Data Science", "IT Operations"])

    # ----- Cybersecurity Tab -----
    with tab_cyber:
        st.subheader("Cybersecurity Overview")

        col1, col2, col3 = st.columns(3)
        col1.metric("Threats Detected", random.randint(200, 300))
        col2.metric(
            "Active Incidents",
            len([i for i in st.session_state.cyber_incidents if i["status"] != "Resolved"])
        )
        col3.metric("Vulnerabilities", random.randint(5, 15))

        # Simple bar chart of threat types
        threat_data = {
            "Threat Type": ["Malware", "Phishing", "DDoS", "Ransomware"],
            "Count": [89, 67, 45, 32]
        }
        threat_df = pd.DataFrame(threat_data)
        threat_df.set_index("Threat Type", inplace=True)
        st.bar_chart(threat_df["Count"])

        st.subheader("Cyber Incidents")
        if st.session_state.cyber_incidents:
            st.dataframe(st.session_state.cyber_incidents, use_container_width=True)

        # Add new incident form
        with st.expander("Add New Incident"):
            with st.form("new_incident_form"):
                new_title = st.text_input("Incident Title")
                new_severity = st.selectbox("Severity", ["Low", "Medium", "High", "Critical"])
                new_status = st.selectbox("Status", ["Open", "In Progress", "Resolved"])
                add_incident = st.form_submit_button("Add Incident")

                if add_incident:
                    if new_title:
                        st.session_state.cyber_incidents.append(
                            {"title": new_title, "severity": new_severity, "status": new_status}
                        )
                        st.success("Incident added.")
                        st.experimental_rerun()
                    else:
                        st.warning("Please enter an incident title.")

    # ----- Data Science Tab -----
    with tab_data:
        st.subheader("Data Science & ML")

        dcol1, dcol2, dcol3 = st.columns(3)
        dcol1.metric("Accuracy", "94.2%")
        dcol2.metric("Precision", "91.8%")
        dcol3.metric("Recall", "89.5%")

        # Training history chart
        history = {
            "epoch": list(range(1, 11)),
            "training_loss": [0.8, 0.6, 0.45, 0.32, 0.24, 0.20, 0.18, 0.16, 0.14, 0.12],
            "val_accuracy": [78, 82, 85, 88, 90, 91, 92, 93, 94, 94.5]
        }
        history_df = pd.DataFrame(history)
        history_df.set_index("epoch", inplace=True)
        st.line_chart(history_df)

        st.subheader("Datasets")
        if st.session_state.datasets:
            st.dataframe(st.session_state.datasets, use_container_width=True)

    # ----- IT Operations Tab -----
    with tab_it:
        st.subheader("IT Operations")

        icol1, icol2, icol3 = st.columns(3)
        icol1.metric("CPU Usage", "67%")
        icol2.metric("Memory Usage", "8.2 GB")
        icol3.metric("Uptime", "99.8%")

        st.subheader("IT Tickets")
        if st.session_state.it_tickets:
            st.dataframe(st.session_state.it_tickets, use_container_width=True)

        # New ticket form
        with st.expander("Create New Ticket"):
            with st.form("new_ticket_form"):
                ticket_title = st.text_input("Issue")
                ticket_priority = st.selectbox("Priority", ["Low", "Medium", "High", "Critical"])
                create_ticket = st.form_submit_button("Create Ticket")

                if create_ticket:
                    if ticket_title:
                        st.session_state.it_tickets.append(
                            {"title": ticket_title, "priority": ticket_priority, "status": "Open"}
                        )
                        st.success("Ticket created.")
                        st.experimental_rerun()
                    else:
                        st.warning("Please describe the issue.")


# ---------- Login / Register (before login) ----------

else:
    tab_login, tab_register = st.tabs(["Login", "Register"])

    # Login tab
    with tab_login:
        st.subheader("Login")

        login_user = st.text_input("Username")
        show_login_password = st.checkbox("Show password")
        login_password_type = "text" if show_login_password else "password"
        login_pass = st.text_input("Password", type=login_password_type)

        if st.button("Log in", use_container_width=True):
            if (
                login_user in st.session_state.users
                and st.session_state.users[login_user] == login_pass
            ):
                st.session_state.logged_in = True
                st.session_state.username = login_user
                st.success("Login successful.")
                st.experimental_rerun()
            else:
                st.error("Invalid username or password.")

    # Register tab
    with tab_register:
        st.subheader("Create Account")

        reg_user = st.text_input("Choose username")
        show_reg_password = st.checkbox("Show password", key="show_reg_password")
        reg_pass_type = "text" if show_reg_password else "password"
        reg_pass = st.text_input("Password", type=reg_pass_type)
        reg_confirm = st.text_input("Confirm password", type=reg_pass_type)

        if st.button("Create account", use_container_width=True):
            if not reg_user or not reg_pass or not reg_confirm:
                st.warning("Please fill in all fields.")
            elif reg_pass != reg_confirm:
                st.error("Passwords do not match.")
            elif reg_user in st.session_state.users:
                st.error("Username already exists.")
            else:
                st.session_state.users[reg_user] = reg_pass
                st.success("Account created. You can log in now.")
