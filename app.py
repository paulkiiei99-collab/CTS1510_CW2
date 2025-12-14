# app.py
"""Main Streamlit Application - Multi-Domain Intelligence Platform"""
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import os
from openai import OpenAI

# Import services
from app.services.user_service import login_user, register_user
from app.data.incidents import (
    get_all_incidents, insert_incident, update_incident,
    delete_incident, get_incidents_by_severity, get_incidents_by_status
)
from app.data.datasets import (
    get_all_datasets, insert_dataset, update_dataset, delete_dataset
)
from app.data.tickets import (
    get_all_tickets, insert_ticket, update_ticket,
    delete_ticket, get_tickets_by_priority
)

# Page configuration
st.set_page_config(
    page_title="Multi-Domain Intelligence Platform",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)


# Initialize OpenAI client
def get_ai_client():
    """Initialize OpenAI client with API key."""
    api_key = os.getenv("OPENAI_API_KEY",
                        "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")
    return OpenAI(api_key=api_key)


# AI Assistant function
def get_ai_response(prompt, context=""):
    """Get response from ChatGPT API."""
    try:
        client = get_ai_client()
        messages = [
            {"role": "system", "content": f"You are a helpful cybersecurity and IT assistant. {context}"},
            {"role": "user", "content": prompt}
        ]

        response = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=messages,
            max_tokens=500,
            temperature=0.7
        )

        return response.choices[0].message.content
    except Exception as e:
        return f"Error: {str(e)}"


# Session state initialization
if 'logged_in' not in st.session_state:
    st.session_state.logged_in = False
if 'user' not in st.session_state:
    st.session_state.user = None
if 'ai_chat_history' not in st.session_state:
    st.session_state.ai_chat_history = []


# Authentication Pages
def login_page():
    """Login page UI."""
    st.title("🔐 Login to Multi-Domain Intelligence Platform")

    col1, col2, col3 = st.columns([1, 2, 1])

    with col2:
        st.markdown("### Welcome Back")

        with st.form("login_form"):
            username = st.text_input("Username", placeholder="Enter your username")
            password = st.text_input("Password", type="password", placeholder="Enter your password")
            submit = st.form_submit_button("Login", use_container_width=True)

            if submit:
                if username and password:
                    success, result = login_user(username, password)
                    if success:
                        st.session_state.logged_in = True
                        st.session_state.user = result
                        st.success("Login successful! Redirecting...")
                        st.rerun()
                    else:
                        st.error(result)
                else:
                    st.warning("Please enter both username and password.")

        st.markdown("---")
        if st.button("Don't have an account? Register here", use_container_width=True):
            st.session_state.show_register = True
            st.rerun()


def register_page():
    """Registration page UI."""
    st.title("📝 Create New Account")

    col1, col2, col3 = st.columns([1, 2, 1])

    with col2:
        st.markdown("### Register")

        with st.form("register_form"):
            username = st.text_input("Username", placeholder="Choose a username (min 3 characters)")
            password = st.text_input("Password", type="password", placeholder="Min 8 characters")
            confirm_password = st.text_input("Confirm Password", type="password")
            role = st.selectbox("Role", ["user", "admin"])

            submit = st.form_submit_button("Create Account", use_container_width=True)

            if submit:
                if not username or not password:
                    st.warning("Please fill in all fields.")
                elif password != confirm_password:
                    st.error("Passwords do not match.")
                else:
                    success, message = register_user(username, password, role)
                    if success:
                        st.success(message)
                        st.info("Please login with your new credentials.")
                        if st.button("Go to Login"):
                            st.session_state.show_register = False
                            st.rerun()
                    else:
                        st.error(message)

        if st.button("Back to Login", use_container_width=True):
            st.session_state.show_register = False
            st.rerun()


# Dashboard Pages
def cybersecurity_dashboard():
    """Cybersecurity domain dashboard."""
    st.header("🛡️ Cybersecurity Dashboard")

    # Fetch data
    incidents_df = get_all_incidents()

    # Metrics
    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric("Total Incidents", len(incidents_df))
    with col2:
        open_incidents = len(incidents_df[incidents_df['status'] == 'Open'])
        st.metric("Open Incidents", open_incidents)
    with col3:
        critical = len(incidents_df[incidents_df['severity'] == 'Critical'])
        st.metric("Critical Threats", critical, delta=f"+{critical}" if critical > 0 else "0")
    with col4:
        resolved = len(incidents_df[incidents_df['status'] == 'Resolved'])
        resolution_rate = (resolved / len(incidents_df) * 100) if len(incidents_df) > 0 else 0
        st.metric("Resolution Rate", f"{resolution_rate:.1f}%")

    # Visualizations
    st.subheader("📊 Analytics")

    viz_col1, viz_col2 = st.columns(2)

    with viz_col1:
        # Severity distribution
        if not incidents_df.empty:
            severity_counts = incidents_df['severity'].value_counts()
            fig_severity = px.pie(
                values=severity_counts.values,
                names=severity_counts.index,
                title="Incidents by Severity",
                color_discrete_sequence=px.colors.sequential.Reds_r
            )
            st.plotly_chart(fig_severity, use_container_width=True)

    with viz_col2:
        # Status distribution
        if not incidents_df.empty:
            status_counts = incidents_df['status'].value_counts()
            fig_status = px.bar(
                x=status_counts.index,
                y=status_counts.values,
                title="Incidents by Status",
                labels={'x': 'Status', 'y': 'Count'},
                color=status_counts.values,
                color_continuous_scale='Blues'
            )
            st.plotly_chart(fig_status, use_container_width=True)

    # Time series plot
    if not incidents_df.empty and 'date' in incidents_df.columns:
        st.subheader("📈 Incident Timeline")
        incidents_df['date'] = pd.to_datetime(incidents_df['date'])
        timeline_data = incidents_df.groupby('date').size().reset_index(name='count')

        fig_timeline = px.line(
            timeline_data,
            x='date',
            y='count',
            title="Incidents Over Time",
            markers=True
        )
        st.plotly_chart(fig_timeline, use_container_width=True)

    # Data table and CRUD
    st.subheader("📋 Incident Records")

    tab1, tab2 = st.tabs(["View Incidents", "Manage Incidents"])

    with tab1:
        if not incidents_df.empty:
            st.dataframe(incidents_df, use_container_width=True, hide_index=True)
        else:
            st.info("No incidents recorded yet.")

    with tab2:
        operation = st.radio("Operation", ["Create", "Update", "Delete"], horizontal=True)

        if operation == "Create":
            with st.form("create_incident"):
                col1, col2 = st.columns(2)
                with col1:
                    date = st.date_input("Date", datetime.now())
                    title = st.text_input("Title")
                    severity = st.selectbox("Severity", ["Low", "Medium", "High", "Critical"])
                with col2:
                    status = st.selectbox("Status", ["Open", "In Progress", "Resolved"])
                    reported_by = st.text_input("Reported By", value=st.session_state.user['username'])

                description = st.text_area("Description")

                if st.form_submit_button("Create Incident"):
                    if title and description:
                        incident_id = insert_incident(
                            str(date), title, severity, status, description, reported_by
                        )
                        st.success(f"Incident created with ID: {incident_id}")
                        st.rerun()
                    else:
                        st.warning("Please fill in all required fields.")

        elif operation == "Update":
            if not incidents_df.empty:
                incident_id = st.selectbox("Select Incident", incidents_df['id'].tolist())
                incident = incidents_df[incidents_df['id'] == incident_id].iloc[0]

                with st.form("update_incident"):
                    col1, col2 = st.columns(2)
                    with col1:
                        new_title = st.text_input("Title", value=incident['title'])
                        new_severity = st.selectbox("Severity",
                                                    ["Low", "Medium", "High", "Critical"],
                                                    index=["Low", "Medium", "High", "Critical"].index(
                                                        incident['severity'])
                                                    )
                    with col2:
                        new_status = st.selectbox("Status",
                                                  ["Open", "In Progress", "Resolved"],
                                                  index=["Open", "In Progress", "Resolved"].index(incident['status'])
                                                  )
                        new_date = st.date_input("Date", value=pd.to_datetime(incident['date']))

                    new_desc = st.text_area("Description", value=incident['description'])

                    if st.form_submit_button("Update Incident"):
                        update_incident(incident_id, str(new_date), new_title,
                                        new_severity, new_status, new_desc)
                        st.success("Incident updated successfully!")
                        st.rerun()

        elif operation == "Delete":
            if not incidents_df.empty:
                incident_id = st.selectbox("Select Incident to Delete", incidents_df['id'].tolist())
                incident = incidents_df[incidents_df['id'] == incident_id].iloc[0]

                st.warning(f"You are about to delete: **{incident['title']}**")

                if st.button("Confirm Delete", type="primary"):
                    delete_incident(incident_id)
                    st.success("Incident deleted successfully!")
                    st.rerun()

    # AI Assistant
    st.subheader("🤖 AI Security Assistant")

    with st.expander("Chat with AI Assistant", expanded=False):
        user_question = st.text_input("Ask about cybersecurity best practices or threat analysis:")

        if st.button("Get AI Response"):
            if user_question:
                context = f"The user is viewing a cybersecurity dashboard with {len(incidents_df)} incidents, {critical} critical threats."
                with st.spinner("Thinking..."):
                    response = get_ai_response(user_question, context)
                    st.session_state.ai_chat_history.append({
                        "question": user_question,
                        "answer": response
                    })
                    st.markdown(f"**AI Response:** {response}")

        if st.session_state.ai_chat_history:
            st.markdown("### Recent Conversations")
            for i, chat in enumerate(reversed(st.session_state.ai_chat_history[-5:])):
                with st.container():
                    st.markdown(f"**Q:** {chat['question']}")
                    st.markdown(f"**A:** {chat['answer']}")
                    st.markdown("---")


def data_science_dashboard():
    """Data Science domain dashboard."""
    st.header("📊 Data Science Dashboard")

    datasets_df = get_all_datasets()

    # Metrics
    col1, col2, col3 = st.columns(3)

    with col1:
        st.metric("Total Datasets", len(datasets_df))
    with col2:
        if not datasets_df.empty:
            total_size = datasets_df['size_gb'].sum()
            st.metric("Total Storage", f"{total_size:.2f} GB")
    with col3:
        if not datasets_df.empty:
            categories = datasets_df['category'].nunique()
            st.metric("Categories", categories)

    # Visualizations
    viz_col1, viz_col2 = st.columns(2)

    with viz_col1:
        if not datasets_df.empty:
            category_dist = datasets_df['category'].value_counts()
            fig = px.bar(
                x=category_dist.index,
                y=category_dist.values,
                title="Datasets by Category",
                labels={'x': 'Category', 'y': 'Count'},
                color=category_dist.values,
                color_continuous_scale='Viridis'
            )
            st.plotly_chart(fig, use_container_width=True)

    with viz_col2:
        if not datasets_df.empty:
            fig = px.scatter(
                datasets_df,
                x='name',
                y='size_gb',
                size='size_gb',
                color='category',
                title="Dataset Sizes",
                labels={'size_gb': 'Size (GB)'}
            )
            st.plotly_chart(fig, use_container_width=True)

    # Data table
    st.subheader("📋 Dataset Records")

    tab1, tab2 = st.tabs(["View Datasets", "Manage Datasets"])

    with tab1:
        if not datasets_df.empty:
            st.dataframe(datasets_df, use_container_width=True, hide_index=True)
        else:
            st.info("No datasets recorded yet.")

    with tab2:
        operation = st.radio("Operation", ["Create", "Update", "Delete"], horizontal=True, key="ds_op")

        if operation == "Create":
            with st.form("create_dataset"):
                col1, col2 = st.columns(2)
                with col1:
                    name = st.text_input("Dataset Name")
                    category = st.selectbox("Category", ["Sensitive", "Public", "Internal", "Confidential"])
                with col2:
                    size_gb = st.number_input("Size (GB)", min_value=0.0, step=0.1)
                    owner = st.text_input("Owner", value=st.session_state.user['username'])

                last_updated = st.date_input("Last Updated", datetime.now())

                if st.form_submit_button("Create Dataset"):
                    if name:
                        dataset_id = insert_dataset(name, category, size_gb, owner, str(last_updated))
                        st.success(f"Dataset created with ID: {dataset_id}")
                        st.rerun()


def it_operations_dashboard():
    """IT Operations domain dashboard."""
    st.header("💻 IT Operations Dashboard")

    tickets_df = get_all_tickets()

    # Metrics
    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric("Total Tickets", len(tickets_df))
    with col2:
        open_tickets = len(tickets_df[tickets_df['status'] == 'Open'])
        st.metric("Open Tickets", open_tickets)
    with col3:
        high_priority = len(tickets_df[tickets_df['priority'] == 'High'])
        st.metric("High Priority", high_priority)
    with col4:
        if len(tickets_df) > 0:
            closed = len(tickets_df[tickets_df['status'] == 'Closed'])
            resolution_rate = (closed / len(tickets_df) * 100)
            st.metric("Resolution Rate", f"{resolution_rate:.1f}%")

    # Visualizations
    viz_col1, viz_col2 = st.columns(2)

    with viz_col1:
        if not tickets_df.empty:
            priority_counts = tickets_df['priority'].value_counts()
            fig = px.pie(
                values=priority_counts.values,
                names=priority_counts.index,
                title="Tickets by Priority",
                color_discrete_sequence=px.colors.sequential.Oranges_r
            )
            st.plotly_chart(fig, use_container_width=True)

    with viz_col2:
        if not tickets_df.empty:
            status_counts = tickets_df['status'].value_counts()
            fig = px.bar(
                x=status_counts.index,
                y=status_counts.values,
                title="Tickets by Status",
                labels={'x': 'Status', 'y': 'Count'},
                color=status_counts.values,
                color_continuous_scale='Greens'
            )
            st.plotly_chart(fig, use_container_width=True)

    # Data table
    st.subheader("📋 Ticket Records")

    tab1, tab2 = st.tabs(["View Tickets", "Manage Tickets"])

    with tab1:
        if not tickets_df.empty:
            st.dataframe(tickets_df, use_container_width=True, hide_index=True)
        else:
            st.info("No tickets recorded yet.")

    with tab2:
        operation = st.radio("Operation", ["Create", "Update", "Delete"], horizontal=True, key="it_op")

        if operation == "Create":
            with st.form("create_ticket"):
                col1, col2 = st.columns(2)
                with col1:
                    title = st.text_input("Issue Title")
                    priority = st.selectbox("Priority", ["Low", "Medium", "High", "Critical"])
                with col2:
                    status = st.selectbox("Status", ["Open", "In Progress", "Closed"])
                    assigned_to = st.text_input("Assigned To")

                description = st.text_area("Description")

                if st.form_submit_button("Create Ticket"):
                    if title:
                        ticket_id = insert_ticket(
                            title, priority, status, description,
                            assigned_to, st.session_state.user['username']
                        )
                        st.success(f"Ticket created with ID: {ticket_id}")
                        st.rerun()


# Main app logic
def main():
    """Main application logic."""
    if not st.session_state.logged_in:
        if 'show_register' in st.session_state and st.session_state.show_register:
            register_page()
        else:
            login_page()
    else:
        # Sidebar
        with st.sidebar:
            st.title("🔐 Navigation")
            st.markdown(f"**Logged in as:** {st.session_state.user['username']}")
            st.markdown(f"**Role:** {st.session_state.user['role']}")
            st.markdown("---")

            page = st.radio(
                "Select Domain",
                ["🛡️ Cybersecurity", "📊 Data Science", "💻 IT Operations"]
            )

            st.markdown("---")
            if st.button("🚪 Logout", use_container_width=True):
                st.session_state.logged_in = False
                st.session_state.user = None
                st.session_state.ai_chat_history = []
                st.rerun()

        # Main content
        if page == "🛡️ Cybersecurity":
            cybersecurity_dashboard()
        elif page == "📊 Data Science":
            data_science_dashboard()
        elif page == "💻 IT Operations":
            it_operations_dashboard()


if __name__ == "__main__":
    main()