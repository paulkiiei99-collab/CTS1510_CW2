import streamlit as st
import pandas as pd
import bcrypt
import sqlite3
from datetime import datetime


# Page config
st.set_page_config(
    page_title="Multi-Domain Intelligence Platform",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# ========== DATABASE INITIALIZATION ==========
def init_database():
    """Initialize SQLite database with tables"""
    conn = sqlite3.connect('intelligence_platform.db')
    cursor = conn.cursor()

    # Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Cyber incidents table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS cyber_incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id TEXT,
            timestamp TIMESTAMP,
            category TEXT,
            severity TEXT,
            status TEXT,
            description TEXT,
            source_ip TEXT,
            destination_ip TEXT,
            assigned_to TEXT
        )
    ''')

    # Datasets table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS datasets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            source TEXT,
            category TEXT,
            rows INTEGER,
            upload_date TIMESTAMP
        )
    ''')

    # IT tickets table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS it_tickets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ticket_id TEXT,
            title TEXT,
            priority TEXT,
            status TEXT,
            created_at TIMESTAMP,
            assigned_to TEXT,
            resolution_time_hours INTEGER
        )
    ''')

    conn.commit()
    conn.close()

# Initialize database on first run
init_database()

# ========== HELPER FUNCTIONS ==========
def convert_timestamp(value):
    """Convert any timestamp-like value to string for SQLite"""
    if pd.isna(value):
        return None
    elif isinstance(value, pd.Timestamp):
        return value.strftime('%Y-%m-%d %H:%M:%S')
    elif isinstance(value, datetime):
        return value.strftime('%Y-%m-%d %H:%M:%S')
    elif isinstance(value, str):
        return value
    else:
        try:
            return str(value)
        except:
            return None

def hash_password(password):
    """Hash password using bcrypt"""
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

def verify_password(password, hashed_password):
    """Verify password against hash"""
    try:
        return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))
    except:
        return False

# ========== DATABASE OPERATIONS ==========
class DatabaseManager:
    """Handles all database operations"""

    @staticmethod
    def add_user(username, password, role="user"):
        """Add a new user to database"""
        try:
            conn = sqlite3.connect('intelligence_platform.db')
            cursor = conn.cursor()
            hashed_password = hash_password(password)
            cursor.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                (username, hashed_password, role)
            )
            conn.commit()
            conn.close()
            return True
        except sqlite3.IntegrityError:
            return False  # Username already exists
        except Exception as e:
            st.error(f"Database error: {e}")
            return False

    @staticmethod
    def authenticate_user(username, password):
        """Authenticate user"""
        try:
            conn = sqlite3.connect('intelligence_platform.db')
            cursor = conn.cursor()
            cursor.execute(
                "SELECT password_hash, role FROM users WHERE username = ?",
                (username,)
            )
            result = cursor.fetchone()
            conn.close()

            if result and verify_password(password, result[0]):
                return True, result[1]  # Return success and role
            return False, None
        except Exception as e:
            st.error(f"Authentication error: {e}")
            return False, None

    @staticmethod
    def save_incident(incident_data):
        """Save cyber incident to database"""
        try:
            conn = sqlite3.connect('intelligence_platform.db')
            cursor = conn.cursor()

            # Convert timestamp
            timestamp = convert_timestamp(incident_data.get('timestamp'))

            cursor.execute('''
                INSERT INTO cyber_incidents 
                (incident_id, timestamp, category, severity, status, description, source_ip, destination_ip, assigned_to)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                incident_data.get('incident_id'),
                timestamp,
                incident_data.get('category'),
                incident_data.get('severity'),
                incident_data.get('status'),
                incident_data.get('description'),
                incident_data.get('source_ip'),
                incident_data.get('destination_ip'),
                incident_data.get('assigned_to')
            ))
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            st.error(f"Error saving incident: {e}")
            return False

    @staticmethod
    def get_incidents(filters=None):
        """Get incidents from database"""
        try:
            conn = sqlite3.connect('intelligence_platform.db')

            query = "SELECT * FROM cyber_incidents WHERE 1=1"
            params = []

            if filters:
                if filters.get('severity'):
                    severity_list = filters['severity']
                    if severity_list:
                        query += " AND severity IN ({})".format(','.join(['?'] * len(severity_list)))
                        params.extend(severity_list)
                if filters.get('status'):
                    status_list = filters['status']
                    if status_list:
                        query += " AND status IN ({})".format(','.join(['?'] * len(status_list)))
                        params.extend(status_list)

            df = pd.read_sql_query(query, conn, params=params if params else None)
            conn.close()

            # Convert timestamp strings back to datetime
            if 'timestamp' in df.columns:
                df['timestamp'] = pd.to_datetime(df['timestamp'])

            return df
        except Exception as e:
            st.error(f"Error fetching incidents: {e}")
            return pd.DataFrame()

    @staticmethod
    def save_dataset(dataset_data):
        """Save dataset to database"""
        try:
            conn = sqlite3.connect('intelligence_platform.db')
            cursor = conn.cursor()

            # Convert upload_date
            upload_date = convert_timestamp(dataset_data.get('upload_date'))

            cursor.execute('''
                INSERT INTO datasets (name, source, category, rows, upload_date)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                dataset_data.get('name'),
                dataset_data.get('source'),
                dataset_data.get('category'),
                dataset_data.get('rows'),
                upload_date
            ))
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            st.error(f"Error saving dataset: {e}")
            return False

    @staticmethod
    def get_datasets():
        """Get all datasets from database"""
        try:
            conn = sqlite3.connect('intelligence_platform.db')
            df = pd.read_sql_query("SELECT * FROM datasets", conn)
            conn.close()

            # Convert upload_date back to datetime
            if 'upload_date' in df.columns:
                df['upload_date'] = pd.to_datetime(df['upload_date'])

            return df
        except Exception as e:
            st.error(f"Error fetching datasets: {e}")
            return pd.DataFrame()

    @staticmethod
    def save_ticket(ticket_data):
        """Save IT ticket to database"""
        try:
            conn = sqlite3.connect('intelligence_platform.db')
            cursor = conn.cursor()

            # Convert created_at
            created_at = convert_timestamp(ticket_data.get('created_at'))

            cursor.execute('''
                INSERT INTO it_tickets 
                (ticket_id, title, priority, status, created_at, assigned_to, resolution_time_hours)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                ticket_data.get('ticket_id'),
                ticket_data.get('title'),
                ticket_data.get('priority'),
                ticket_data.get('status'),
                created_at,
                ticket_data.get('assigned_to'),
                ticket_data.get('resolution_time_hours', 0)
            ))
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            st.error(f"Error saving ticket: {e}")
            return False

    @staticmethod
    def get_tickets(filters=None):
        """Get IT tickets from database"""
        try:
            conn = sqlite3.connect('intelligence_platform.db')

            query = "SELECT * FROM it_tickets WHERE 1=1"
            params = []

            if filters:
                if filters.get('priority'):
                    priority_list = filters['priority']
                    if priority_list:
                        query += " AND priority IN ({})".format(','.join(['?'] * len(priority_list)))
                        params.extend(priority_list)
                if filters.get('status'):
                    status_list = filters['status']
                    if status_list:
                        query += " AND status IN ({})".format(','.join(['?'] * len(status_list)))
                        params.extend(status_list)

            df = pd.read_sql_query(query, conn, params=params if params else None)
            conn.close()

            # Convert created_at back to datetime
            if 'created_at' in df.columns:
                df['created_at'] = pd.to_datetime(df['created_at'])

            return df
        except Exception as e:
            st.error(f"Error fetching tickets: {e}")
            return pd.DataFrame()


# ========== OOP CLASSES ==========
class User:
    """User entity class"""

    def __init__(self, username="", password_hash="", role="user"):
        self.username = username
        self._password_hash = password_hash  # Private attribute
        self.role = role

    def set_password(self, plain_password):
        """Hash and set password"""
        self._password_hash = hash_password(plain_password)

    def verify_password(self, plain_password):
        """Verify password"""
        return verify_password(plain_password, self._password_hash)

    def is_admin(self):
        """Check if user is admin"""
        return self.role.lower() == "admin"

    def __str__(self):
        return f"User(username={self.username}, role={self.role})"


class SecurityIncident:
    """Cybersecurity incident entity class"""

    def __init__(self, incident_id="", timestamp=None, category="", severity="Medium",
                 status="Open", description="", source_ip="", destination_ip="", assigned_to=""):
        self.incident_id = incident_id
        self.timestamp = timestamp or datetime.now()
        self.category = category
        self.severity = severity
        self.status = status
        self.description = description
        self.source_ip = source_ip
        self.destination_ip = destination_ip
        self.assigned_to = assigned_to

    def get_severity_score(self):
        """Convert severity to numeric score"""
        severity_scores = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
        return severity_scores.get(self.severity, 0)

    def is_open(self):
        """Check if incident is still open"""
        return self.status in ["Open", "In Progress"]

    def to_dict(self):
        """Convert to dictionary for database"""
        return {
            "incident_id": self.incident_id,
            "timestamp": self.timestamp,
            "category": self.category,
            "severity": self.severity,
            "status": self.status,
            "description": self.description,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "assigned_to": self.assigned_to
        }

    def __str__(self):
        return f"Incident({self.incident_id}, {self.severity}, {self.status})"


class Dataset:
    """Dataset entity class"""

    def __init__(self, name="", source="", category="", rows=0, upload_date=None):
        self.name = name
        self.source = source
        self.category = category
        self.rows = rows
        self.upload_date = upload_date or datetime.now()

    def get_size_gb(self):
        """Estimate size in GB (assuming 1KB per row)"""
        return (self.rows * 1024) / (1024 ** 3)  # Convert to GB

    def is_large_dataset(self):
        """Check if dataset is large (>1M rows)"""
        return self.rows > 1000000

    def to_dict(self):
        """Convert to dictionary for database"""
        return {
            "name": self.name,
            "source": self.source,
            "category": self.category,
            "rows": self.rows,
            "upload_date": self.upload_date
        }


class ITTicket:
    """IT ticket entity class"""

    def __init__(self, ticket_id="", title="", priority="Medium", status="Open",
                 created_at=None, assigned_to="", resolution_time_hours=0):
        self.ticket_id = ticket_id
        self.title = title
        self.priority = priority
        self.status = status
        self.created_at = created_at or datetime.now()
        self.assigned_to = assigned_to
        self.resolution_time_hours = resolution_time_hours

    def is_overdue(self):
        """Check if ticket is overdue (>72 hours)"""
        if self.status in ["Open", "In Progress"]:
            if isinstance(self.created_at, datetime):
                age_hours = (datetime.now() - self.created_at).total_seconds() / 3600
                return age_hours > 72
        return False

    def get_priority_score(self):
        """Convert priority to numeric score"""
        priority_scores = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
        return priority_scores.get(self.priority, 0)

    def to_dict(self):
        """Convert to dictionary for database"""
        return {
            "ticket_id": self.ticket_id,
            "title": self.title,
            "priority": self.priority,
            "status": self.status,
            "created_at": self.created_at,
            "assigned_to": self.assigned_to,
            "resolution_time_hours": self.resolution_time_hours
        }


# ========== AI ASSISTANT ==========
class AIAssistant:
    """Simple AI assistant (simulated)"""

    @staticmethod
    def analyze_incident(incident):
        """Analyze security incident"""
        analysis = {
            "Low": "Routine monitoring. No immediate action required.",
            "Medium": "Investigate within 24 hours. Update firewall rules.",
            "High": "Immediate investigation required. Isolate affected systems.",
            "Critical": "Emergency response. Activate incident response team."
        }
        return analysis.get(incident.severity, "Analysis unavailable")

    @staticmethod
    def suggest_dataset_analysis(dataset):
        """Suggest analysis for dataset"""
        if dataset.rows > 500000:
            return "Consider distributed processing (Spark/Dask). Sample data before full analysis."
        elif dataset.category == "Time Series":
            return "Apply time series analysis: trend decomposition, forecasting with ARIMA/LSTM."
        elif dataset.category == "Transactional":
            return "Perform RFM analysis and customer segmentation."
        else:
            return "Start with exploratory data analysis (EDA) and feature engineering."

    @staticmethod
    def prioritize_ticket(ticket):
        """Provide ticket prioritization advice"""
        advice = {
            "Critical": "Immediate attention. Escalate to senior staff.",
            "High": "Address within 4 hours. System impact likely.",
            "Medium": "Address within 24 hours. Business process affected.",
            "Low": "Address within 72 hours. Minor inconvenience."
        }
        return advice.get(ticket.priority, "Follow standard SLA procedures.")


# ========== MAIN APPLICATION ==========
st.title("Multi-Domain Intelligence Platform")
st.markdown("---")

# Initialize session state
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
if "username" not in st.session_state:
    st.session_state.username = ""
if "role" not in st.session_state:
    st.session_state.role = "user"
if "data_loaded" not in st.session_state:
    st.session_state.data_loaded = False


# Function to load CSV data into database
def load_csv_data():
    """Load CSV data and save to database"""
    try:
        db = DatabaseManager()

        # Clear existing data
        conn = sqlite3.connect('intelligence_platform.db')
        cursor = conn.cursor()
        cursor.execute("DELETE FROM cyber_incidents")
        cursor.execute("DELETE FROM datasets")
        cursor.execute("DELETE FROM it_tickets")
        conn.commit()
        conn.close()

        # Load and save cyber incidents
        try:
            cyber_df = pd.read_csv("cyber_incidents (1).csv")
            cyber_df['timestamp'] = pd.to_datetime(cyber_df['timestamp'])
            for _, row in cyber_df.iterrows():
                db.save_incident(row.to_dict())
            st.success(f"Loaded {len(cyber_df)} cyber incidents")
        except Exception as e:
            st.warning(f"Could not load cyber incidents: {e}")

        # Load and save datasets
        try:
            datasets_df = pd.read_csv("datasets_metadata (1).csv")
            datasets_df['upload_date'] = pd.to_datetime(datasets_df['upload_date'])
            for _, row in datasets_df.iterrows():
                db.save_dataset(row.to_dict())
            st.success(f"Loaded {len(datasets_df)} datasets")
        except Exception as e:
            st.warning(f"Could not load datasets: {e}")

        # Load and save IT tickets
        try:
            tickets_df = pd.read_csv("it_tickets (1).csv")
            tickets_df['created_at'] = pd.to_datetime(tickets_df['created_at'])
            for _, row in tickets_df.iterrows():
                db.save_ticket(row.to_dict())
            st.success(f"Loaded {len(tickets_df)} IT tickets")
        except Exception as e:
            st.warning(f"Could not load IT tickets: {e}")

        st.session_state.data_loaded = True
        return True
    except Exception as e:
        st.error(f"Error loading data: {e}")
        return False


# Check if we need to load data
if not st.session_state.data_loaded:
    with st.spinner("Loading initial data into database..."):
        if load_csv_data():
            st.success("Data loaded successfully!")
        else:
            st.error("Failed to load data. Please check CSV files.")

# ========== LOGIN / REGISTER PAGE ==========
if not st.session_state.logged_in:
    tab_login, tab_register = st.tabs(["Login", "Register"])

    with tab_login:
        st.subheader("Login to Intelligence Platform")
        username = st.text_input("Username", key="login_username")
        password = st.text_input("Password", type="password", key="login_password")

        if st.button("Log In", type="primary", use_container_width=True, key="login_button"):
            if username and password:
                db = DatabaseManager()
                authenticated, role = db.authenticate_user(username, password)
                if authenticated:
                    st.session_state.logged_in = True
                    st.session_state.username = username
                    st.session_state.role = role
                    st.success(f"Welcome back, {username}!")
                    st.rerun()
                else:
                    st.error("Invalid credentials")
            else:
                st.warning("Please enter username and password")

    with tab_register:
        st.subheader("Create New Account")
        new_user = st.text_input("New Username", key="register_username")
        new_pass = st.text_input("New Password", type="password", key="register_password")
        confirm = st.text_input("Confirm Password", type="password", key="register_confirm_password")
        user_role = st.selectbox("Role", ["user", "analyst", "admin"], key="register_role")

        if st.button("Register", type="primary", key="register_button"):
            if not new_user or not new_pass:
                st.warning("Please fill all fields")
            elif new_pass != confirm:
                st.error("Passwords do not match")
            elif len(new_pass) < 6:
                st.error("Password must be at least 6 characters")
            else:
                db = DatabaseManager()
                if db.add_user(new_user, new_pass, user_role):
                    st.success("Account created! You can now log in.")
                    st.balloons()
                else:
                    st.error("Username already exists")

# ========== LOGGED-IN DASHBOARD ==========
else:
    st.success(f"Logged in as **{st.session_state.username}** (Role: {st.session_state.role})")

    # Create instances
    ai_assistant = AIAssistant()
    db = DatabaseManager()

    # Sidebar
    with st.sidebar:
        st.image("https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcQ9jyim-4Ats0DsW7XPslTJgDwiMWpHyDeH7A&s", width=100)
        st.write(f"**User:** {st.session_state.username}")
        st.write(f"**Role:** {st.session_state.role}")

        # Reload data button
        if st.button("Reload CSV Data", key="reload_data"):
            with st.spinner("Reloading data..."):
                if load_csv_data():
                    st.success("Data reloaded!")
                    st.rerun()

        # AI Assistant quick access
        st.markdown("---")
        st.subheader("AI Assistant")
        if st.button("Get Security Tips", key="security_tips"):
            tip = ai_assistant.analyze_incident(
                SecurityIncident(severity="Medium")
            )
            st.info(tip)

        if st.button("Logout", type="primary", key="logout_button"):
            st.session_state.logged_in = False
            st.session_state.username = ""
            st.session_state.role = "user"
            st.rerun()

    # Tabs
    tab_cyber, tab_data, tab_it, tab_ai = st.tabs([
        "Cybersecurity", "Data Science", "IT Operations", "AI Assistant"
    ])

    # ===========================
    # CYBERSECURITY TAB
    # ===========================
    with tab_cyber:
        st.subheader("Cybersecurity Threat Dashboard")

        # Create incident using OOP
        with st.expander("Report New Incident", expanded=False):
            col1, col2 = st.columns(2)
            with col1:
                incident_id = st.text_input("Incident ID",
                                          value=f"INC-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
                                          key="incident_id_input")
                category = st.selectbox("Category",
                                      ["Malware", "Phishing", "DDoS", "Unauthorized Access", "Data Leak"],
                                      key="incident_category")
                severity = st.select_slider("Severity",
                                          options=["Low", "Medium", "High", "Critical"],
                                          key="incident_severity")

            with col2:
                description = st.text_area("Description", key="incident_description")
                source_ip = st.text_input("Source IP",
                                        value="192.168.1.1",
                                        key="incident_source_ip")
                assigned_to = st.text_input("Assign To",
                                          value=st.session_state.username,
                                          key="incident_assigned_to")

            if st.button("Submit Incident", type="primary", key="submit_incident"):
                incident = SecurityIncident(
                    incident_id=incident_id,
                    timestamp=datetime.now(),
                    category=category,
                    severity=severity,
                    status="Open",
                    description=description,
                    source_ip=source_ip,
                    assigned_to=assigned_to
                )

                if db.save_incident(incident.to_dict()):
                    st.success("Incident reported successfully!")

                    # AI Analysis
                    analysis = ai_assistant.analyze_incident(incident)
                    st.info(f"AI Analysis: {analysis}")
                    st.rerun()
                else:
                    st.error("Failed to save incident")

        # Get data from database
        incidents_df = db.get_incidents()

        if not incidents_df.empty:
            # Convert to OOP objects for demonstration
            incidents = []
            for _, row in incidents_df.iterrows():
                incident = SecurityIncident(
                    incident_id=row['incident_id'],
                    timestamp=row['timestamp'],
                    category=row['category'],
                    severity=row['severity'],
                    status=row['status'],
                    description=row['description']
                )
                incidents.append(incident)

            # Metrics using OOP objects
            open_incidents = [i for i in incidents if i.is_open()]
            high_critical = [i for i in incidents if i.severity in ["High", "Critical"]]
            avg_severity = sum(i.get_severity_score() for i in incidents) / len(incidents) if incidents else 0

            col1, col2, col3, col4 = st.columns(4)
            col1.metric("Total Incidents", len(incidents))
            col2.metric("Open Incidents", len(open_incidents))
            col3.metric("High/Critical", len(high_critical))
            col4.metric("Avg Severity", f"{avg_severity:.1f}/4.0")

            # Filters
            col_a, col_b = st.columns(2)
            with col_a:
                severity_filter = st.multiselect(
                    "Filter by Severity",
                    options=["Low", "Medium", "High", "Critical"],
                    default=["Low", "Medium", "High", "Critical"],
                    key="cyber_severity_filter"
                )
            with col_b:
                status_filter = st.multiselect(
                    "Filter by Status",
                    options=["Open", "In Progress", "Resolved", "Closed"],
                    default=["Open", "In Progress"],
                    key="cyber_status_filter"
                )

            # Filter incidents
            filtered_incidents = db.get_incidents({
                "severity": severity_filter,
                "status": status_filter
            })

            # Visualizations
            col1, col2 = st.columns(2)
            with col1:
                if not filtered_incidents.empty:
                    severity_counts = filtered_incidents['severity'].value_counts()
                    st.bar_chart(severity_counts)

            with col2:
                if not filtered_incidents.empty:
                    category_counts = filtered_incidents['category'].value_counts().head(6)
                    st.bar_chart(category_counts)

            # Recent incidents with AI analysis
            st.subheader("Recent Incidents with AI Analysis")
            recent_df = incidents_df.sort_values('timestamp', ascending=False).head(3)

            for _, row in recent_df.iterrows():
                incident_obj = SecurityIncident(
                    severity=row['severity'],
                    category=row['category'],
                    description=row['description'][:100] + "..." if len(row['description']) > 100 else row[
                        'description']
                )
                analysis = ai_assistant.analyze_incident(incident_obj)

                with st.expander(f"{row['incident_id']} - {row['severity']} - {row['category']}"):
                    col1, col2 = st.columns([2, 1])
                    with col1:
                        st.write(f"**Description:** {row['description']}")
                        st.write(f"**Status:** {row['status']}")
                        st.write(f"**Timestamp:** {row['timestamp']}")
                    with col2:
                        st.info(f"**AI Advice:** {analysis}")

            # All incidents table
            st.subheader("All Incidents")
            st.dataframe(
                filtered_incidents.sort_values('timestamp', ascending=False),
                use_container_width=True
            )
        else:
            st.info("No incidents found in database.")

    # ===========================
    # DATA SCIENCE TAB
    # ===========================
    with tab_data:
        st.subheader("Data Science & ML Datasets Repository")

        # Add new dataset using OOP
        with st.expander("📁 Upload New Dataset", expanded=False):
            col1, col2 = st.columns(2)
            with col1:
                dataset_name = st.text_input("Dataset Name", key="dataset_name_input")
                source = st.selectbox("Source",
                                    ["Internal", "External API", "Public Repository", "Generated"],
                                    key="dataset_source")
                category = st.selectbox("Category",
                                      ["Time Series", "Transactional", "Image", "Text", "Structured"],
                                      key="dataset_category")

            with col2:
                rows = st.number_input("Number of Rows", min_value=1, value=1000, key="dataset_rows")
                upload_date = st.date_input("Upload Date", value=datetime.now().date(), key="dataset_date")

            if st.button("Upload Dataset", type="primary", key="upload_dataset"):
                dataset = Dataset(
                    name=dataset_name,
                    source=source,
                    category=category,
                    rows=rows,
                    upload_date=upload_date
                )

                if db.save_dataset(dataset.to_dict()):
                    st.success("Dataset uploaded successfully!")

                    # AI Suggestions
                    suggestion = ai_assistant.suggest_dataset_analysis(dataset)
                    st.info(f"🤖 AI Suggestion: {suggestion}")
                    st.rerun()
                else:
                    st.error("Failed to upload dataset")

        # Get datasets from database
        datasets_df = db.get_datasets()

        if not datasets_df.empty:
            # Convert to OOP objects
            datasets = []
            for _, row in datasets_df.iterrows():
                dataset = Dataset(
                    name=row['name'],
                    source=row['source'],
                    category=row['category'],
                    rows=row['rows'],
                    upload_date=row['upload_date']
                )
                datasets.append(dataset)

            # Metrics using OOP
            total_rows = sum(d.rows for d in datasets)
            large_datasets = [d for d in datasets if d.is_large_dataset()]
            avg_size_gb = sum(d.get_size_gb() for d in datasets) / len(datasets) if datasets else 0

            col1, col2, col3 = st.columns(3)
            col1.metric("Total Datasets", len(datasets))
            col2.metric("Total Rows", f"{total_rows:,}")
            col3.metric("Avg Size", f"{avg_size_gb:.2f} GB")

            # Dataset overview
            st.subheader("Available Datasets")
            display_df = datasets_df.copy()
            display_df['upload_date'] = pd.to_datetime(display_df['upload_date']).dt.strftime("%b %d, %Y")
            display_df['estimated_size_gb'] = display_df['rows'].apply(lambda x: (x * 1024) / (1024 ** 3))

            st.dataframe(
                display_df,
                use_container_width=True,
                column_config={
                    "estimated_size_gb": st.column_config.NumberColumn("Est. Size (GB)", format="%.2f GB")
                }
            )

            # AI recommendations for each dataset
            st.subheader("AI Analysis Recommendations")
            for dataset in datasets[:3]:  # Show for first 3 datasets
                with st.expander(f"Analysis for {dataset.name}"):
                    suggestion = ai_assistant.suggest_dataset_analysis(dataset)
                    st.write(suggestion)

                    if dataset.is_large_dataset():
                        st.warning("Large dataset - consider distributed processing")
                    else:
                        st.success("Dataset size is manageable for local processing")
        else:
            st.info("No datasets found in database.")

    # ===========================
    # IT OPERATIONS TAB
    # ===========================
    with tab_it:
        st.subheader("IT Service Desk & Operations")

        # Create new ticket using OOP
        with st.expander("Create New Ticket", expanded=False):
            col1, col2 = st.columns(2)
            with col1:
                ticket_id = st.text_input("Ticket ID",
                                        value=f"TICKET-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
                                        key="ticket_id_input")
                title = st.text_input("Title", key="ticket_title_input")
                priority = st.selectbox("Priority",
                                      ["Low", "Medium", "High", "Critical"],
                                      key="ticket_priority")

            with col2:
                assigned_to = st.text_input("Assign To",
                                          value=st.session_state.username,
                                          key="ticket_assigned_to")
                description = st.text_area("Description", key="ticket_description")

            if st.button("Create Ticket", type="primary", key="create_ticket"):
                ticket = ITTicket(
                    ticket_id=ticket_id,
                    title=title,
                    priority=priority,
                    status="Open",
                    assigned_to=assigned_to
                )

                if db.save_ticket(ticket.to_dict()):
                    st.success("Ticket created successfully!")

                    # AI Prioritization advice
                    advice = ai_assistant.prioritize_ticket(ticket)
                    st.info(f"AI Prioritization: {advice}")
                    st.rerun()
                else:
                    st.error("Failed to create ticket")

        # Get tickets from database
        tickets_df = db.get_tickets()

        if not tickets_df.empty:
            # Convert to OOP objects
            tickets = []
            for _, row in tickets_df.iterrows():
                ticket = ITTicket(
                    ticket_id=row['ticket_id'],
                    title=row['title'],
                    priority=row['priority'],
                    status=row['status'],
                    created_at=row['created_at'],
                    assigned_to=row['assigned_to'],
                    resolution_time_hours=row['resolution_time_hours']
                )
                tickets.append(ticket)

            # Filters
            col1, col2 = st.columns(2)
            with col1:
                priority_filter = st.multiselect(
                    "Filter by Priority",
                    options=["Low", "Medium", "High", "Critical"],
                    default=["Low", "Medium", "High", "Critical"],
                    key="it_priority_filter"
                )
            with col2:
                status_filter = st.multiselect(
                    "Filter by Status",
                    options=["Open", "In Progress", "Resolved", "Closed"],
                    default=["Open", "In Progress"],
                    key="it_status_filter"
                )

            # Get filtered tickets
            filtered_tickets_df = db.get_tickets({
                "priority": priority_filter,
                "status": status_filter
            })

            # Metrics using OOP
            open_tickets = [t for t in tickets if t.status in ["Open", "In Progress"]]
            critical_tickets = [t for t in tickets if t.priority == "Critical"]
            overdue_tickets = [t for t in tickets if t.is_overdue()]

            c1, c2, c3, c4 = st.columns(4)
            c1.metric("Total Tickets", len(tickets))
            c2.metric("Open Tickets", len(open_tickets))
            c3.metric("Critical Tickets", len(critical_tickets))
            c4.metric("Overdue Tickets", len(overdue_tickets), delta="SLA Risk" if overdue_tickets else None)

            # Priority distribution
            col1, col2 = st.columns(2)
            with col1:
                if not filtered_tickets_df.empty:
                    priority_counts = filtered_tickets_df['priority'].value_counts()
                    st.bar_chart(priority_counts)

            with col2:
                if not filtered_tickets_df.empty:
                    status_counts = filtered_tickets_df['status'].value_counts()
                    st.bar_chart(status_counts)

            # AI analysis of ticket backlog
            if overdue_tickets:
                st.warning(f"{len(overdue_tickets)} tickets are overdue. Consider reassigning or escalating.")

            # Show tickets with AI suggestions
            st.subheader("Ticket Queue with AI Recommendations")
            for i, ticket in enumerate(tickets[:5]):  # Show first 5 tickets
                with st.expander(f"{ticket.ticket_id} - {ticket.priority} - {ticket.title}"):
                    col1, col2 = st.columns([2, 1])
                    with col1:
                        st.write(f"**Status:** {ticket.status}")
                        st.write(f"**Assigned to:** {ticket.assigned_to}")
                        st.write(f"**Created:** {ticket.created_at}")
                        if ticket.is_overdue():
                            st.error("OVERDUE - Exceeds 72 hour SLA")

                    with col2:
                        advice = ai_assistant.prioritize_ticket(ticket)
                        st.info(f"**AI Advice:** {advice}")

            # All tickets table
            st.subheader("All Tickets")
            st.dataframe(
                filtered_tickets_df.sort_values('created_at', ascending=False),
                use_container_width=True
            )
        else:
            st.info("No tickets found in database.")

    # ===========================
    # AI ASSISTANT TAB
    # ===========================
    with tab_ai:
        st.subheader("🤖 Multi-Domain AI Assistant")

        col1, col2 = st.columns([2, 1])

        with col1:
            st.markdown("""
            ### Intelligent Analysis Across All Domains

            This AI assistant provides specialized expertise for:
            - **Cybersecurity**: Incident analysis and threat mitigation
            - **Data Science**: Dataset analysis and ML recommendations
            - **IT Operations**: Ticket prioritization and troubleshooting

            Select a domain and ask your question below.
            """)

            domain = st.selectbox(
                "Select Domain Expert",
                ["Cybersecurity", "Data Science", "IT Operations", "General"],
                key="ai_domain_select"
            )

            question = st.text_area(
                "Your Question",
                placeholder=f"Ask a question about {domain}...",
                height=100,
                key="ai_question_input"
            )

            if st.button("Ask AI Assistant", type="primary", key="ask_ai_button"):
                if question:
                    with st.spinner("AI is thinking..."):
                        # Simulate AI response based on domain
                        import random

                        responses = {
                            "Cybersecurity": [
                                "Based on recent incidents, phishing attacks have increased by 40%. "
                                "Recommend implementing DMARC policies and user training.",
                                "For DDoS mitigation, consider rate limiting and cloud-based protection services.",
                                "Security incident response should follow NIST framework: Prepare, Identify, Contain, Eradicate, Recover."
                            ],
                            "Data Science": [
                                "For time series data, consider ARIMA for stationary data or LSTM for complex patterns.",
                                "Feature engineering can improve model performance by 20-30%. Focus on domain-specific features.",
                                "Large datasets (>1M rows) benefit from distributed computing with Spark or Dask."
                            ],
                            "IT Operations": [
                                "Critical tickets should be addressed within 4 hours. Consider automating common resolutions.",
                                "System monitoring should include CPU, memory, disk I/O, and network latency metrics.",
                                "Implement ITIL framework for better service management and incident tracking."
                            ],
                            "General": [
                                "The multi-domain platform integrates cybersecurity, data science, and IT operations for comprehensive intelligence.",
                                "Best practices include regular backups, security audits, and continuous monitoring across all domains.",
                                "Consider implementing dashboards with real-time alerts for proactive management."
                            ]
                        }

                        response = random.choice(
                            responses.get(domain, ["I'm here to help! Please ask a specific question."]))

                        st.success("AI Response:")
                        st.info(response)
                else:
                    st.warning("Please enter a question")

        with col2:
            st.markdown("### Quick Actions")

            if st.button("Analyze Security Posture", key="analyze_security"):
                st.info(
                    "**Security Analysis:** Recent phishing spike detected. Recommend immediate user awareness training.")

            if st.button("Dataset Recommendations", key="dataset_recommendations"):
                st.info(
                    "**Data Analysis:** For transactional data, consider RFM analysis and customer segmentation models.")

            if st.button("IT Optimization", key="it_optimization"):
                st.info(
                    "**IT Recommendations:** Implement automated ticket routing to reduce resolution time by 30%.")

            st.markdown("---")
            st.markdown("### Recent AI Insights")
            st.caption("• Phishing incidents increased by 40% in Q1")
            st.caption("• Server_Logs dataset ideal for anomaly detection")
            st.caption("• 15% of tickets exceed SLA resolution time")

# ========== FOOTER ==========
st.markdown("---")
st.caption("Multi-Domain Intelligence Platform | KELSEY THEE GENIUS")