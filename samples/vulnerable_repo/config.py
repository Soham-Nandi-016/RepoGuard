"""
Vulnerable Sample: App Configuration
Demonstrates hardcoded secrets: OpenAI API key, AWS key, DB connection string, and JWT.
"""

# Flagged: SEC-OPENAI-001 - Hardcoded OpenAI API Key
OPENAI_API_KEY = "sk-proj-928471928374918237491827349182"

# Flagged: SEC-AWS-001 - Hardcoded AWS Access Key ID
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"

# Flagged: SEC-AWS-002 - AWS Secret Key
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# Flagged: SEC-DB-001 - Hardcoded Database URI with credentials
DATABASE_URL = "postgresql://prod_admin:SecretPassw0rd99!@db.internal.corp:5432/finance_db"

# Flagged: SEC-JWT-001 - Exposed JWT Token
DEFAULT_AUTH_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
