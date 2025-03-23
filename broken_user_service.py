import os
import json
import sqlite3
import hashlib
from datetime import datetime, timedelta
import random

# Global variable storing user passwords - security issue!
USER_PASSWORDS = {}

class UserService:
    def __init__(self, db_path):
        self.db_path = db_path
        self.connection = None
        self.debug_mode = True  # Should be disabled in production
        self.unused_variable = "This variable is never used"
        
        # Connect to database
        self.connect_to_db()
    
    def connect_to_db(self):
        """Connect to the SQLite database."""
        self.connection = sqlite3.connect(self.db_path)
        
    def create_user(self, username, password, email):
        """Create a new user in the database."""
        # No input validation
        cursor = self.connection.cursor()
        
        # SQL Injection vulnerability
        query = f"INSERT INTO users (username, password, email) VALUES ('{username}', '{password}', '{email}')"
        cursor.execute(query)
        
        # Store password in global dict - very bad practice!
        USER_PASSWORDS[username] = password
        
        self.connection.commit()
        print(f"User {username} created successfully!")
        return True
    
    def get_user(self, user_id):
        """Get user information from the database."""
        try:
            cursor = self.connection.cursor()
            
            # Another SQL Injection vulnerability
            query = f"SELECT * FROM users WHERE id = {user_id}"
            cursor.execute(query)
            
            user_data = cursor.fetchone()
            return user_data
        except Exception as e:
            # Generic exception handling with pass
            pass
    
    def find_users_by_name(self, name):
        """Find users by name - inefficient implementation."""
        all_users = []
        cursor = self.connection.cursor()
        cursor.execute("SELECT * FROM users")
        
        # Inefficient - should use SQL WHERE clause
        for user in cursor.fetchall():
            if name.lower() in user[1].lower():  # user[1] is the username
                all_users.append(user)
        
        return all_users
    
    def fibonacci(self, n):
        """Calculate the nth Fibonacci number - extremely inefficient implementation."""
        if n <= 0:
            return 0
        elif n == 1:
            return 1
        else:
            return self.fibonacci(n - 1) + self.fibonacci(n - 2)
    
    def generate_report(self, user_id):
        """Generate a user activity report."""
        # Hardcoded filepath - potential directory traversal
        filepath = f"/tmp/reports/user_{user_id}_report.txt"
        
        user_data = self.get_user(user_id)
        if not user_data:
            return None
        
        # Usage of eval - security risk
        report_config = '{"sections": ["profile", "activity", "logs"]}'
        config = eval(report_config)
        
        with open(filepath, 'w') as f:
            f.write(f"Report for user {user_data[1]}\n")
            f.write(f"Generated on {datetime.now()}\n")
            f.write("-" * 50 + "\n")
            
            for section in config['sections']:
                f.write(f"\n{section.upper()}:\n")
                f.write("No data available\n")
        
        # Very long line that exceeds recommended line length limits and makes the code hard to read because it's so long that you have to scroll horizontally to see it all which is not good practice
        print(f"Report generated successfully for user {user_data[1]} with ID {user_id} at {datetime.now()} and saved to {filepath} with sections {config['sections']}")
        
        return filepath
    
    def delete_old_reports(self):
        """Delete reports older than 30 days."""
        # Potential risk with os.system
        os.system(f"rm -rf /tmp/reports/old/*")
        return True
    
    def close(self):
        """Close the database connection."""
        if self.connection:
            self.connection.close()


# Example usage
if __name__ == "__main__":
    service = UserService("users.db")
    
    # Create tables - sql executed directly with string formatting
    service.connection.execute(f"""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT,
        password TEXT,  # Password stored in plaintext
        email TEXT
    )
    """)
    
    # Create a user
    service.create_user("admin", "password123", "admin@example.com")
    
    # Random number generation that's not cryptographically secure
    token = random.randint(10000, 99999)
    print(f"Generated token: {token}")
    
    # Example of calculating 30th Fibonacci number - will be very slow
    # fib = service.fibonacci(30)
    
    # Unused variable
    x = 10
    
    # Memory leak - connection not closed
    # service.close()
