import os
import sqlite3
import hashlib
import random
import string
from datetime import datetime, timedelta
from flask_login import UserMixin
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import logging
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class User(UserMixin):
    def __init__(self, user_id, email, name, is_admin=False):
        self.id = user_id
        self.email = email
        self.name = name
        self.is_admin = is_admin

class AuthManager:
    def __init__(self):
        self.setup_database()
        self.otp_storage = {}
        self.setup_smtp_config()
        self.setup_admin_accounts()   

    def setup_admin_accounts(self):
        
        try:
            conn = sqlite3.connect('rfid_users.db')
            cursor = conn.cursor()

            
            cursor.execute('''
                PRAGMA table_info(users)
            ''')
            columns = [column[1] for column in cursor.fetchall()]

            if 'is_admin' not in columns:
                cursor.execute('''
                    ALTER TABLE users ADD COLUMN is_admin INTEGER DEFAULT 0
                ''')
                conn.commit()

           
            admin_accounts = [
                {
                    'name': 'Admin',
                    'email': 'admin@gmail.com',
                    'password': 'Admin@2024',  
                    'is_admin': 1
                },
                {
                    'name': 'Arya Jayan',
                    'email': 'aryajayan55@gmail.com',
                    'password': 'AryaAdmin@2024',  
                    'is_admin': 1
                }
            ]

            for admin in admin_accounts:
               
                cursor.execute('SELECT id FROM users WHERE email = ?', (admin['email'],))
                existing = cursor.fetchone()

                if not existing:
                    
                    password_hash = hashlib.sha256(admin['password'].encode()).hexdigest()
                    cursor.execute('''
                        INSERT INTO users (name, email, password_hash, created_at, is_verified, is_admin)
                        VALUES (?, ?, ?, ?, 1, ?)
                    ''', (admin['name'], admin['email'], password_hash,
                          datetime.now().isoformat(), admin['is_admin']))
                    logger.info(f"Admin account created for {admin['email']}")
                else:
                    
                    cursor.execute('''
                        UPDATE users SET is_admin = ? WHERE email = ?
                    ''', (admin['is_admin'], admin['email']))
                    logger.info(f"Updated {admin['email']} to admin status")

            conn.commit()
            conn.close()

            logger.info("Admin accounts setup completed")

        except Exception as e:
            logger.error(f"Error setting up admin accounts: {e}")

    def setup_smtp_config(self):
        """Setup SMTP configuration from environment variables"""
        self.smtp_config = {
            'server': os.getenv('SMTP_SERVER', 'smtp.gmail.com'),
            'port': int(os.getenv('SMTP_PORT', '587')),
            'use_tls': os.getenv('SMTP_USE_TLS', 'True').lower() == 'true',
            'email': os.getenv('EMAIL_USER'),
            'password': os.getenv('EMAIL_PASSWORD')
        }

        if not self.smtp_config['email'] or not self.smtp_config['password']:
            logger.warning("SMTP credentials not configured properly in .env file")
        else:
            logger.info(f"SMTP configured for: {self.smtp_config['server']}:{self.smtp_config['port']}")

    def setup_database(self):
        
        conn = sqlite3.connect('rfid_users.db')
        cursor = conn.cursor()

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TEXT,
                last_login TEXT,
                is_verified INTEGER DEFAULT 0,
                is_admin INTEGER DEFAULT 0
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS user_scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                scan_id INTEGER,
                timestamp TEXT,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')

        conn.commit()
        conn.close()
        logger.info("Database initialized successfully")

    def generate_otp(self):
       
        return ''.join(random.choices(string.digits, k=6))

    def send_otp_email(self, email, otp):
        
        try:
            if not self.smtp_config['email'] or not self.smtp_config['password']:
                logger.error("Email credentials not configured in .env file")
                print(f"\n{'='*50}")
                print(f"TEST MODE - OTP for {email}: {otp}")
                print(f"{'='*50}\n")
                return True

            msg = MIMEMultipart('alternative')
            msg['From'] = self.smtp_config['email']
            msg['To'] = email
            msg['Subject'] = 'RFID Security Scanner - Email Verification'

            html_body = f"""
            <html>
              <head></head>
              <body style="font-family: Arial, sans-serif; padding: 20px; background-color: #f4f4f4;">
                <div style="max-width: 600px; margin: 0 auto; background-color: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
                  <h2 style="color: #2563eb; text-align: center;">RFID Security Scanner</h2>
                  <h3 style="color: #333; text-align: center;">Email Verification</h3>

                  <div style="background-color: #f0f9ff; border: 2px solid #2563eb; border-radius: 8px; padding: 20px; margin: 20px 0; text-align: center;">
                    <p style="font-size: 16px; color: #333; margin: 10px 0;">Your verification code is:</p>
                    <h1 style="color: #2563eb; font-size: 36px; letter-spacing: 8px; margin: 20px 0;">{otp}</h1>
                  </div>

                  <p style="color: #666; text-align: center; margin: 20px 0;">
                    This code will expire in <strong>10 minutes</strong>.
                  </p>

                  <div style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #e5e7eb;">
                    <p style="color: #999; font-size: 12px; text-align: center;">
                      If you didn't request this verification code, please ignore this email.
                    </p>
                    <p style="color: #999; font-size: 12px; text-align: center;">
                      RFID Security Scanner <br>
                    </p>
                  </div>
                </div>
              </body>
            </html>
            """

            text_body = f"""
            RFID Security Scanner - Email Verification

            Your verification code is: {otp}

            This code will expire in 10 minutes.

            If you didn't request this verification code, please ignore this email.

            RFID Security Scanner
            """

            part1 = MIMEText(text_body, 'plain')
            part2 = MIMEText(html_body, 'html')
            msg.attach(part1)
            msg.attach(part2)

            logger.info(f"Connecting to {self.smtp_config['server']}:{self.smtp_config['port']}")

            if self.smtp_config['use_tls']:
                server = smtplib.SMTP(self.smtp_config['server'], self.smtp_config['port'])
                server.starttls()
            else:
                server = smtplib.SMTP_SSL(self.smtp_config['server'], self.smtp_config['port'])

            server.login(self.smtp_config['email'], self.smtp_config['password'])
            server.send_message(msg)
            server.quit()

            logger.info(f"OTP email sent successfully to {email}")
            return True

        except smtplib.SMTPAuthenticationError:
            logger.error("SMTP Authentication failed. Check your email and password.")
            return False

        except smtplib.SMTPException as e:
            logger.error(f"SMTP error: {e}")
            return False

        except Exception as e:
            logger.error(f"Failed to send OTP email: {e}")
            print(f"\n{'='*50}")
            print(f"EMAIL ERROR - Manual OTP for {email}: {otp}")
            print(f"Error: {e}")
            print(f"{'='*50}\n")
            return True

    def register_user(self, name, email, password):
        
        try:
            conn = sqlite3.connect('rfid_users.db')
            cursor = conn.cursor()
            cursor.execute('SELECT id FROM users WHERE email = ?', (email,))
            if cursor.fetchone():
                conn.close()
                return {'success': False, 'message': 'Email already registered'}
            conn.close()

            otp = self.generate_otp()

            self.otp_storage[email] = {
                'otp': otp,
                'expires': datetime.now() + timedelta(minutes=10),
                'name': name,
                'password': hashlib.sha256(password.encode()).hexdigest()
            }

            logger.info(f"Generated OTP for {email}: {otp}")

            if self.send_otp_email(email, otp):
                return {'success': True, 'message': 'OTP sent to your email'}
            else:
                return {'success': False, 'message': 'Failed to send OTP. Check email configuration.'}

        except Exception as e:
            logger.error(f"Registration error: {e}")
            return {'success': False, 'message': str(e)}

    def verify_otp_and_create_user(self, email, otp):
       
        if email not in self.otp_storage:
            return {'success': False, 'message': 'No OTP request found. Please register again.'}

        stored_data = self.otp_storage[email]

        if datetime.now() > stored_data['expires']:
            del self.otp_storage[email]
            return {'success': False, 'message': 'OTP expired. Please register again.'}

        if stored_data['otp'] != otp:
            return {'success': False, 'message': 'Invalid OTP. Please check and try again.'}

        try:
            conn = sqlite3.connect('rfid_users.db')
            cursor = conn.cursor()

           
            cursor.execute('''
                INSERT INTO users (name, email, password_hash, created_at, is_verified, is_admin)
                VALUES (?, ?, ?, ?, 1, 0)
            ''', (stored_data['name'], email, stored_data['password'],
                  datetime.now().isoformat()))

            conn.commit()
            user_id = cursor.lastrowid
            conn.close()

            del self.otp_storage[email]

            logger.info(f"User account created successfully for {email}")

            return {
                'success': True,
                'message': 'Account created successfully',
                'user_id': user_id
            }

        except sqlite3.IntegrityError:
            return {'success': False, 'message': 'Email already registered'}
        except Exception as e:
            logger.error(f"Error creating user: {e}")
            return {'success': False, 'message': str(e)}

    def login_user(self, email, password):
        
        try:
            conn = sqlite3.connect('rfid_users.db')
            cursor = conn.cursor()

            cursor.execute('''
                SELECT id, name, password_hash, is_admin FROM users
                WHERE email = ? AND is_verified = 1
            ''', (email,))

            user = cursor.fetchone()

            if not user:
                return {'success': False, 'message': 'Invalid email or password'}

            
            password_hash = hashlib.sha256(password.encode()).hexdigest()
            if password_hash != user[2]:
                return {'success': False, 'message': 'Invalid email or password'}

           
            cursor.execute('''
                UPDATE users SET last_login = ? WHERE id = ?
            ''', (datetime.now().isoformat(), user[0]))

            conn.commit()
            conn.close()

            logger.info(f"User {email} logged in successfully (Admin: {bool(user[3])})")

            return {
                'success': True,
                'user': User(user[0], email, user[1], bool(user[3]))
            }

        except Exception as e:
            logger.error(f"Login error: {e}")
            return {'success': False, 'message': 'Login failed. Please try again.'}

    def get_user_by_id(self, user_id):
       
        try:
            conn = sqlite3.connect('rfid_users.db')
            cursor = conn.cursor()

            cursor.execute('''
                SELECT id, email, name, is_admin FROM users WHERE id = ?
            ''', (user_id,))

            user = cursor.fetchone()
            conn.close()

            if user:
                return User(user[0], user[1], user[2], bool(user[3]))
            return None

        except Exception as e:
            logger.error(f"Error getting user: {e}")
            return None

    def link_scan_to_user(self, user_id, scan_id):
       
        try:
            conn = sqlite3.connect('rfid_users.db')
            cursor = conn.cursor()

            cursor.execute('''
                INSERT INTO user_scans (user_id, scan_id, timestamp)
                VALUES (?, ?, ?)
            ''', (user_id, scan_id, datetime.now().isoformat()))

            conn.commit()
            conn.close()
            return True

        except Exception as e:
            logger.error(f"Error linking scan to user: {e}")
            return False

    def get_user_scans(self, user_id):
        
        try:
            conn = sqlite3.connect('rfid_users.db')
            cursor = conn.cursor()

            cursor.execute('''
                SELECT scan_id FROM user_scans WHERE user_id = ?
                ORDER BY timestamp DESC
            ''', (user_id,))

            scan_ids = [row[0] for row in cursor.fetchall()]
            conn.close()

            return scan_ids

        except Exception as e:
            logger.error(f"Error getting user scans: {e}")
            return []

auth_manager = AuthManager()