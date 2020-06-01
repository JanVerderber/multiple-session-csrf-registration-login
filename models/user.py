import bleach
import bcrypt
import hashlib
import secrets
import datetime
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class Session(db.Model):
    token_hash = db.Column(db.String())
    ip = db.Column(db.String())
    platform = db.Column(db.String())
    browser = db.Column(db.String())
    country = db.Column(db.String())
    user_agent = db.Column(db.String())
    expired = db.Column(db.String())

class CSRFToken(db.Model):
    token = db.Column(db.String())
    expired = db.Column(db.DateTime)

class User(db.Model):
    __tablename__ = 'user'
    user_id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50))
    password = db.Column(db.String(50))
    session_token_hash = db.Column(db.String())
    session_expiration_date = db.Column(db.DateTime)
    csrf_token = db.Column(db.String())

    @classmethod
    def create(cls, username, password):
        # sanitize username
        username = bleach.clean(username, strip=True)

        # checks if user with this username already exists
        user = cls.query.filter_by(username=username).first()

        if not user:  # if user does not yet exist, create one
            if password:
                # use bcrypt to hash the password
                hashed = bcrypt.hashpw(password.encode('utf8'), bcrypt.gensalt())
                password_hash = hashed.decode('utf8')

                user = cls(username=username, password=password_hash)
                db.session.add(user)
                db.session.commit()

                return True, user, "Success"  # success, user, message
        else:
            return False, user, "User with this email address is already registered. Please go to the " \
                            "Login page and try to log in."

    @classmethod
    def generate_session(cls, username):
        # generate session token and its hash
        token = secrets.token_hex()
        token_hash = hashlib.sha256(str.encode(token)).hexdigest()

        cls.query.filter_by(username=username).update(dict(session_token_hash=token_hash, session_expiration_date=datetime.datetime.now() + datetime.timedelta(days=30)))
        db.session.commit()

        return token

    @classmethod
    def verify_session(cls, session_token):
        if session_token:
            token_hash = hashlib.sha256(str.encode(session_token)).hexdigest()

            user = cls.query.filter_by(session_token_hash=token_hash).first()

            if not user:
                return False, None, "A user with this session token does not exist. Try to log in again."

            if user.session_expiration_date > datetime.datetime.now():
                return True, user, "Success"
            else:
                return False, None, "Your session has expired, please login again."
        else:
            return False, None, "Please login to access this page."

    @classmethod
    def delete_session(cls, session_token):
        if session_token:
            token_hash = hashlib.sha256(str.encode(session_token)).hexdigest()

            cls.query.filter_by(session_token_hash=token_hash).update(dict(session_token_hash="", session_expiration_date=datetime.datetime(1, 1, 1)))
            db.session.commit()

            return True, "Logged out"

        else:
            return False, "Please login to access this page."

    @classmethod
    def update_password(cls, username, new_password):
        if username and new_password:
            # use bcrypt to hash the new password
            hashed = bcrypt.hashpw(new_password.encode('utf8'), bcrypt.gensalt())
            password_hash = hashed.decode('utf8')
            cls.query.filter_by(username=username).update(dict(password=password_hash))
            db.session.commit()

            return True, "Successfully changed password"
        else:
            return False, "Unknown error"

    @classmethod
    def generate_csrf_token(cls, username):
        # generate csrf token and save it to User
        csrf_token = secrets.token_hex()

        cls.query.filter_by(username=username).update(dict(csrf_token=csrf_token))
        db.session.commit()

        return csrf_token

    @classmethod
    def validate_csrf_token(cls, username, csrf_token):
        if username and csrf_token:
            # validate CSRF token from form
            user = cls.query.filter_by(username=username, csrf_token=csrf_token).first()

            if user:
                return True
            else:
                return False
        else:
            return False

    @classmethod
    def get_users(cls):
        users = cls.query.all()

        return users

