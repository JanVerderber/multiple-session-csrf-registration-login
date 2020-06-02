import bleach
import bcrypt
import hashlib
import secrets
import datetime
from flask_sqlalchemy import SQLAlchemy
from flask import request
from operator import attrgetter

db = SQLAlchemy()

class Session(db.Model):
    __tablename__ = 'session'
    session_id = db.Column(db.Integer, primary_key=True)
    token_hash = db.Column(db.String())
    ip = db.Column(db.String)
    platform = db.Column(db.String())
    browser = db.Column(db.String())
    country = db.Column(db.String())
    user_agent = db.Column(db.String())
    expired = db.Column(db.DateTime)

    user_id = db.Column(db.Integer, db.ForeignKey('user.user_id'))

    @classmethod
    def generate_session(cls, user):
        if user:
            # first, check for expired session tokens
            tokens = cls.query.filter_by(user_session=user).all()

            for token in tokens:
                if token.expired < datetime.datetime.now():
                    db.session.delete(token)

            # generate session token and its hash
            token = secrets.token_hex()
            token_hash = hashlib.sha256(str.encode(token)).hexdigest()

            session = cls(token_hash=token_hash, expired=datetime.datetime.now() + datetime.timedelta(days=30))
            if request:  # this separation is needed for tests which don't have the access to "request" variable
                session.ip = request.access_route[-1]
                session.platform = request.user_agent.platform
                session.browser = request.user_agent.browser
                session.user_agent = request.user_agent.string
                session.country = request.headers.get("X-AppEngine-Country")
                session.user_session = user

                db.session.add(session)
                db.session.commit()

            return token

    @classmethod
    def verify_session(cls, session_token):
        if session_token:
            token_hash = hashlib.sha256(str.encode(session_token)).hexdigest()

            session = cls.query.filter_by(token_hash=token_hash).first()
            user = session.user_session

            if not user:
                return False, None, "A user with this session token does not exist. Try to log in again."

            if session.expired > datetime.datetime.now():
                return True, user, "Success"
            else:
                return False, None, "Your session has expired, please login again."
        else:
            return False, None, "Please login to access this page."

    @classmethod
    def delete_session(cls, session_token):
        if session_token:
            token_hash = hashlib.sha256(str.encode(session_token)).hexdigest()

            session = cls.query.filter_by(token_hash=token_hash).first()

            if session:
                db.session.delete(session)
                db.session.commit()

                return True, "Logged out"
            else:
                return False, "No such session found."

        else:
            return False, "Please login to access this page."

class CSRFToken(db.Model):
    __tablename__ = 'csrf_token'
    csrf_id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String())
    expired = db.Column(db.DateTime)

    user_id = db.Column(db.Integer, db.ForeignKey('user.user_id'))

    @classmethod
    def generate_csrf_token(cls, user):
        # first, check for expired CSRF tokens
        tokens = cls.query.filter_by(user_csrf_tokens=user).all()

        for token in tokens:
            if token.expired < datetime.datetime.now():
                db.session.delete(token)

        # there should be maximum 10 CSRF tokens per user and not more, check and delete oldest one
        if len(tokens) >= 10:
            oldest_token = min(tokens, key=attrgetter("expired"))
            db.session.delete(oldest_token)

        # generate csrf token and save it to CSRF table
        csrf_token = secrets.token_hex()

        csrf = cls(token=csrf_token, expired=datetime.datetime.now() + datetime.timedelta(hours=1), user_csrf_tokens=user)
        db.session.add(csrf)
        db.session.commit()

        return csrf_token

    @classmethod
    def validate_csrf_token(cls, csrf_token):
        if csrf_token:
            # validate CSRF token from form
            csrf_success = cls.query.filter_by(token=csrf_token).first()

            if csrf_success:
                return True
            else:
                return False
        else:
            return False

class User(db.Model):
    __tablename__ = 'user'
    user_id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50))
    password = db.Column(db.String(50))
    csrf_token = db.Column(db.String())

    sessions = db.relationship('Session', backref='user_session')
    csrf_tokens = db.relationship('CSRFToken', backref='user_csrf_tokens')

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
    def get_users(cls):
        users = cls.query.all()

        return users

