import hashlib
import secrets
import datetime
from database import db
from flask import request

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