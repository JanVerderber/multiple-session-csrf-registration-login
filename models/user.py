import bleach
import bcrypt
from database import db

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

