import bleach
import secrets
import datetime
import hashlib
import bcrypt
from database import db


class User(db.Model):
    __tablename__ = 'user'
    user_id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String())
    verification_code = db.Column(db.String())
    verification_code_expiration = db.Column(db.DateTime)
    password = db.Column(db.String())
    csrf_token = db.Column(db.String())

    sessions = db.relationship('Session', backref='user_session')
    csrf_tokens = db.relationship('CSRFToken', backref='user_csrf_tokens')

    @classmethod
    def create(cls, email, password):
        # sanitize email
        email = bleach.clean(email, strip=True)

        # checks if user with this email already exists
        user = cls.query.filter_by(email=email).first()

        if not user:  # if user does not yet exist, create one
            if password:
                # use bcrypt to hash the password
                hashed = bcrypt.hashpw(password.encode('utf8'), bcrypt.gensalt())
                password_hash = hashed.decode('utf8')

                user = cls(email=email, password=password_hash)
                db.session.add(user)
                db.session.commit()

                return True, user, "Success"  # success, user, message
        else:
            return False, user, "User with this email address is already registered. Please go to the " \
                            "Login page and try to log in."

    @classmethod
    def send_verification_code(cls, user):
        if user:
            # generate verification code
            code = secrets.token_hex()

            # store it in user
            user.verification_code = hashlib.sha256(str.encode(code)).hexdigest()
            user.verification_code_expiration = datetime.datetime.now() + datetime.timedelta(hours=1)
            db.session.add(user)
            db.session.commit()

            print("__________________________________________________________________________________________________")
            print("Thank you for registering at our web app! Please verify your e-mail by clicking on the link below:")
            print("http://127.0.0.1:5000/email-verification/" + code)
            print("__________________________________________________________________________________________________")

            return True

    @classmethod
    def verify_verification_code(cls, code):
        if code:
            # verify verification code
            code_hash = hashlib.sha256(str.encode(code)).hexdigest()

            user = cls.query.filter_by(verification_code=code_hash).first()

            if not user:
                return False, "That verification code is not valid."

            if user.verification_code_expiration > datetime.datetime.now():
                user.verification_code = ""
                user.verification_code_expiration = datetime.datetime.min
                db.session.add(user)
                db.session.commit()

                print("_________________________________________________________________________________")
                print("Your e-mail has been confirmed! Thank you, you can now login with the link below:")
                print("http://127.0.0.1:5000/")
                print("_________________________________________________________________________________")

                return True, "Success"
            else:
                return False, "That verification code is not valid."

    @classmethod
    def update_password(cls, email, new_password):
        if email and new_password:
            # use bcrypt to hash the new password
            hashed = bcrypt.hashpw(new_password.encode('utf8'), bcrypt.gensalt())
            password_hash = hashed.decode('utf8')
            cls.query.filter_by(email=email).update(dict(password=password_hash))
            db.session.commit()

            return True, "Successfully changed password"
        else:
            return False, "Unknown error"

    @classmethod
    def get_users(cls):
        users = cls.query.all()

        return users
