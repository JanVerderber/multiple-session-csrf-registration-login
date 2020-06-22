import bleach
import secrets
import datetime
import hashlib
import bcrypt
from database import db
from flask import request
from utils.email_helper import send_email


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

            url = request.url_root
            complete_url = url + "email-verification/" + code

            message_title = "Verify e-mail address - Moderately simple registration login"

            message_body = "Thank you for registering at our web app! Please verify your e-mail by clicking on the " \
                           "link below:\n" \
                           + complete_url + "\n"

            message_html = "<p>Thank you for registering at our web app! Please verify your e-mail by clicking on the" \
                           "link below:<br> " \
                           + "<a href='" + complete_url + "' target='_blank'>" + complete_url + "</a></p>"

            send_email(email_params={"recipient_email": user.email, "message_title": message_title,
                                     "message_body": message_body, "message_html": message_html})

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

                url = request.url_root

                message_title = "E-mail address confirmed - Moderately simple registration login"

                message_body = "Your e-mail has been confirmed! Thank you, you can now login with the link below:\n" \
                               + url + "\n"

                message_html = "<p>Your e-mail has been confirmed! Thank you, you can now login with the link below:" \
                               "<br><a href='" + url + "' target='_blank'>" + url + "</a></p>"

                send_email(email_params={"recipient_email": user.email, "message_title": message_title,
                                         "message_body": message_body, "message_html": message_html})

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
