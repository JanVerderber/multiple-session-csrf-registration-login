import secrets
import datetime
from database import db
from operator import attrgetter


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
