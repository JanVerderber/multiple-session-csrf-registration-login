from flask import Flask
from database import db
from handlers.admin import users
from handlers.profile.auth import logout, change_password
from handlers.public import main as public_main, auth

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app_database.db'
db.init_app(app)

with app.app_context():
    db.create_all()

# PUBLIC URLS

# HOME PAGE (LOGIN)
app.add_url_rule(rule="/", endpoint="public.main.login", view_func=public_main.login, methods=["GET", "POST"])

# REGISTRATION
app.add_url_rule(rule="/registration", endpoint="public.auth.registration", view_func=auth.registration, methods=["GET", "POST"])


# PRIVATE URLS

# USERS LIST (NEEDS TO BE LOGGED IN)
app.add_url_rule(rule="/admin/users", endpoint="admin.users.users_list", view_func=users.users_list,
                 methods=["GET"])

# LOG OUT

app.add_url_rule(rule="/logout", endpoint="profile.auth.logout", view_func=logout, methods=["POST"])

# CHANGE USER PASSWORD

app.add_url_rule(rule="/change-password", endpoint="profile.auth.change_password", view_func=change_password, methods=["GET", "POST"])


# FOR RUNNING THE APP

if __name__ == '__main__':
    app.run(debug=True)