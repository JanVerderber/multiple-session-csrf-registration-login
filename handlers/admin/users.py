from models.user import User, Session
from flask import render_template, request

def users_list(**params):
    token = request.cookies.get('my-simple-app-session')
    success, user, message = Session.verify_session(token)

    if success:
        params["current_user"] = user
        params["users"] = User.get_users()
        return render_template("admin/users/users-list.html", **params)
    else:
        params["error_message"] = message
        return render_template("public/auth/error_page.html", **params)

