import bcrypt
from flask import request, render_template, redirect, url_for, make_response
from models.user import User
from models.session import Session


def login(**params):
    if request.method == "GET":
        params["info_message"] = request.args.get("info_message")
        token = request.cookies.get('my-simple-app-session')
        success, user, message = Session.verify_session(token)

        if success:
            params["current_user"] = user
            return render_template("public/auth/logged_in.html", **params)
        else:
            return render_template('public/main/index.html', **params)

    elif request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        if email and password:
            # checks if user with this username and password exists
            user = User.query.filter_by(email=email).first()

            if user.verification_code != "":
                message = "Please verify your e-mail, we've sent you instructions."
                params["danger_message"] = message
                return render_template("public/main/index.html", **params)

            if user and bcrypt.checkpw(password.encode("utf-8"), user.password.encode("utf-8")):
                token = Session.generate_session(user)

                response = make_response(redirect(url_for("admin.users.users_list")))
                response.set_cookie('my-simple-app-session', token)

                return response
            else:
                message = "You entered wrong e-mail or password."
                params["danger_message"] = message
                return render_template("public/main/index.html", **params)
