import bcrypt
from flask import request, render_template, redirect, url_for, make_response
from models.user import User

def login(**params):
    if request.method == "GET":
        token = request.cookies.get('my-simple-app-session')
        success, user, message = User.verify_session(token)

        if success:
            return render_template("public/auth/logged_in.html", **params)
        else:
            return render_template('public/main/index.html', **params)

    elif request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        if username and password:
            # checks if user with this username and password exists
            user = User.query.filter_by(username=username).first()

            if user and bcrypt.checkpw(password.encode("utf-8"), user.password.encode("utf-8")):
                token = User.generate_session(username)

                response = make_response(redirect(url_for("admin.users.users_list")))
                response.set_cookie('my-simple-app-session', token)

                return response
            else:
                return redirect(url_for("public.auth.registration"))
