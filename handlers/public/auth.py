from flask import request, render_template

from models.user import User

def registration(**params):
    if request.method == "GET":
        token = request.cookies.get('my-simple-app-session')
        success, user, message = User.verify_session(token)

        if success:
            return render_template("public/auth/logged_in.html", **params)
        else:
            return render_template("public/auth/registration.html", **params)

    elif request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        if username and password:
            success, user, message = User.create(username=username, password=password)

            if success:
                return render_template("public/auth/registration_success.html", **params)
            else:
                params["error_message"] = message
                return render_template("public/auth/error_page.html", **params)
