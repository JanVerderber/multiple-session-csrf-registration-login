import bcrypt
from flask import request, make_response, redirect, url_for, render_template
from models.user import User
from models.session import Session
from models.csrf import CSRFToken


def logout(**params):
    # logout should accept POST only (don't do logout via GET, to avoid pre-fetching issues in browsers)
    if request.method == "POST":
        # get the session token from the cookie
        token = request.cookies.get('my-simple-app-session')

        # delete the session token from the User object
        success, message = Session.delete_session(token)

        if success:
            # prepare the response
            response = make_response(redirect(url_for("public.main.login")))

            # remove session cookie
            response.set_cookie('my-simple-app-session', '', expires=0)

            return response
        else:
            params["error_message"] = message
            return render_template("public/auth/error_page.html", **params)


def change_password(**params):
    if request.method == "GET":
        token = request.cookies.get('my-simple-app-session')
        success, user, message = Session.verify_session(token)

        csrf_token = CSRFToken.generate_csrf_token(user)

        if success and csrf_token:
            params["current_user"] = user
            params["csrf_token"] = csrf_token
            return render_template("public/auth/change_password.html", **params)
        else:
            params["error_message"] = message
            return render_template("public/auth/error_page.html", **params)

    elif request.method == "POST":
        token = request.cookies.get('my-simple-app-session')
        success, user, message = Session.verify_session(token)

        current_email = user.email
        current_password = request.form.get("current_password")
        new_password = request.form.get("new_password")
        form_csrf_token = request.form.get("csrf_token")
        csrf_validation_success = CSRFToken.validate_csrf_token(form_csrf_token)

        if current_email and current_password and new_password and csrf_validation_success:
            # checks if user with this e-mail and password exists
            user = User.query.filter_by(email=current_email).first()

            if user and bcrypt.checkpw(current_password.encode("utf-8"), user.password.encode("utf-8")):
                success, message = User.update_password(current_email, new_password)

                if success:
                    # if password was changed, logout the user so he has to login again
                    # prepare the response
                    message = "Your password has been changed, please login again."
                    response = redirect(url_for("public.main.login", info_message=message))

                    # remove session cookie
                    response.set_cookie('my-simple-app-session', '', expires=0)

                    return response
                else:
                    params["error_message"] = message
                    return render_template("public/auth/error_page.html", **params)
            else:
                params["error_message"] = "You entered the wrong old password, please try again."
                return render_template("public/auth/error_page.html", **params)
