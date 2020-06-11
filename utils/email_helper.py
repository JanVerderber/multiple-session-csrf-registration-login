from utils.environment import is_local


def send_email(recipient_email, email_params):
    # send web app URL data by default to every email template
    if is_local():
        print("__________________________________________________________________________________________________")
        print("Thank you for registering at our web app! Please verify your e-mail by clicking on the link below:")
        print("http://localhost:8080/email-verification/" + email_params["verification_code"])
        print("__________________________________________________________________________________________________")
    else:
        pass
        # will add SendGrid system for sending e-mails
