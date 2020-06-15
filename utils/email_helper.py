from utils.environment import is_local


def send_email(recipient_email, email_params):
    # send web app URL data by default to every email template
    if is_local():
        print(email_params["message"])
    else:
        pass
        # will add SendGrid system for sending e-mails
