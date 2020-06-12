import os
import smtplib
import ssl
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

receiver_email = "kethan@vegunta.com"

message = MIMEMultipart("alternative")
message["Subject"] = "Password Reset for Kethan's CCI Fair Project 2020 Summer"
message["From"] = sender_email
message["To"] = receiver_email

# Create the plain-text and HTML version of your message
file = open("./templates/forgot_password_error.html", "r")
html = file.read()
file.close()


def send_email(html_display, receiver_email, sender_email="cci.throwaway.summer@gmail.com", text="Error. Your email client does not support HTML (Fancier) emails."):

    # Add HTML/plain-text parts to MIMEMultipart message
    # The email client will try to render the last part first
    message.attach(MIMEText(text, "plain"))
    message.attach(MIMEText(html_display, "html"))

    # Create secure connection with server and send email
    context = ssl.create_default_context()
    with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context) as server:
        server.login(sender_email, os.environ.get('Password'))
        server.sendmail(
            sender_email, receiver_email, message.as_string()
        )


send_email(html, receiver_email)
