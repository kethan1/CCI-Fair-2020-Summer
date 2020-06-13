from flask import Flask, render_template, redirect, url_for, request, flash
import requests
import json
import os
import binascii
from werkzeug.utils import secure_filename
from database import Database
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import ssl
import smtplib
import os
from cryptography.fernet import Fernet


def send_email(message, html_display, receiver_email, sender_email="cci.throwaway.summer@gmail.com", text="Error. Your email client does not support HTML (Fancier) emails."):

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


app = Flask(__name__)

app.config["UPLOAD_FOLDER"] = "./files"

receiver_email = "kethan@vegunta.com"


@app.before_first_request
def initialize_database():
    Database.initialize()
    # print(Database.get("users"))
    # Database.delete_docs("users")


user_logged_in = None


def is_human(captcha_response):
    """ Validating recaptcha response from google server
        Returns True captcha test passed for submitted form else returns False.
    """
    secret = os.environ.get('RECAPTCHASECRET')
    payload = {"response": captcha_response, 'secret': secret}
    response = requests.post("https://www.google.com/recaptcha/api/siteverify", payload)
    response_text = json.loads(response.text)
    return response_text["success"]


@app.route("/")
def home():
    global user_logged_in
    return render_template("home.html", logged_in=user_logged_in)


@app.route("/<string:page_name>/")
def render_static(page_name):
    global user_logged_in
    return render_template('%s' % page_name, logged_in=user_logged_in)


@app.route("/sign_out")
def sign_out():
    global user_logged_in
    user_logged_in = None
    app.config['UPLOAD_FOLDER'] = './files'
    return redirect(url_for('home'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    global user_logged_in
    if request.method == 'GET':
        return render_template("login.html", red=False, logged_in=user_logged_in, error='')
    elif request.method == 'POST':
        file = open('key.key', 'rb')
        key = file.read()  # The key will be type bytes
        file.close()

        f = Fernet(key)

        t = [{'username': (f.decrypt(each['username'])).decode(), 'password': (f.decrypt(each['password'])).decode(), 'email': each['email']} for
             each in Database.get("users")]
        username = request.form.get("username")
        password = request.form.get("password")
        if is_human(request.form['g-recaptcha-response']):
            if username in [each['username'] for each in t]:
                if password == [each['password'] for each in t if username == each['username']][0]:
                    user_logged_in = [username, password]
                    app.config['UPLOAD_FOLDER'] = os.path.join('./files/', user_logged_in[0])
                    return render_static("success_login.html")
                else:
                    return render_template("login.html", red=False, logged_in=user_logged_in, error='Incorrect Password')
            else:
                return render_template("login.html", red=False, logged_in=user_logged_in, error='Username Does Not Exist')
        else:
            return render_template("login.html", logged_in=user_logged_in, red=True, error='')


@app.route('/sign_up', methods=['GET', 'POST'])
def sign_up():
    global user_logged_in
    if request.method == 'GET':
        return render_template("sign_up.html", red=False, logged_in=user_logged_in, error='')
    elif request.method == 'POST':

        file = open('key.key', 'rb')
        key = file.read()  # The key will be type bytes
        file.close()

        f = Fernet(key)

        if is_human(request.form['g-recaptcha-response']):

            t = [{'users': ((f.decrypt(each['username'])).decode()), 'password':((f.decrypt(each['password'])).decode())} for each in Database.get("users")]

            username = request.form.get('username')
            password = request.form.get('password')
            confirm_password = request.form.get('confirm_password')
            email = request.form.get('email')

            if username not in [each['users'] for each in t]:
                if password == confirm_password:
                    Database.insert_record({'username': f.encrypt((username.encode())), 'password': f.encrypt((password.encode())), 'email': email.lower()}, "users")
                    user_logged_in = [username, password]
                    try:
                        os.mkdir(os.path.join('./files', username))
                    except:
                        pass
                    app.config['UPLOAD_FOLDER'] = os.path.join('./files/', username)
                    return render_static("success_sign_up.html")
                else:
                    return render_template("sign_up.html", red=False, logged_in=user_logged_in, error='Password Does Not Match Confirm Password')
            else:
                return render_template("sign_up.html", red=False, logged_in=user_logged_in, error='Username Already Exists')
        else:
            return render_template("sign_up.html", red=True, error='')


@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    global user_logged_in
    if request.method == 'GET':
        return render_template('email_sending.html', red=False, logged_in=user_logged_in)
    elif request.method == 'POST':
        if is_human(request.form['g-recaptcha-response']):
            username = request.form.get('username')
            email = request.form.get('email')

            file = open('key.key', 'rb')
            key = file.read()  # The key will be type bytes
            file.close()

            f = Fernet(key)

            t = [[(f.decrypt(each['username'])).decode(), each['email'], (f.decrypt(each['password'])).decode()] for each in Database.get('users')]

            for each in t:
                if each[0] == username and each[1] == email.lower():

                    message = MIMEMultipart("alternative")
                    message["Subject"] = "Password Reset for Kethan's CCI Fair Project 2020 Summer"
                    message["From"] = "cci.throwaway.summer@gmail.com"
                    message["To"] = email

                    # Create the plain-text and HTML version of your message
                    html = """
                    <!DOCTYPE html>
                    <html>
                      <body>
                        <p>Hi,%s
                            <br>
                            <br>
                            Your Password is: %s
                            <br>
                        </p>
                      </body>
                    </html>
                    """ % (username, each[2])

                    send_email(message, html, receiver_email)

                    return render_template('email_sent.html', logged_in=user_logged_in)
                else:
                    return render_template('no_account_matches.html', logged_in=user_logged_in)
        else:
            return render_template('email_sending.html', red=True, logged_in=user_logged_in)


@app.route('/remove_file', methods=['GET', 'POST'])
def remove_file():
    global user_logged_in
    try:
        file_name = request.form['DeleteButton']
        if user_logged_in is not None:
            os.remove(os.path.join('./files', user_logged_in[0], file_name))
            path = os.path.join('./files', user_logged_in[0])
            files = os.listdir(path)
            return render_template("upload_files.html", files=files, path=path, logged_in=user_logged_in)
    except:
        pass


@app.route('/upload_file', methods=['GET', 'POST'])
def upload_file():
    global user_logged_in
    if request.method == 'GET':
        if user_logged_in is None:
            return render_static("please_login_in.html")
        else:
            path = os.path.join('./files', user_logged_in[0])
            files = os.listdir(path)
            return render_template("upload_files.html", files=files, path=path, logged_in=user_logged_in)
    elif request.method == 'POST':
        file = request.files['file']
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        if user_logged_in is not None:
            path = os.path.join('./files', user_logged_in[0])
            files = os.listdir(path)
            return render_template("upload_files.html", files=files, path=path, logged_in=user_logged_in)
        else:
            return render_static("please_login_in.html")


if __name__ == '__main__':
    app.run(debug=True)
