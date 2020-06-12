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


def str2num(string):
    return int(binascii.hexlify(string.encode("utf-8")), 16)


def num2str(number):
    return binascii.unhexlify(format(number, "x").encode("utf-8")).decode("utf-8")


app = Flask(__name__)

app.config["UPLOAD_FOLDER"] = "./files"

receiver_email = "kethan@vegunta.com"


@app.before_first_request
def initialize_database():
    Database.initialize()
    print(Database.get("users"))
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
    return render_template('%s' % page_name)


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
        return render_template("login.html")
    elif request.method == 'POST':
        t = [{'username': num2str(each['username']), 'password': num2str(each['password']), 'email': each['email']} for
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
                    return render_static("incorrect_password.html")
            else:
                return render_static("username_does_not_exist.html")
        else:
            return render_static("bot.html")


@app.route('/sign_up', methods=['GET', 'POST'])
def sign_up():
    global user_logged_in
    if request.method == 'GET':
        return render_template("sign_up.html")
    elif request.method == 'POST':
        if is_human(request.form['g-recaptcha-response']):

            t = {key2: value2 for each in Database.get("users") for key2, value2 in each.items() if key2 != '_id'}
            print(t)
            username = str2num(request.form.get('username'))
            password = str2num(request.form.get('password'))
            confirm_password = str2num(request.form.get('confirm_password'))
            email = request.form.get('email')

            if username not in t.keys():
                if password == confirm_password:
                    Database.insert_record({'username': username, 'password': password, 'email': email}, "users")
                    user_logged_in = [num2str(username), password]
                    try:
                        os.mkdir(os.path.join('./files', num2str(username)))
                    except:
                        pass
                    app.config['UPLOAD_FOLDER'] = os.path.join('./files/', num2str(username))
                    return render_static("success_sign_up.html")
                else:
                    return render_static("password_not_match_confirm_password.html")
            else:
                return render_static("username_already_exists.html")
        else:
            return render_static("bot.html")


@app.route('/remove_file', methods=['GET', 'POST'])
def remove_file():
    file_name=request.form['DeleteButton']
    if user_logged_in is not None:
        print('removing file...')
        os.remove(os.path.join('./files', user_logged_in[0], file_name))
        path = os.path.join('./files', user_logged_in[0])
        files = os.listdir(path)
        return render_template("upload_files.html", files=files, path=path)


@app.route('/upload_file', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'GET':
        if user_logged_in is None:
            return render_static("please_login_in.html")
        else:
            path = os.path.join('./files', user_logged_in[0])
            files = os.listdir(path)
            return render_template("upload_files.html", files=files, path=path)
    elif request.method == 'POST':
        file = request.files['file']
        filename = secure_filename(file.filename)
        print(app.config['UPLOAD_FOLDER'], filename)
        print(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        if user_logged_in is not None:
            path = os.path.join('./files', user_logged_in[0])
            files = os.listdir(path)
            return render_template("upload_files.html", files=files, path=path)
        else:
            return render_static("please_login_in.html")


if __name__ == '__main__':
    app.run(debug=True)
