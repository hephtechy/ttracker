import secrets
from dotenv import load_dotenv
import os
from flask import Blueprint, render_template, request, flash, redirect, url_for
from .models import User, Attendance, Report
from . import db, bcrypt
from flask_login import login_user, login_required, logout_user, current_user
import pytz
from datetime import datetime, timezone, timedelta
from threading import Timer
from twilio.rest import Client
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail


load_dotenv()

auth = Blueprint('auth', __name__)

token_onpremise = secrets.token_hex(4)
token_remote = secrets.token_hex(4)

def current_time():
    dateNtime = datetime.now(pytz.utc)
    minute = list(str(dateNtime.minute))
    if len(minute) == 1:
        hour, minute = str(dateNtime.hour+1), list(str(dateNtime.minute))
        new_minute = []
        new_minute.append(0)
        new_minute.append(int(minute[0]))
        minute = str(new_minute[0]) + str(new_minute[1])
        current_time = str(hour) + ":" + minute
    else:
        hour, minute = str(dateNtime.hour+1), str(dateNtime.minute)
        current_time = hour + ":" + minute
    return current_time

def chat_HR(user, user_location, admins=['whatsapp:+2347037006829']):
    account_sid = os.environ.get("ACCOUNT_SID")
    auth_token = os.environ.get("AUTH_TOKEN")
    client = Client(account_sid, auth_token)
    for admin in admins:
        if user.sign_in_status == True:
            message = client.messages.create(
            from_='whatsapp:+14155238886',
            body="Good day HR Mgr \n{} {} just signed in {}!!!".format(user.first_name, user.last_name, user_location),
            to=admin
            )
        if user.sign_in_status == False:
            message = client.messages.create(
             from_='whatsapp:+14155238886',
             body="Good day HR Mgr \n{} {} just signed out!!!".format(user.first_name, user.last_name),
             to=admin
             )
        return "HR chatted!!!"

def sendGridMail(recipients, title, body):
    message = Mail(
                from_email='emmanueloyekanmi@student.oauife.edu.ng',
                to_emails=recipients,
                subject=title,
                html_content=body)
    try:
        sg = SendGridAPIClient(os.environ.get("MAIL_TOKEN"))
        response = sg.send(message)
        print(response.status_code)
        print(response.body)
        print(response.headers)
    except Exception as e:
        print(str(e))

def send_token(admins=['whatsapp:+2347037006829']):
    account_sid = os.environ.get("ACCOUNT_SID")
    auth_token = os.environ.get("AUTH_TOKEN")
    client = Client(account_sid, auth_token)
    for admin in admins:
        message = client.messages.create(
            from_='whatsapp:+14155238886',
            body="Good day HR Mgr \nToday\'s login_token for remote staffs: {}\
            \nToday\'s login_token for on-premise staffs: {}".format(token_onpremise, token_remote),
            to=admin
        )

# Global variable to track if the sendtoken functions have been executed today
last_send_token_date = None

@auth.before_request
def post_tokens():
    global last_send_token_date

    # Check if the code has been executed today
    today = datetime.now().date()

    # Check if send_token has already been executed
    if last_send_token_date != today:
        send_token()
        sendGridMail(
        ['emanueloyekanmi@gmail.com', 'hephman320@gmail.com'],
        'TODAY\'S LOGIN TOKEN',
        "Good day HR Mgr \nToday\'s login_token for remote staffs: {}\
        \nToday\'s login_token for on-premise staffs: {}".format(token_onpremise, token_remote)
        )

        # Update the last_execution_date
        last_send_token_date = today

        # Schedule the next execution for tomorrow
        c = datetime.today()
        d = c.replace(day=c.day, hour=5, minute=0, second=0, microsecond=0) + timedelta(days=1)
        delta_t = d - c
        secs = delta_t.total_seconds()

        # Set timer for the next execution
        args = (['emanueloyekanmi@gmail.com', 'hephman320@gmail.com'],
        'TODAY\'S LOGIN TOKEN',
        "Good day HR Mgr \nToday\'s login_token for remote staffs: {}\
        \nToday\'s login_token for on-premise staffs: {}".format(token_onpremise, token_remote)
        )
        mailing_countdown = Timer(secs, sendGridMail, args)
        whatsapp_countdown = Timer(secs + 1800, send_token)

        mailing_countdown.start()
        whatsapp_countdown.start()

@auth.route('/login', methods=['GET', 'POST'])
def sign_in():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        token = request.form.get('token')

        user = User.query.filter_by(email=email).first()
        if user:
            if bcrypt.check_password_hash(user.password, password):
                if token == token_remote or token == token_onpremise:
                    if token == token_remote:
                        user_location = 'remotely'
                    else:
                        user_location = 'on premise'
                    flash(f'Logged in successfully \'{user_location}\'!', category='success')
                    login_user(user, remember=True)
                    current_date = datetime.utcnow().date()
                    if user.sign_in_status != True and user.date != current_date:
                        user.sign_in_status = True
                        user.date = current_date
                        fullname = user.first_name + " " + user.last_name
                        present_time = current_time()
                        attendance = Attendance(user_id=user.id, report_id=user.id, date=current_date, sign_in_time=present_time)

                        report_text = f'\n{fullname} signed in at {present_time} {user_location}.\n'
                        report = Report(user_id=user.id, sign_in_report=report_text)

                        db.session.add_all([user, attendance, report])
                        db.session.commit()

                        report = Report.query.filter(Report.user_id == user.id, Report.date == current_date).first()
                        if datetime.utcnow().hour > 6 or (datetime.utcnow().hour == 6 and datetime.utcnow().minute > 0):
                            report.punctuality = False
                        else:
                            report.punctuality = True
                        db.session.add(report)
                        db.session.commit()

                        try:
                            # Assuming user and user_location are defined somewhere in your code
                            chat_HR(user, user_location=user_location)

                        except Exception as e:
                            # Handle the exception raised by the function call
                            print(f"An error occurred during HR chat: {str(e)}")

                    users_attendance = Attendance.query.filter_by(date=current_date)

                    return render_template('report.html', users=users_attendance, zip=zip)
                else:
                    flash('Incorrect token try again.', category='error')
            else:
                flash('Incorrect password try again.', category='error')
        else:
            flash('Email does not exist.', category='error')
    return render_template("sign_in.html", user=current_user)

@auth.route('/sign_out', methods=['GET', 'POST'])
@login_required
def sign_out():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        current_date = datetime.utcnow().date()
        user = User.query.filter(User.email == email).first()
        if user:
            if user.sign_in_status == False:
                flash('You have signed out already.', category='error')
            else:
                if bcrypt.check_password_hash(user.password, password):
                    flash('Logged out successfully!', category='success')
                    user.sign_in_status = False
                    db.session.add(user)
                    date = user.date
                    attendance = Attendance.query.filter(Attendance.user_id == user.id, Attendance.date == date).first()
                    sign_out_datetime = datetime.utcnow()
                    attendance.sign_out_datetime = sign_out_datetime
                    attendance.sign_out_time = current_time()
                    db.session.add(attendance)
                    db.session.commit()

                    try:
                        # Assuming user and user_location are defined somewhere in your code
                        chat_HR(user, user_location=user_location)

                    except Exception as e:
                        # Handle the exception raised by the function call
                        print(f"An error occurred during HR chat: {str(e)}")

                    users_attendance = Attendance.query.filter_by(date=current_date)
                    return render_template('report.html', users=users_attendance, zip=zip)
                else:
                    flash('Incorrect password, try again.', category='error')
        else:
            flash('Email does not exist.', category='error')
    return render_template("sign_out.html", user=current_user)


# Global variable to track if the sendGridMail function has executed today
last_execution_date = None

@auth.after_request
def do_reports(response):
    current_date = datetime.utcnow().date()
    reports = Report.query.filter_by(date=current_date)
    attendances_today = Attendance.query.filter_by(date=current_date).all()
    message = f"Good day sir\ma. \n"

    for report in reports:
        user = User.query.get(report.user_id)
        fullname = user.first_name + " " + user.last_name
        for attendance in attendances_today:
            if report.user_id == attendance.user_id:
                if report.punctuality == True:
                    report.default_report = f"{fullname} resumed punctual to work at {attendance.sign_in_time}. \n"
                if report.punctuality == False:
                    report.default_report = f"{fullname} resumed late to work at {attendance.sign_in_time}. \n"
                if report.punctuality == None:
                    report.default_report = f"{fullname} was absent at work today. \n"
                db.session.add(report)
                db.session.commit()
                message += report.default_report

    global last_execution_date

    # Check if the code has been executed today
    today = datetime.now().date()

    if last_execution_date != today:
        # Execute the code if it hasn't been run today
        sendGridMail(['emanueloyekanmi@gmail.com', 'hephman320@gmail.com'],
        f'Daily Attendance Report for {str(today)}',
        body=message)

        # Update the last_execution_date
        last_execution_date = today

        print("Global last_execution_date after reassigning it: ", last_execution_date)

        # Schedule the next execution for tomorrow
        x = datetime.today()
        y = x.replace(day=x.day, hour=20, minute=0, second=0, microsecond=0) + timedelta(days=1)
        delta_t = y - x
        secs = delta_t.total_seconds()

        # Set timer for the next execution
        args = (['emanueloyekanmi@gmail.com', 'hephman320@gmail.com'],
        f'Daily Attendance Report for {str(today)}',
        message)
        t = Timer(secs, sendGridMail, args)
        t.start()

    return response


@auth.route('/sign_up', methods=['GET', 'POST'])
def sign_up():
    if request.method == 'POST':
        email = request.form.get('email')
        first_name = request.form.get('firstName')
        last_name = request.form.get('lastName')
        password1 = request.form.get('password1')
        password2 = request.form['password2']

        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email already exists. Please use another one.', category='error')
        elif len(email) < 4:
            flash('Email must be greater than 3 characters.', category='error')
        elif len(first_name) < 2:
            flash('First name must be greater than 1 character.', category='error')
        elif password1 != password2:
            flash('Passwords don\'t match.', category='error')
        elif len(password1) < 7:
            flash('Password must be at least 7 characters.', category='error')
        else:
            new_user = User(email=email, first_name=first_name, last_name=last_name,
            password=bcrypt.generate_password_hash(password1).decode('utf-8'))

            db.session.add(new_user)
            db.session.commit()
            #login_user(new_user, remember=True)
            flash('Account created!', category='success')
            return redirect(url_for('auth.sign_in'))
    return render_template("sign_up.html")

@auth.route('/t_k_n')
def token():
    return render_template('token.html', token_remote=token_remote, \
                            token_onpremise=token_onpremise)
