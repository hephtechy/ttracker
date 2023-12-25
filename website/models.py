from . import db
from flask_login import UserMixin
from sqlalchemy.sql import func
from datetime import datetime, timedelta
import pytz



class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(50))
    last_name = db.Column(db.String(50))
    email = db.Column(db.String(150), unique=True)
    password = db.Column(db.String(150))
    sign_in_status = db.Column(db.Boolean, nullable=True)
    date = db.Column(db.Date, nullable=True)
    attendances = db.relationship('Attendance', backref='user', lazy=True)
    reports = db.relationship('Report', backref='user', lazy=True)

class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    sign_in_report = db.Column(db.String(250), nullable=True)
    date = db.Column(db.Date, nullable=False, default=datetime.utcnow().date)
    punctuality = db.Column(db.Boolean, nullable=True) # true - user is punctual, false - late, None - absent
    default_report = db.Column(db.String(250), nullable=True)
    attendances = db.relationship('Attendance',backref='report', lazy=True)

# Define Attendance model
class Attendance(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    report_id = db.Column(db.Integer, db.ForeignKey('report.id'), nullable=False)
    sign_in_datetime = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    sign_out_datetime = db.Column(db.DateTime)
    sign_in_time = db.Column(db.String(10), nullable=True)
    sign_out_time = db.Column(db.String(10), nullable=True)
    date = db.Column(db.Date, nullable=False, default=datetime.utcnow().date)
