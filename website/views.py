from flask import Blueprint, render_template, request, flash, jsonify

from flask_login import  login_required, current_user # logout_user,  login_user

from .models import User

views = Blueprint('views', __name__)

@views.route('/')
@login_required
def home():
#    return render_template("home.html")
    return render_template("home.html", user=current_user)

@views.route('/report')
@login_required
def report():
    user = User.query.all()
#    return render_template("report.html")
    return render_template("report.html", user=user)
