from flask import Flask, request, jsonify, make_response, redirect, url_for, render_template, session
from flask_pymongo import PyMongo
from flask_bcrypt import Bcrypt
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, create_refresh_token, get_jwt
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField
from wtforms.validators import DataRequired, Email, Length, Regexp
from flask_cors import CORS
from flask_mail import Mail, Message
from flask_otp import OTP
from flask_otp import pyotp
from markupsafe import escape
from flask_wtf.csrf import CSRFProtect, generate_csrf
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
from config import Config
from bson import ObjectId
from datetime import datetime, timedelta

app = Flask(__name__)
app.config.from_object(Config)

mongo = PyMongo(app)
bcrypt = Bcrypt(app)
limiter = Limiter(app)
jwt = JWTManager(app)
CORS(app)
mail = Mail(app)
otp = OTP(app)
csrf = CSRFProtect(app)
ph = PasswordHasher()
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

class RegistrationForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[
        DataRequired(),
        Length(min=8),
        Regexp(
            r'^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[^\w\s]).{8,}$',
            message="Password must contain at least one uppercase letter, one lowercase letter, one digit, and one special character."
        )
    ])

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])

class OTPForm(FlaskForm):
    otp = StringField('OTP', validators=[DataRequired(), Length(min=6, max=6)])

@app.route('/register', methods=['POST'])
@csrf.exempt
@limiter.limit("10/minute")
def register():
    data = request.get_json()
    form = RegistrationForm(meta={'csrf': False}, data=data)

    if not form.validate():
        return jsonify({'message': 'Invalid input data', 'error': form.errors})

    name = form.name.data
    email = form.email.data
    password = form.password.data

    user = mongo.db.users.find_one({'email': email})

    if user:
        return jsonify({'message': 'User already exists'})

    user_id = generate_unique_id()  # Generate a 10-digit unique ID
    current_time = get_current_time()  # Get current datetime of Indian Standard
    hashed_password = ph.hash(password)

    user_data = {
        'user_id': user_id,
        'name': name,
        'email': email,
        'password': hashed_password,
        'status': 'inactive',
        'lockout_count': 0,
        'last_login_attempt': None,
        'created_at': current_time
    }

    mongo.db.users.insert_one(user_data)

    otp_secret = pyotp.random_base32()
    totp = pyotp.TOTP(otp_secret)
    otp_code = totp.now()

    mongo.db.users.update_one({'user_id': user_id}, {'$set': {'otp_secret': otp_secret, 'otp_code': otp_code}})

    send_otp_email(email, otp_code)

    return jsonify({'message': 'User registered successfully. OTP sent to your email.', 'csrfToken': "generate from here: http://localhost:5000/generate-csrf-token"})


@app.route('/verify-otp', methods=['POST'])
@csrf.exempt
def verify_otp():
    data = request.get_json()
    email = escape(data['email'])
    otp = escape(data['otp'])

    user = mongo.db.users.find_one({'email': email})

    if not user:
        return jsonify({'message': 'Invalid email'})

    stored_otp = user.get('otp_code')

    if not stored_otp:
        return jsonify({'message': 'OTP not found in the database'})

    if stored_otp == otp:
        mongo.db.users.update_one({'email': email}, {'$set': {'status': 'active'}})
        return jsonify({'message': 'OTP verified successfully. Account activated.'})
    else:
        return jsonify({'message': 'Invalid OTP'})


@app.route('/login', methods=['POST'])
@csrf.exempt
def login():
    data = request.get_json()
    email = escape(data['email'])
    password = escape(data['password'])

    user = mongo.db.users.find_one({'email': email})

    if not user:
        return jsonify({'message': 'Invalid credentials'})

    if user.get('lockout_count') and user['lockout_count'] >= 3:
        if user.get('last_login_attempt'):
            if user['last_login_attempt'] > datetime.utcnow() - timedelta(minutes=15):
                return jsonify({'message': 'Account locked. Please try again later.'}), 401
            else:
                # Reset lockout count if the lockout period has expired
                mongo.db.users.update_one({'email': email}, {'$set': {'lockout_count': 0}})

    try:
        if not ph.verify(user['password'], password):
            if user.get('lockout_count'):
                user['lockout_count'] += 1
            else:
                user['lockout_count'] = 1
            user['last_login_attempt'] = datetime.utcnow()

            if user['lockout_count'] >= 3:
                user['lockout_count'] = 3

            mongo.db.users.update_one({'email': email}, {'$set': {'lockout_count': user['lockout_count'],
                                                                   'last_login_attempt': user['last_login_attempt']}})

            return jsonify({'message': 'Invalid credentials'})
    except VerifyMismatchError:
        return jsonify({'message': 'Invalid credentials'})

    if user['status'] != 'active':
        return jsonify({'message': 'Account is not active'})

    # Reset lockout count and last_login_attempt upon successful login
    if user.get('lockout_count'):
        mongo.db.users.update_one({'email': email}, {'$unset': {'lockout_count': '', 'last_login_attempt': ''}})

    access_token = create_access_token(identity=str(user['_id']))

    refresh_token = create_refresh_token(identity=str(user['_id']))

    mongo.db.session_tokens.insert_one({'user_id': user['_id'], 'token': refresh_token})

    return jsonify({'access_token': access_token, 'refresh_token': refresh_token})


@app.route('/refresh', methods=['POST'])
def refresh():
    data = request.get_json()
    refresh_token = data['refresh_token']

    session_token = mongo.db.session_tokens.find_one({'token': refresh_token})

    if not session_token:
        return jsonify({'message': 'Invalid refresh token'})

    user_id = session_token['user_id']
    user = mongo.db.users.find_one({'_id': user_id})

    if not user:
        return jsonify({'message': 'Invalid user'})

    access_token = create_access_token(identity=str(user['_id']))

    return jsonify({'access_token': access_token})

@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    user_id = get_jwt_identity()
    user = mongo.db.users.find_one({'_id': ObjectId(user_id)}, {'name': 1, 'email': 1, 'status': 1})
    name = user['name']
    email = user['email']
    status = user['status']

    if user:
       return jsonify({ 'name': name, 'email': email, 'status': status})
    else:
        return jsonify({ 'error':'Invalid user' })

@app.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    jti = get_jwt()['jti']
    mongo.db.session_tokens.delete_one({'token': jti})
    return jsonify({'message': 'Logged out successfully'})


@app.route('/forgot-password', methods=['POST'])
@csrf.exempt
def forgot_password():
    data = request.get_json()
    email = escape(data['email'])

    user = mongo.db.users.find_one({'email': email})

    if not user:
        return jsonify({'message': 'Invalid email'})

    token = serializer.dumps(email, salt='forgot-password')
    reset_link = url_for('reset_password', token=token, _external=True)

    send_reset_password_email(email, reset_link)

    return jsonify({'message': 'Reset password instructions sent to your email'})


@app.route('/reset-password/<token>', methods=['GET', 'POST'])
@csrf.exempt
def reset_password(token):
    try:
        email = serializer.loads(token, salt='forgot-password', max_age=3600)
    except SignatureExpired:
        return jsonify({'message': 'Password reset link has expired'})

    user = mongo.db.users.find_one({'email': email})

    if not user:
        return jsonify({'message': 'Invalid user'})

    if request.method == 'POST':
        data = request.get_json()
        password = escape(data['password'])
        hashed_password = ph.hash(password)
        mongo.db.users.update_one({'email': email}, {'$set': {'password': hashed_password}})
        return jsonify({'message': 'Password reset successfully'})

    return render_template('reset_password.html', token=token)

@app.route('/generate-csrf-token', methods=['GET'])
def get_csrf_token():
    csrf_token = generate_csrf()
    return jsonify({'csrf_token': csrf_token})

# Error Handlers




def generate_unique_id():
    import uuid
    return str(uuid.uuid4())[:10]

def generate_csrf_token():
    csrf_token = generate_csrf()
    return csrf_token

def get_current_time():
    import datetime
    from pytz import timezone

    ist = timezone('Asia/Kolkata')
    current_time = datetime.datetime.now(ist)
    return current_time

def store_csrf_token(user_id, csrf_token):
    session['user_id'] = user_id
    session['csrf_token'] = csrf_token

    return jsonify({'message': 'User ID and CSRF token stored in session'})


def csrf_protect_enabled():
    return app.config['CSRF_PROTECTION_ENABLED']

def send_otp_email(email, otp_code):
    msg = Message('OTP Verification', sender=app.config['MAIL_USERNAME'], recipients=[email])
    msg.body = f'Your OTP is: {otp_code}'
    mail.send(msg)

def send_reset_password_email(email, reset_link):
    msg = Message('Reset Password', sender=app.config['MAIL_USERNAME'], recipients=[email])
    msg.body = f'Click the following link to reset your password: {reset_link}'
    mail.send(msg)


if __name__ == '__main__':
    app.run(debug=True)
