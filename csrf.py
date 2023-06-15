@app.route('/register', methods=['POST'])
@limiter.limit("10/minute")
def register():
    data = request.get_json()
    form = RegistrationForm(meta={'csrf': True}, data=data)

    if not form.validate():
        return jsonify({'message': 'Invalid input data'}, {'error': form.errors})

    name = escape(form.name.data)
    email = escape(form.email.data)
    password = escape(form.password.data)

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

    # Generate and store CSRF session token
    csrf_token = generate_csrf_token()
    store_csrf_token(csrf_token, user_id)

    response = {
        'message': 'User registered successfully. OTP sent to your email.',
        'csrf_token': csrf_token
    }

    return jsonify(response)
