class Config:
    # MongoDB Configuration
    MONGO_URI = 'mongodb+srv://admin:pawan2244@cluster0.mv4ja.mongodb.net/vvfin?retryWrites=true&w=majority'

    # Flask Secret Key
    SECRET_KEY = '4BD6D8629E112249FDD36A7211D44'

    # JWT Configuration
    JWT_SECRET_KEY = 'M5^L8H&m)41`Mzf=KA;f`sj5LJ`V:[M)/7cIieTpGV:hI2><!l~meD)FivyE((5'
    JWT_ACCESS_TOKEN_EXPIRES = 86400
    JWT_TOKEN_LOCATION = ['headers', 'cookies']
    JWT_COOKIE_SECURE = True
    JWT_COOKIE_CSRF_PROTECT = True
    JWT_CSRF_IN_COOKIES = True
    CSRF_PROTECTION_ENABLED = True

    # Flask-Mail Configuration
    MAIL_SERVER = 'smtppro.zoho.in'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = 'no-reply@vvfin.in'
    MAIL_PASSWORD = 'DfiL0C7fwT5y'
    MAIL_DEFAULT_SENDER = 'no-reply@vvfin.in'
