"""
Django settings for worsica_web project.

Generated by 'django-admin startproject' using Django 2.2.3.

For more information on this file, see
https://docs.djangoproject.com/en/2.2/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/2.2/ref/settings/
"""

import os
from worsica_portal import logger
from . import settings_sensitive
print('---------------------')
print(os.environ['PYTHONIOENCODING'])
print('---------------------')

# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

DATA_UPLOAD_MAX_MEMORY_SIZE = 52428800
# Quick-start development settings - unsuitable for production

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = settings_sensitive.SECRET_KEY

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True
IS_ON_INCD = True  # flag to differentiate settings development with centaurus


# CUSTOM VARIABLES
WORSICA_FOLDER_PATH, VENV_PYTHON_EXECUTABLE, LOG_PATH = settings_sensitive.getPaths(IS_ON_INCD)

worsica_logger = logger.init_logger('WorSiCa-Portal.Settings', LOG_PATH)
worsica_logger.info('Running on centaurus? '+str(IS_ON_INCD))

WORSICA_INTERMEDIATE_URL = settings_sensitive.WORSICA_INTERMEDIATE_URL
ALLOWED_HOSTS = settings_sensitive.getAllowedHosts(IS_ON_INCD)

# Application definition
if DEBUG:
    INSTALLED_APPS = [
        'django.contrib.admin',
        'django.contrib.auth',
        'django.contrib.contenttypes',
        'django.contrib.sessions',
        'django.contrib.messages',
        'django.contrib.staticfiles',

        'django_countries',
        'django_auth_oidc',

        'worsica_portal',
        'request',
    ]
else:
    INSTALLED_APPS = [
        'multi_captcha_admin',
        'django.contrib.admin',
        'django.contrib.auth',
        'django.contrib.contenttypes',
        'django.contrib.sessions',
        'django.contrib.messages',
        'django.contrib.staticfiles',

        'django_countries',
        'django_auth_oidc',
        'snowpenguin.django.recaptcha2',

        'worsica_portal',
        'request',
    ]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'request.middleware.RequestMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'worsica_web.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [os.path.join(BASE_DIR, 'worsica_portal/templates')],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'worsica_web.wsgi.application'

FILE_UPLOAD_HANDLERS = [
    'django.core.files.uploadhandler.TemporaryFileUploadHandler',
]

# Database
# https://docs.djangoproject.com/en/2.2/ref/settings/#databases
DATABASES = settings_sensitive.getDatabaseConfigs(DEBUG, IS_ON_INCD)

# Password validation
# https://docs.djangoproject.com/en/2.2/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]


# Internationalization
# https://docs.djangoproject.com/en/2.2/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_L10N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/2.2/howto/static-files/

STATIC_URL = '/static/'
if DEBUG:
    STATICFILES_DIRS = (
        os.path.join(BASE_DIR, 'static'),
    )
else:
    STATIC_ROOT = os.path.join(BASE_DIR, 'static')

# AUTH OIDC
LOGIN_REDIRECT_URL = settings_sensitive.LOGIN_REDIRECT_URL
AUTH_SERVER = settings_sensitive.AUTH_SERVER
AUTH_SERVER_USERINFO = settings_sensitive.AUTH_SERVER_USERINFO
AUTH_CLIENT_ID = settings_sensitive.AUTH_CLIENT_ID
AUTH_CLIENT_SECRET = settings_sensitive.AUTH_CLIENT_SECRET
AUTH_SCOPE = settings_sensitive.AUTH_SCOPE

# EMAIL
# Email notifications settings
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = settings_sensitive.EMAIL_HOST
EMAIL_USE_TLS = settings_sensitive.EMAIL_USE_TLS
EMAIL_PORT = settings_sensitive.EMAIL_PORT
EMAIL_HOST_USER = settings_sensitive.EMAIL_HOST_USER
EMAIL_HOST_PASSWORD = settings_sensitive.EMAIL_HOST_PASSWORD
MANAGERS = settings_sensitive.getEmailManagers(DEBUG)
WORSICA_DEFAULT_EMAIL = settings_sensitive.WORSICA_DEFAULT_EMAIL

REQUEST_IGNORE_AJAX = True
REQUEST_IGNORE_PATHS = (
    r'^admin/',
    r'^metrics/',
    r'^metrics.json',
    r'^portal/proxy/',
    # r'^index/',
)
REQUEST_IGNORE_USER_AGENTS = (
    r'^$',  # ignore requests with no user agent string set
    r'Googlebot',
    r'Baiduspider',
)
REQUEST_TRAFFIC_MODULES = (
    'request.traffic.UniqueVisitor',
    'request.traffic.UniqueVisit',
    'request.traffic.Hit',
    'request.traffic.User',
    'request.traffic.UniqueUser',
)

OPENLAYERS_API_KEY = settings_sensitive.OPENLAYERS_API_KEY

if not DEBUG:  # production
    RECAPTCHA_ENGINE = 'recaptcha2'
    print(RECAPTCHA_ENGINE)
    MULTI_CAPTCHA_ADMIN = {
        'engine': RECAPTCHA_ENGINE,
    }
    if RECAPTCHA_ENGINE == 'recaptcha2':
        RECAPTCHA_PUBLIC_KEY = settings_sensitive.RECAPTCHA_PUBLIC_KEY
        RECAPTCHA_PRIVATE_KEY = settings_sensitive.RECAPTCHA_PRIVATE_KEY
