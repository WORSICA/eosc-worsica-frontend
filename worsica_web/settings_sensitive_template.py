print('load sensitive data')
#Feel free to change this to your needs.
#IS_ON_INCD: Custom boolean flag to distinguish different configs

#django
SECRET_KEY = '' #your django secret key
WORSICA_INTERMEDIATE_URL = '' #URL and port for your worsica intermediate
def getAllowedHosts(IS_ON_INCD):
    if IS_ON_INCD:
        ALLOWED_HOSTS = ['127.0.0.1', 'localhost'] 
    else:
        ALLOWED_HOSTS = ['127.0.0.1', 'localhost']   
    return ALLOWED_HOSTS

#custom vars
#WORSICA_FOLDER_PATH indicate full local path where all worsica components are located
#LOG_PATH where to send logs
#VENV_PYTHON_EXECUTABLE if you use venv to run, set the python3 executable, else set blank
def getPaths(IS_ON_INCD):
    if IS_ON_INCD:
        WORSICA_FOLDER_PATH = '/usr/local'
        VENV_PYTHON_EXECUTABLE = 'python3'
        LOG_PATH = '/dev/log'
    else:
        WORSICA_FOLDER_PATH = '/usr/local'
        VENV_PYTHON_EXECUTABLE = 'python3'
        LOG_PATH = '/dev/log'
    return WORSICA_FOLDER_PATH, VENV_PYTHON_EXECUTABLE, LOG_PATH


#egi checkin
#read egi checkin documentation and oidc-auth documentation
#LOGIN_REDIRECT_URL is the url on worsica where EGI provider must redirect after the checkin
LOGIN_REDIRECT_URL = '/login-egi/'
AUTH_SERVER = ''
AUTH_SERVER_USERINFO = AUTH_SERVER + '/protocol/openid-connect/userinfo'
AUTH_CLIENT_ID = '' 
AUTH_CLIENT_SECRET = '' 
AUTH_SCOPE = ('openid', 'profile', 'email', 'voperson_id')

#DB
#set DB configs according to your needs, read django documentation for more info
def getDatabaseConfigs(DEBUG, IS_ON_INCD):
    if DEBUG:
        DATABASES = {
            'default': {
                'ENGINE': 'django.db.backends.postgresql',
                'NAME': '',
                'USER': '',
                'PASSWORD': '',
                'HOST': '',
                'PORT': '',
            }
        }
    else:
        DATABASES = {
            'default': {
                'ENGINE': 'django.db.backends.postgresql',
                'NAME': '',
                'USER': '',
                'PASSWORD': '',
                'HOST': '',
                'PORT': '',
            }
        }
    return DATABASES

#email
#read django documentnation for more info
#WORSICA_DEFAULT_EMAIL the email address from who is sending the email
#MANAGERS are the list of emails to send (this is applied for user registrations)
EMAIL_HOST = ''
EMAIL_USE_TLS = False
EMAIL_PORT = 25
EMAIL_HOST_USER = ''
EMAIL_HOST_PASSWORD = ''
WORSICA_DEFAULT_EMAIL = '' 
def getEmailManagers(DEBUG):
    if DEBUG:
        MANAGERS = ('', )
    else:
        MANAGERS = ('', )
    return MANAGERS

#recaptcha
#read django-recaptcha documentation
#create a google recaptcha account and generate pub and priv keys
RECAPTCHA_PUBLIC_KEY = ''
RECAPTCHA_PRIVATE_KEY = ''
OPENLAYERS_API_KEY = ''
