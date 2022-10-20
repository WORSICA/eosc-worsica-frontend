from worsica_web import settings
from django.core.mail import send_mail
from django.utils.html import strip_tags

def is_bad_input(bad_input):
	lower_bad_input = bad_input.lower()
	FILTER_SQL_TERMS = ['SELECT ','FROM ','WHERE ','DELETE ','IN ','AND ','OR ','ALTER ','CREATE ','DROP ','SLEEP ', 'DELAY ']
	lower_bad_input2 = lower_bad_input.upper().replace('(',' ').replace(')',' ')#if my sql
	for f in FILTER_SQL_TERMS:
		if f in lower_bad_input2:
			return f, True
	FILTER_HTML_JS_TAGS = ['<script','<html','<input','<br','<span']	
	FILTER_OTHER_TAGS = ['../','./','\..','\.','http:','\\n','\\r']
	FILTER_CHARS = ['|','!','?','>','<','&','\"','\'','\\','#','$','(',')','^','*','+','/','-']
	FILTER = FILTER_HTML_JS_TAGS+FILTER_OTHER_TAGS+FILTER_CHARS
	#print(lower_bad_input)
	for f in FILTER:
		if f in lower_bad_input:
			return f, True	
	return None, False

def sanitize_input(i):
	return strip_tags(i)

def sanitize_input_email(i):
	i = i.replace(" ","") 
	return sanitize_input(i) #remove empty spaces on the email address
#
def parse_wkt_to_extent(wkt):
	wkt = wkt.replace(", ",",")
	wkt = wkt.replace("POLYGON ((","")
	wkt = wkt.replace("))","")
	wkt = wkt.replace("MULTI(","")
	wkt = wkt.replace(")","")
	wkt_split = wkt.split(',')

	left, bottom, right, top = 0, 0, 0, 0
	_auxw0 = []
	_auxw1 = []
	for ws in wkt_split:
		w = ws.split(" ")
		_auxw0.append(float(w[0]))
		_auxw1.append(float(w[1]))
	right = max(_auxw0)
	left = min(_auxw0)		
	top = max(_auxw1)
	bottom = min(_auxw1)

	startAt = None
	#w = wkt_split[0].split()
	#w0, w1= float(w[0]), float(w[1])
	return [left, bottom, right, top], startAt



# Send email notifications
def notify_users(send_to, subject, plain_content):
	# send_to: array of emails
	# subject: email subject
	# dic_pars: passes dictionary to template
	# plain_template: link to plain text template
	# html_template: link to html template
	try:
		print('debug')
		print('[WORSICA] ' + subject)
		print(plain_content)
		print(settings.WORSICA_DEFAULT_EMAIL)
		print(send_to)
		s = send_mail(
			'[WORSICA] ' + subject,
			plain_content,
			settings.WORSICA_DEFAULT_EMAIL,
			send_to,
			fail_silently=False
		)
		print(s)
	except Exception as e:
		print('Error sending email: '+str(e))

# Send email notification to User on Worsica registration with confirmation link
def notify_registration(new_user, new_profile, confirmation_link):
	# Prepare email parameters
	subject = 'Confirm account registration'
	plain_content = ('Congratulations. You created the following account:\n'+
		'Affiliation: '+new_profile.affiliation+"\n"+
		'Affiliation country: '+new_profile.affiliation_country.name+"\n"+
		'First name: '+new_user.first_name+"\n"+
		'Last name: '+ new_user.last_name+"\n"+
		'Email: '+ new_user.email+"\n"+
		'Please confirm your registration by following this link: '+ confirmation_link+"\n")
	# Send email to user	
	notify_users([new_user.email], subject, plain_content)

# Send email notification to Managers and to User on user's EGI Check-in registration
def notify_registration_egi(new_user, new_profile, activation_link):
	# Prepare email to notify admin
	subject = 'Confirm account registration by EGI'
	plain_content = ('Affiliation: '+new_profile.affiliation+"\n"+
		'Affiliation country: '+new_profile.affiliation_country.name+"\n"+
		'First name: '+new_user.first_name+"\n"+
		'Last name: '+ new_user.last_name+"\n"+
		'Email: '+ new_user.email+"\n")
	plain_content_managers = ('A new user registered to the service.\n'+
		plain_content+
		'Please activate this account by following this link: '+ activation_link+"\n")
	plain_content_user = ('Congratulations. You created the following account:\n'+
		plain_content+ 
		"You need to wait for administration to activate your account.")
	# Send email to Managers
	notify_users(settings.MANAGERS, subject, plain_content_managers)
	# Send email to user
	notify_users([new_user.email], subject, plain_content_user)

# Send email notification to Managers on user's Worsica registration
def notify_confirm_registration(new_user, new_profile, activation_link):
	# Prepare email parameters
	subject = 'Confirm Registration'
	plain_content = ('Affiliation: '+new_profile.affiliation+"\n"+
		'Affiliation country: '+new_profile.affiliation_country.name+"\n"+
		'First name: '+new_user.first_name+"\n"+
		'Last name: '+ new_user.last_name+"\n"+
		'Email: '+ new_user.email+"\n")
	plain_content_managers = ('A new user registered to the service.\n'+
		plain_content+
		'Please activate this account by following this link: '+ activation_link+"\n")
	# Send email to user
	notify_users(settings.MANAGERS, subject, plain_content_managers)

# Send email notification to User on user's Worsica activation
def notify_set_active(new_user, active):
	# Prepare email parameters
	#plain_content = ('username: '+new_user.username+'\n'+
	#	'default_email: '+settings.DEFAULT_FROM_EMAIL)
	# Send email to user
	if active:
		subject = 'Account activated'
		plain_content = ('Congratulations, your account '+new_user.username+' is activated. You can login.\n')
		notify_users([new_user.email], subject, plain_content)
	else:
		subject = 'Account deactivated'
		plain_content = ('Sorry, your account '+new_user.username+' is deactivated. For more information, enter in contact with the support (worsica@lnec.pt).\n')
		notify_users([new_user.email], subject, plain_content)

# Send email notification to User on user's password recover
def notify_user_password_recover(user, password_recover_link):
	# Prepare email parameters	
	subject = 'Password recovery'
	plain_content = ('You requested to recover password to your account username '+user.username+'\n'+
		'Please follow this link: '+ password_recover_link+"\n")
	notify_users([user.email], subject, plain_content)

#
def notify_success_user_password_change(user):
	# Prepare email parameters	
	subject = 'Password changed'
	plain_content = ('Success! You changed the password to your account username '+user.username+'\n'+
		'Please login \n')
	notify_users([user.email], subject, plain_content)