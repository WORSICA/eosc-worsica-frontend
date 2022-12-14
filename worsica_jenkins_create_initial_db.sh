CUSTOM_HOME="/usr/local"
echo '------------------------------------'
echo '1- Create DB for worsica_web...'
export PGPASSWORD="${POSTGRES_PASSWORD}" 
if echo -e "CREATE DATABASE corsica_web_dev;\n
	CREATE USER ${POSTGRES_WORSICA_DB_USER} WITH PASSWORD '${POSTGRES_WORSICA_DB_PWD}';\n
	ALTER ROLE ${POSTGRES_WORSICA_DB_USER} SET client_encoding TO 'utf8';\n
	ALTER ROLE ${POSTGRES_WORSICA_DB_USER} SET default_transaction_isolation TO 'read committed';\n
	ALTER ROLE ${POSTGRES_WORSICA_DB_USER} SET timezone TO 'UTC';\n
	GRANT ALL PRIVILEGES ON DATABASE corsica_web_dev TO ${POSTGRES_WORSICA_DB_USER};"| psql -h postgis -p 5432 -U postgres ; then
	echo '[OK] Successfully created the DB worsica_web'
	if echo -e "CREATE EXTENSION postgis;"| psql -h postgis -p 5432 -U postgres corsica_web_dev ; then
		echo '[OK] Successfully added postgis extension to the DB worsica_web'
	else
		echo '[Error] Something went wrong on adding postgis extension to the DB worsica_web. Aborting!'
		exit 1
	fi
else
	echo '[Error] Something went wrong during creation. Aborting!'
	exit 1
fi

echo '------------------------------------'
echo '2- Make the django migrations and migrate...'
if ($CUSTOM_HOME/worsica_web-py363_venv/bin/python3 manage.py makemigrations && $CUSTOM_HOME/worsica_web-py363_venv/bin/python3 manage.py makemigrations worsica_portal ); then
	echo '[OK] Make migrations'
	if $CUSTOM_HOME/worsica_web-py363_venv/bin/python3 manage.py migrate ; then
		echo '[OK] Migrate'
	else
		echo '[Error] Something went wrong on migration. Aborting!'
		exit 1
	fi
else
	echo '[Error] Something went wrong on making migrations. Aborting!'
	exit 1
fi

echo '------------------------------------'
echo '3- Create user selenium_test...'
if echo -e "import django\n
import worsica_portal.models as worsica_portal_models\n
from django.contrib.auth.models import User\n
user, user_created = User.objects.get_or_create(username='rjmartins', email = '${WORSICA_FRONTEND_SUPERUSER_USERNAME}')\n
if user_created:\n
\tprint('Superuser created')\n
\tuser.is_active = True\n
\tuser.is_staff = True\n
\tuser.is_superuser = True\n
\tuser.set_password('${WORSICA_FRONTEND_SUPERUSER_PWD}')\n
\tuser.save()\n
\tprint('Success')\n
user, user_created = User.objects.get_or_create(username = '${WORSICA_FRONTEND_SELENIUM_USERNAME}', email ='selenium_test@test.com')\n
if user_created:\n
\tprint('User selenium_test created')\n
\tuser.is_active = True\n
\tuser.set_password('${WORSICA_FRONTEND_SELENIUM_PWD}')\n
\tuser.save()\n
\tprint('Success')\n
\tup, up_created = worsica_portal_models.UserProfile.objects.get_or_create(user=user)\n
\tif up_created:\n
\t\tprint('User profile selenium_test created')\n
\t\tup.affiliation = 'TEST'\n
\t\tup.affiliation_country = 'PT'\n
\t\tup.confirm_registration = True\n
\t\tup.read_disclaimer = True\n
\t\tup.save()\n
\t\tprint('Success')\n
\t\texit(0)\n
\telse:\n
\t\tprint('User profile exists, skip.')\n
\t\texit(0)\n
else:\n
\tprint('User exists, skip.')\n
\texit(0)\n" | $CUSTOM_HOME/worsica_web-py363_venv/bin/python3 manage.py shell ; then
	echo '[OK] Successfully created the DB worsica_web'
else
	echo '[Error] Something went wrong on creating users. Aborting!'
	exit 1
fi
