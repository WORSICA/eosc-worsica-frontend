CUSTOM_HOME="/usr/local"
if (echo -e "def getCredentials():
\treturn {'user': '${WORSICA_SSECRET_USER}' ,'password': '${WORSICA_SSECRET_PASSWORD}'}\n" > $CUSTOM_HOME/worsica_web/worsica_portal/SSecrets.py) ; then
	echo '[OK] Successfully created the ssecrets'
else
	echo '[Error] Something went wrong on creating the ssecrets. Aborting!'
	exit 1
fi
