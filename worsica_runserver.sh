#!/bin/sh -ex
echo "(Re)Start Django"
pkill -9 -f 'python3 ./manage.py runserver' || true
python3 ./manage.py runserver 0.0.0.0:8001 
tail -f /dev/null
