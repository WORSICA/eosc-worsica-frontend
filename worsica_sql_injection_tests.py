#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import os


def _create_message(dic, msgtype, message):
    sdic = dic
    sdic['msgtype'] = msgtype
    sdic['message'] = message
    return sdic


def test_registrations(formdata):
    user = None
    user_created = False
    try:
        jsonmsg = {}
        # CHECK
        is_form_inputs_good = True
        _keys = ['name', 'surname', 'affiliation', 'email', ]
        for k in _keys:
            f, bad = utils.is_bad_input(formdata[k])
            if bad:
                is_form_inputs_good = False
                jsonmsg = _create_message(
                    jsonmsg, 'error', 'Error: Found possible malicious code injection on '+k+': " '+str(f)+' "')
                return jsonmsg
        if is_form_inputs_good:
            # AND SANITIZE
            auth.password_validation.validate_password(formdata['password'])
            get_user_by_username = User.objects.filter(
                username=utils.sanitize_input(formdata['email']))
            get_user_by_email = User.objects.filter(email=utils.sanitize_input(formdata['email']))
            user_not_exists = (len(get_user_by_username) == 0 and len(get_user_by_email) == 0)
            if len(get_user_by_username) > 0:
                jsonmsg = _create_message(
                    jsonmsg, 'error', 'Error: This username is already in use!')
                return jsonmsg
            elif len(get_user_by_email) > 0:
                jsonmsg = _create_message(jsonmsg, 'error', 'Error: This email is already in use!')
                return jsonmsg
            elif user_not_exists:
                print('all forms are clean, create account')
                user, user_created = User.objects.get_or_create(username=utils.sanitize_input(
                    formdata['email']), email=utils.sanitize_input(formdata['email']))
                if user_created:
                    user.username = utils.sanitize_input(formdata['email'])
                    user.first_name = utils.sanitize_input(formdata['name'])
                    user.last_name = utils.sanitize_input(formdata['surname'])
                    user.set_password(formdata['password'])
                    user.is_active = False  # workaround to avoid email activations
                    user.save()
                    # Try to update info if already exists
                    userprofile, up_created = worsica_portal_models.UserProfile.objects.get_or_create(
                        user=user)
                    if up_created:
                        userprofile.affiliation = utils.sanitize_input(formdata['affiliation'])
                        userprofile.affiliation_country = formdata['affiliation_country']
                        userprofile.save()
                        if not userprofile.confirm_registration:  # user.is_active:
                            # send email to activate account
                            try:
                                if user and user_created:  # if new user, delete it
                                    user.delete()
                                jsonmsg = _create_message(
                                    jsonmsg, 'notice', 'Success! In a few minutes, you will receive an email to activate account. Check SPAM.')
                                return jsonmsg
                            except Exception as e:
                                print(e)
                                if user and user_created:  # if new user, delete it
                                    user.delete()
                                jsonmsg = _create_message(
                                    jsonmsg, 'error', 'Error sending email: '+str(e))
                                return jsonmsg
                        else:
                            # remove this temporary fix
                            jsonmsg = _create_message(
                                jsonmsg, 'notice', 'Success! You can now login.')
                            return jsonmsg
                    else:
                        if user and user_created:  # if new user, delete it
                            user.delete()
                        jsonmsg = _create_message(
                            jsonmsg, 'error', 'Error! User profile could not be created.')
                        return jsonmsg
                else:
                    jsonmsg = _create_message(jsonmsg, 'error', 'Error: This user already exists!')
                    return jsonmsg
        else:
            jsonmsg = _create_message(
                jsonmsg, 'error', 'Error! Invalid inputs on form found, aborting registration!.')
            return jsonmsg
    except Exception as e:
        print(e)
        if user and user_created:  # if new user, delete it
            user.delete()
        jsonmsg = _create_message(jsonmsg, 'error', 'Error: '+str(e))
        return jsonmsg


if __name__ == '__main__':
    import django

    sys.path.append("/usr/local/worsica_web")
    os.environ['DJANGO_SETTINGS_MODULE'] = 'worsica_web.settings'
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "worsica_web.settings")

    django.setup()

    from worsica_portal import utils
    import worsica_portal.models as worsica_portal_models
    from django.contrib import auth
    from django.contrib.auth.models import User

    formdata = {}
    formdata['name'] = 'KfnqDuxw'
    formdata['surname'] = 'KfnqDuxw'
    formdata['password'] = 'teste12345678'
    formdata['affiliation_country'] = 'PT'
    CULPRITS = [
        '^(#$!@#$)(()))******',
        '!(()&&!|*|*|',
        ')',
        "0'XOR(if(now()=sysdate(),sleep(15),0))XOR'Z",
        '0"XOR(if(now()=sysdate(),sleep(15),0))XOR"Z',
        "12345\'\"\'\")",
        '-1 OR 2+30-30-1=0+0+0+1',
        '-1 OR 2+861-861-1=0+0+0+1',
        '-1 OR 2+994-994-1=0+0+0+1',
        '-1 OR 3+30-30-1=0+0+0+1',
        '-1 OR 3+861-861-1=0+0+0+1',
        '-1 OR 3+994-994-1=0+0+0+1',
        "1 waitfor delay '0:0:15' --",
        "38AzTN4F'",
        # "587ZjN95",
        "7iGM9awD') OR 193=(SELECT 193 FROM PG_SLEEP(15))--",
        "\'\"()&%<acx><ScRiPt >HZDq(9870)</ScRiPt>",
        "\'\"()&%<acx><ScRiPt >YMD3(9767)</ScRiPt>",
        "\'\"()&%<acx><ScRiPt >yq6M(9380)</ScRiPt>",
        "AIO63cOg'",
        "bxss.me",
        "@@d70Sv",
        "dD5zlfkI')) OR 54=(SELECT 54 FROM PG_SLEEP(15))--",
        "../../../../../../../../../../../../../../etc/passwd",
        "GMVSXZFg')) OR 114=(SELECT 114 FROM PG_SLEEP(15))--",
        "Http://bxss.me/t/fit.txt",
        "http://bxss.me/t/fit.txt?.tst",
        "http://some-inexistent-website.acu/some_inexistent_file_with_long_name?.tst",
        "if(now()=sysdate(),sleep(15),0)",
        "J7asvjnz' OR 867=(SELECT 867 FROM PG_SLEEP(15))--",
        # "@@jAHtX",
        "jGgBFdhD')) OR 97=(SELECT 97 FROM PG_SLEEP(15))--",
        # "@@JJ6mY",
        # "QZ54TFs3",
        "ra5NegYr",
        "./sample@email.tst",
        "../sample@email.tst",
        "sample@email.tst'|||'",
        "sample@email.tst'||'",
        "sample@email.tst'||''||'",
        "sample@email.tst9233233",
        "sample@email.tst9417113",
        "sample@email.tst'\"()&%<acx><ScRiPt >HZDq(9652)</ScRiPt>",
        "sample@email.tst\" AND 2*3*8=6*8 AND \"2YMV\"=\"2YMV",
        "sample@email.tst%' AND 2*3*8=6*8 AND 'cAnO'!='cAnO%",
        "sample@email.tst'||DBMS_PIPE.RECEIVE_MESSAGE(CHR(98)||CHR(98)||CHR(98),15)||'"
        "(select(0)from(select(sleep(15)))v)/*'+(select(0)from(select(sleep(15)))v)+'\"+(select(0)from(select(sleep(15)))v)+\"*/",
        "../../../../../../../../../../../../../../windows/win.ini",
    ]
    for c in CULPRITS:
        print('-----------------')
        print(c)
        formdata['email'] = c
        formdata['affiliation'] = c
        j = test_registrations(formdata)
        print(j['message'])
