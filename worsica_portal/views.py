from django.shortcuts import render, redirect
from django.contrib import auth
from django.template.context_processors import csrf
from django.contrib.auth.decorators import login_required, user_passes_test
from django.utils.text import slugify
from django.http import HttpResponse, FileResponse
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.auth.tokens import default_token_generator
from django.utils.encoding import force_bytes

from django.contrib.auth.models import User
from django.db.models import Count, Q

import worsica_portal.models as worsica_portal_models
import json
from collections import OrderedDict

from sentinelsat import SentinelAPI, geojson_to_wkt

from worsica_web import settings

import os
import requests
import zipfile

from . import logger
from . import SSecrets
from . import utils
from . import nextcloud_access

import traceback
import calendar
import datetime
import time

import request.models as request_models
import xlwt

import itertools
from operator import itemgetter

from base64 import b64encode


worsica_logger = logger.init_logger('WorSiCa-Portal.Views', settings.LOG_PATH)

##


def check_has_user_read_disclaimer(user):
    flag = False
    try:
        up = worsica_portal_models.UserProfile.objects.get(user=user)
        flag = (up and up.read_disclaimer)
    except Exception:  # if no user profile or fail
        flag = False
    print('--check read disclaimer? '+str(flag))
    return flag


def check_has_user_confirmed_registration(user):
    flag = False
    try:
        up = worsica_portal_models.UserProfile.objects.get(user=user)
        flag = (up and up.confirm_registration)
    except Exception:  # if no user profile or fail
        flag = False
    print('--check confirmed registration? '+str(flag))
    return flag


def check_has_user_activated(user):
    flag = False
    try:
        # if user exists, is active and has set at least an email
        flag = (user and user.is_active)
    except Exception:  # if no user or fail
        return False
    print('--check user activated? '+str(flag))
    return flag


def check_is_user_authenticated(user):
    flag = False
    try:
        flag = (user and user.is_authenticated and not user.is_anonymous)
    except Exception:  # if no user or fail
        flag = False
    print('--check user authenticated? '+str(flag))
    return flag


def check_has_user_filled_required_information(user):
    flag = False
    try:
        up = worsica_portal_models.UserProfile.objects.get(user=user)
        flag = (up and (user.email != '' and user.username != '' and up.affiliation != ''))
    except Exception:  # if no user or fail
        flag = False
    print('--check user filled required? '+str(flag))
    return flag
##


def _purge_message(request):
    c = {}
    if (request.GET.get('next')):  # check if theres a redirect
        c['next'] = request.GET.get('next')
    if (request.session.get('message')):
        print('remove message')
        c['message'] = request.session.pop('message')
    if (request.session.get('msgtype')):
        print('remove msgtype')
        c['msgtype'] = request.session.pop('msgtype')
    c.update(csrf(request))
    return c


def _create_message(dic, msgtype, message):
    sdic = dic
    sdic['msgtype'] = msgtype
    sdic['message'] = message
    print(message)
    return sdic


def _create_user_repository_frontend(user_id):
    try:
        requests_session = requests.Session()
        requests_session.auth = (nextcloud_access.NEXTCLOUD_USER, nextcloud_access.NEXTCLOUD_PWD)
        path = nextcloud_access.NEXTCLOUD_URL_PATH
        # create folder recursively
        pathList = ['/user_repository', '/user'+str(user_id)]  # create first the user_repository
        for p in pathList:
            path = path + p
            print(path)
            r = requests_session.request('MKCOL', path)
            if (r.status_code == 201 or r.status_code == 405):
                print('[_create_user_repository_frontend]: folder '+path+' does not exist, create')
        # reaching /user_repository/userID, start creating subfolders
        # imagesets will be for all services
        subfolders = ['/imagesets']
        for sf in subfolders:
            pathsf = path + sf
            print(pathsf)
            r = requests_session.request('MKCOL', pathsf)
            if (r.status_code == 201 or r.status_code == 405):
                print('[_create_user_repository_frontend]: folder '+pathsf+' does not exist, create')
        # create other folders
        # geometries will be loaded by each service
        # masks and leakpoints is only for waterleak service
        subfolders = ['/geometries', '/masks', '/leakpoints']
        for sf in subfolders:
            pathsf = path + sf
            print(pathsf)
            r = requests_session.request('MKCOL', pathsf)
            if (r.status_code == 201 or r.status_code == 405):
                print('[_create_user_repository_frontend]: folder '+pathsf+' does not exist, create')
            #
            subsubfolders = ['/waterleak']
            if sf in ['/geometries']:  # geometries will for all services
                subsubfolders += ['/inland', '/coastal']
            for ssf in subsubfolders:
                pathsf2 = pathsf + ssf
                print(pathsf2)
                r = requests_session.request('MKCOL', pathsf2)
                if (r.status_code == 201 or r.status_code == 405):
                    print('[_create_user_repository_frontend]: folder ' +
                          pathsf2+' does not exist, create')
    except Exception as e:
        print(traceback.format_exc())


# Create your views here.
def index(request):
    if request.user.is_authenticated:
        return redirect('/portal/')
    else:
        c = _purge_message(request)
        return render(request, 'index.html', c)


def login(request):
    c = _purge_message(request)
    if check_is_user_authenticated(request.user):
        if check_has_user_filled_required_information(request.user):
            if check_has_user_activated(request.user):
                if check_has_user_confirmed_registration(request.user):
                    if check_has_user_read_disclaimer(request.user):
                        if (request.GET.get('next')):  # check if theres a redirect
                            return redirect(request.GET.get('next'))
                        else:
                            return redirect('/portal')
                    else:
                        return redirect('/portal/disclaimer')
                else:
                    c = _create_message(c, "error", 'Error: User has not confirmed the registration')
            else:
                c = _create_message(c, "error", 'Error: User is not active')
        else:
            c = _create_message(
                c, "error", 'You havent finished your registration. If you are an EGI user, please login as EGI to finish.')

    else:
        if (request.GET.get('next')):  # check if theres a redirect
            c = _create_message(c, "error", 'Error: Login first before accessing to this page.')
    return render(request, 'login.html', c)


def auth_view(request):
    if '@' in request.POST.get('email', ''):
        try:
            find_user = User.objects.get(email=request.POST.get('email', ''))
            user = auth.authenticate(username=find_user.username,
                                     password=request.POST.get('password', ''))
            if user is not None:
                auth.login(request, user)
                if check_has_user_activated(user):  # if user.is_active: #if request.user.is_active:
                    if check_has_user_confirmed_registration(user):
                        if not check_has_user_read_disclaimer(user):
                            return redirect('/portal/disclaimer')
                        else:
                            if (request.GET.get('next')):  # check if theres a redirect
                                return redirect(request.GET.get('next'))
                            else:
                                return redirect('/portal')
                    else:
                        request.session = _create_message(
                            request.session, "error", 'Error: User has not confirmed yet the registration!')
                        return redirect('/accounts/login/')
                else:
                    request.session = _create_message(
                        request.session, "error", 'Error: User not yet activated!')
                    return redirect('/accounts/login/')
            else:
                request.session = _create_message(
                    request.session, "error", 'Error: Invalid email/password! Or if you already have an account, make sure you confirmed it and/or was approved by the administration.')
                return redirect('/accounts/login/')
        except Exception as e:
            request.session = _create_message(request.session, "error", 'Error: '+str(e))
            return redirect('/accounts/login/')
    else:
        request.session = _create_message(request.session, "error",
                                          'Error: Please provide an email address!')
        return redirect('/accounts/login/')


def user_token_encrypt(user):
    token = default_token_generator.make_token(user)
    uidb64 = urlsafe_base64_encode(force_bytes(user.pk))
    return token, uidb64


def user_token_decrypt(uidb64, token):
    user = User.objects.get(pk=urlsafe_base64_decode(uidb64))
    token_valid = default_token_generator.check_token(user, token)
    return user, token_valid

# user registration
# workflow
# 1) register (open page to user)
# 2) register_post (send post request to register user, send email to user)
# 3) activation (user activates to change confirm_registation flag, send email to admins)
# 4) userprofile_activate (admin goes to a admin page to activate/deactivate user account
# -a) activate_user (if admin activates user account, change is_active flag to true and send email to user)
# -b) deactivate_user (if admin deactivates/refuses, change is_active to false and send email to user)


def register(request):
    if request.user.is_authenticated:
        return redirect('/portal/')
    else:
        c = _purge_message(request)
        return render(request, 'register.html', c)


def register_post(request):
    if request.user.is_authenticated:
        return redirect('/portal/')
    else:
        user = None
        user_created = False
        request.encoding = 'utf-8'
        formdata = request.POST
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
                    return HttpResponse(json.dumps(jsonmsg), content_type='application/json')
            if is_form_inputs_good:
                # AND SANITIZE
                auth.password_validation.validate_password(formdata['password'])
                get_user_by_username = User.objects.filter(
                    username=utils.sanitize_input_email(formdata['email']))
                get_user_by_email = User.objects.filter(
                    email=utils.sanitize_input_email(formdata['email']))
                user_not_exists = (len(get_user_by_username) == 0 and len(get_user_by_email) == 0)
                if len(get_user_by_username) > 0:
                    jsonmsg = _create_message(
                        jsonmsg, 'error', 'Error: This username is already in use!')
                    return HttpResponse(json.dumps(jsonmsg), content_type='application/json')
                elif len(get_user_by_email) > 0:
                    jsonmsg = _create_message(
                        jsonmsg, 'error', 'Error: This email is already in use!')
                    return HttpResponse(json.dumps(jsonmsg), content_type='application/json')
                elif user_not_exists:
                    print('all forms are clean, create account')
                    user, user_created = User.objects.get_or_create(username=utils.sanitize_input_email(
                        formdata['email']), email=utils.sanitize_input_email(formdata['email']))
                    if user_created:
                        user.username = utils.sanitize_input_email(formdata['email'])
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
                                    token, uidb64 = user_token_encrypt(user)
                                    confirmation_link = request.build_absolute_uri(
                                        "/accounts/activation/"+str(uidb64)+'/'+str(token))
                                    utils.notify_registration(user, userprofile, confirmation_link)
                                    jsonmsg = _create_message(
                                        jsonmsg, 'notice', 'Success! Check SPAM, in a few minutes, you will receive an email with a link to confirm account.')
                                    return HttpResponse(json.dumps(jsonmsg), content_type='application/json')
                                except Exception as e:
                                    print(e)
                                    if user and user_created:  # if new user, delete it
                                        user.delete()
                                    jsonmsg = _create_message(
                                        jsonmsg, 'error', 'Error sending email: '+str(e))
                                    return HttpResponse(json.dumps(jsonmsg), content_type='application/json')
                            else:
                                # remove this temporary fix
                                jsonmsg = _create_message(
                                    jsonmsg, 'notice', 'Success! You can now login.')
                                return HttpResponse(json.dumps(jsonmsg), content_type='application/json')
                        else:
                            if user and user_created:  # if new user, delete it
                                user.delete()
                            jsonmsg = _create_message(
                                jsonmsg, 'error', 'Error! User profile could not be created.')
                            return HttpResponse(json.dumps(jsonmsg), content_type='application/json')
                    else:
                        jsonmsg = _create_message(
                            jsonmsg, 'error', 'Error: This user already exists!')
                        return HttpResponse(json.dumps(jsonmsg), content_type='application/json')
            else:
                jsonmsg = _create_message(
                    jsonmsg, 'error', 'Error! Invalid inputs on form found, aborting registration!.')
                return HttpResponse(json.dumps(jsonmsg), content_type='application/json')
        except Exception as e:
            print(e)
            if user and user_created:  # if new user, delete it
                user.delete()
            jsonmsg = _create_message(jsonmsg, 'error', 'Error: '+str(e))
            return HttpResponse(json.dumps(jsonmsg), content_type='application/json')


def activation(request, uidb64, token):
    try:
        if check_is_user_authenticated(request.user):
            return redirect('/portal/')
        else:
            user, token_valid = user_token_decrypt(uidb64, token)
            if user.is_active:
                request.session = _create_message(request.session, "error", 'Error: User is active')
                return redirect('/accounts/login/')
            else:
                userprofile = worsica_portal_models.UserProfile.objects.get(user=user)
                if userprofile.confirm_registration:
                    request.session = _create_message(
                        request.session, "error", 'Error: User has confirmed registration!')
                    return redirect('/accounts/login/')
                else:
                    userprofile.confirm_registration = True
                    userprofile.save()
                    # send email to set new password
                    activation_link = request.build_absolute_uri(
                        "/accounts/activate/"+str(uidb64)+'/'+str(token))
                    utils.notify_confirm_registration(user, userprofile, activation_link)
                    request.session = _create_message(
                        request.session, "notice", 'Success, you confirmed your account! Now you need to wait for administration to approve your account. You will receive soon an email confirming that and to login!')
                    return redirect('/accounts/login/')
    except Exception as e:
        request.session = _create_message(request.session, "error",
                                          'Error: User with that id does not exist')
        return redirect('/accounts/recovery/')
# admin only


@login_required
def userprofile_activate(request, uidb64, token):
    try:
        # Only power users can activate users
        if request.user.is_staff:
            try:
                new_user, token_valid = user_token_decrypt(uidb64, token)
                # Comment check of token validity - link can be used more than once
                if new_user:
                    request.session['activate_new_user'] = new_user.username
                    if new_user.is_active:
                        request.session['activate_msg'] = 'This user is already activated'
                    return redirect('/admin/worsica_portal/userprofile/')
                else:
                    msg = 'An error has occured, try again.'
            except Exception:
                msg = 'Error rendering admin/deployments with userprofile activate - getting user'
        else:
            msg = 'You do not have admin permissions to activate users'
    except Exception:
        msg = 'Error rendering admin/deployments with userprofile activate'
    request.session['msg_str'] = str(msg)
    return redirect('/admin/worsica_portal/userprofile/')
# admin only


@login_required
def activate_user(request, username):
    try:
        # Only power users can activate users
        if request.user.is_staff:
            try:
                # Save user as active (signal on Users pre-save sends email notification)
                new_user = User.objects.get(username=username)
                new_user.is_active = True
                new_user.save()
                utils.notify_set_active(new_user, True)
                request.session['activate_new_user'] = username
                request.session['activate_msg'] = 'User active'
                return redirect('/admin/worsica_portal/userprofile/')
            except Exception:
                msg = 'Error activating user'
        else:
            msg = "You do not have permissions to activate users"
    except Exception:
        msg = 'Error activating user'
    request.session['msg_str'] = str(msg)
    return redirect('/admin/worsica_portal/userprofile/')
# admin only


@login_required
def deactivate_user(request, username):
    try:
        # Only power users can activate users
        if request.user.is_staff:
            try:
                # Save user as active (signal on Users pre-save sends email notification)
                new_user = User.objects.get(username=username)
                new_user.is_active = False
                new_user.save()
                utils.notify_set_active(new_user, False)
                request.session['activate_new_user'] = username
                request.session['activate_msg'] = 'User was deactivated'  # and deleted'
                return redirect('/admin/worsica_portal/userprofile/')
            except Exception:
                msg = 'Error deactivating user'
        else:
            msg = "You do not have permissions to deactivate users"
    except Exception:
        msg = 'Error deactivating user'
    request.session['msg_str'] = str(msg)
    return redirect('/admin/worsica_portal/userprofile/')

# user recovery (set email)


def recovery_post(request):
    if check_is_user_authenticated(request.user):
        return redirect('/portal/')
    else:
        formdata = request.POST
        print(formdata)
        jsonmsg = {}
        try:
            user = User.objects.get(email=utils.sanitize_input_email(formdata['email']))
            token, uidb64 = user_token_encrypt(user)
            password_recover_link = request.build_absolute_uri(
                "/accounts/recovery_set_pwd/"+str(uidb64)+'/'+str(token))
            utils.notify_user_password_recover(user, password_recover_link)
            # send email to set new password
            jsonmsg = _create_message(
                jsonmsg, 'notice', 'Success! An email for password recovery was sent, please check on your mail box. Check SPAM.')
            return HttpResponse(json.dumps(jsonmsg), content_type='application/json')
        except Exception as e:
            jsonmsg = _create_message(jsonmsg, 'error', str(e))
            return HttpResponse(json.dumps(jsonmsg), content_type='application/json')

# user recovery 2 (set password)


def recovery_set_pwd(request, uidb64, token):
    try:
        if check_is_user_authenticated(request.user):
            return redirect('/portal/')
        else:
            user, token_valid = user_token_decrypt(uidb64, token)
            c = _purge_message(request)
            return render(request, 'recovery_set_pwd.html', c)
    except Exception as e:
        request.session = _create_message(request.session, "error",
                                          'Error: User with that id does not exist/Invalid token')
        return redirect('/accounts/login/')


def recovery_set_pwd_post(request, uidb64, token):
    formdata = request.POST
    jsonmsg = {}
    try:
        if check_is_user_authenticated(request.user):
            return redirect('/portal/')
        else:
            user, token_valid = user_token_decrypt(uidb64, token)
            new_password = formdata['password']
            auth.password_validation.validate_password(new_password)
            user.set_password(new_password)
            user.save()
            utils.notify_success_user_password_change(user)
            # send email
            jsonmsg = _create_message(
                jsonmsg, 'notice', 'Success! You changed the password, please login.')
            return HttpResponse(json.dumps(jsonmsg), content_type='application/json')
    except Exception as e:
        jsonmsg = _create_message(jsonmsg, "error", 'Error: '+str(e))
        return HttpResponse(json.dumps(jsonmsg), content_type='application/json')


def logout(request):
    auth.logout(request)
    request.session = _create_message(request.session, "notice", 'Logged out successfully!')
    return redirect('/index/')

# View for login/register via EGI Check-in service - Login redirect
# Authentication by egi using django-auth-oidc works by tokens. There's two caveats:
# Caveat 1 - login:
# 1) First time users: After accepting EGI permission, the user is redirected to the registration page and django oidc creates and logs in user for one session.
# 2) If the user decides to 'leave' the registration page, that session is lost, and When user starts again this procedure,
# django oidc can't do the registration because it becomes AnonymousUser (strangely he's not logged in). In that way, User no longer can do the registration.
# 3) To fix that, before the checks, log in the user. Get the openid session, and get the user from the sub variable, and use it to do the auth.login.
# Caveat 2 - access:
# 1) First time users: After accepting EGI permission, the user is redirected to the registration page and django oidc creates and logs in user for one session.
# 2) User can get out of registration page and go to any other page authenticated in that session (even if hasnt read the disclaimer or confirmed registration!),
# which consists in a security flaw.
# 3) To fix that flaw and improve security, two things were made:
# 3.1) login_egi: Before login, check four things, if user has filled required information, confirmed registration, is activated and read disclaimer. If any of these fail, throw error.
# 3.2) For all pages that do require login_required, apply these checks with user_passes_test


def login_egi(request):
    request.session = _create_message(request.session, "error",
                                      'An error occured during authentication. Try again.')
    try:
        # use access_token for dev (keycloak) or openid for production (mitreid)
        KEY_TOKEN = 'access_token'
        if KEY_TOKEN in request.session:
            # print(request.user)
            if request.user.is_anonymous:
                print('is anonymous, login again')
                oid = request.session['openid']
                auth.login(request, User.objects.get(username=oid['sub']))
                print('logged in as '+str(request.user))

            if check_has_user_filled_required_information(request.user):
                # if userprofile.confirm_registration:
                if check_has_user_confirmed_registration(request.user):
                    # if request.user.is_active and request.user.email != '':
                    if check_has_user_activated(request.user):
                        # userprofile = worsica_portal_models.UserProfile.objects.get(user=request.user) # Redirecting
                        if check_has_user_read_disclaimer(request.user):
                            if 'next' in request.GET:
                                return HttpResponseRedirect(request.GET['next'])
                            else:
                                return redirect('/portal')
                        else:
                            return redirect('/portal/disclaimer')
                    else:
                        request.session = _create_message(
                            request.session, "error", 'Your account is not activated.')
                        return redirect('/accounts/login/')
                else:
                    request.session = _create_message(
                        request.session, "error", 'You need to confirm your registration.')
                    return redirect('/accounts/login/')

            else:
                # Get user information
                access_token = request.session[KEY_TOKEN]

                headers = {
                    'Authorization': "Bearer " + access_token
                }
                get_user_info = requests.get(settings.AUTH_SERVER_USERINFO,
                                             headers=headers, allow_redirects=False)
                if get_user_info.status_code == 200:
                    user_info = get_user_info.json()
                    # keycloak (dev) uses client_id, while mitreid uses sub
                    user_info_sub = user_info['voperson_id']
                    new_user, created = User.objects.get_or_create(username=user_info_sub)
                    # If new user or no user info exists
                    new_user.is_active = False
                    if created:
                        new_user.password = '***'
                        if 'email' in user_info:
                            new_user.email = user_info['email']
                        if 'given_name' in user_info:
                            new_user.first_name = user_info['given_name']
                        if 'family_name' in user_info:
                            new_user.last_name = user_info['family_name']
                    new_user.save()
                    # Send fillout form
                    request.session = _create_message(
                        request.session, 'notice', 'Fill the required data and submit.')
                    # If UserProfile already exists but no affiliation info exists: send out fill form again
                    try:
                        new_userprofile = worsica_portal_models.UserProfile.objects.get(
                            user=new_user)
                        if new_userprofile.affiliation and new_userprofile.affiliation_country:
                            # Not a new user, all is filled out and activation is still pending
                            request.session = _create_message(
                                request.session, 'error', 'Your registration is still pending!')
                            return redirect('/accounts/login/')
                    except Exception:
                        print('skip...')
                    c = _purge_message(request)
                    request.session['user_info_sub'] = user_info_sub
                    if 'email' in user_info:
                        c['email'] = user_info['email']
                    if 'given_name' in user_info:
                        c['given_name'] = user_info['given_name']
                    if 'family_name' in user_info:
                        c['family_name'] = user_info['family_name']
                    return render(request, 'login_egi.html', c)
                else:
                    worsica_logger.debug('>> EGI userinfo request status not 200')
                    # Error logging through egi
                    request.session = _create_message(
                        request.session, "error", 'Error: userinfo request status not 200')
                    return redirect('/accounts/login/')  # render(request, '/login', c)
        else:
            worsica_logger.debug('>> EGI no token')
            # Error logging through egi
            request.session = _create_message(request.session, "error", 'Error: No token')
            return redirect('/accounts/login/')  # render(request, '/login', c)
    except Exception as e:
        worsica_logger.exception('Error on EGI login')
        # Error logging through egi
        request.session = _create_message(request.session, "error", 'Error on EGI login: '+str(e))
        return redirect('/accounts/login/')


# Complete EGI Registration
def login_egi_complete(request):
    # Try to update info if already exists
    if request.POST:
        request.encoding = 'utf-8'
        formdata = request.POST
        # Get user to update fields
        jsonmsg = {}
        user = None
        user_created = False
        # CHECK
        is_form_inputs_good = True
        _keys = ['name', 'surname', 'affiliation', 'email', ]
        for k in _keys:
            f, bad = utils.is_bad_input(formdata[k])
            if bad:
                is_form_inputs_good = False
                jsonmsg = _create_message(
                    jsonmsg, 'error', 'Error: Found possible malicious code injection on '+k+': " '+str(f)+' "')
                return HttpResponse(json.dumps(jsonmsg), content_type='application/json')
        if is_form_inputs_good:
            # AND SANITIZE
            get_user_by_email = User.objects.filter(
                email=utils.sanitize_input_email(formdata['email']))
            if len(get_user_by_email) > 0:
                jsonmsg = _create_message(jsonmsg, 'error', 'Error: This email is already in use!')
                return HttpResponse(json.dumps(jsonmsg), content_type='application/json')
            else:
                try:
                    user = User.objects.get(username=request.session.get('user_info_sub'))
                    if 'name' in formdata:
                        user.first_name = utils.sanitize_input(formdata['name'])
                    if 'surname' in formdata:
                        user.last_name = utils.sanitize_input(formdata['surname'])
                    if 'email' in formdata:
                        user.email = utils.sanitize_input_email(formdata['email'])
                    user.save()
                    try:
                        # Try to update info if already exists
                        userprofile = worsica_portal_models.UserProfile.objects.get(user=user)
                        userprofile.affiliation = utils.sanitize_input(formdata['affiliation'])
                        userprofile.affiliation_country = formdata['affiliation_country']
                        userprofile.confirm_registration = True
                        userprofile.save()

                    except Exception:
                        # UserProfile doesn't exist yet let's create it
                        userprofile = worsica_portal_models.UserProfile.objects.create(user=user, affiliation=utils.sanitize_input(formdata['affiliation']),
                                                                                       affiliation_country=formdata['affiliation_country'],
                                                                                       confirm_registration=True)

                    # Send email notifying user's register on create user
                    token, uidb64 = user_token_encrypt(user)
                    # Send user activation link to DEFAULT_FROM_EMAIL
                    activation_link = request.build_absolute_uri(
                        '/accounts/activate/'+str(uidb64)+'/'+str(token))
                    utils.notify_registration_egi(user, userprofile, activation_link)
                    jsonmsg = _create_message(
                        jsonmsg, 'notice', 'Success! In a few minutes, you will receive an email to activate account. Check SPAM.')
                    return HttpResponse(json.dumps(jsonmsg), content_type='application/json')
                except Exception as e:
                    worsica_logger.exception('Error on EGI registration')
                    print(e)
                    jsonmsg = _create_message(jsonmsg, 'error', 'Error: '+str(e))
                    return HttpResponse(json.dumps(jsonmsg), content_type='application/json')
        else:
            jsonmsg = _create_message(
                jsonmsg, 'error', 'Error! Invalid inputs on form found, aborting EGI registration!.')
            return HttpResponse(json.dumps(jsonmsg), content_type='application/json')

# View for logout of EGI Check-in service


def logout_egi(request):
    # Logout OPENCoastS
    auth.logout(request)
    request.session = _create_message(request.session, "notice", 'Logged out successfully!')
    return redirect('/accounts/login/')

# REMOVE THIS


def get_user(request, user_id):
    hostname = request.GET.get('hostname')
    ALLOW_WHICH_HOSTS = [settings.WORSICA_INTERMEDIATE_URL]
    if hostname in ALLOW_WHICH_HOSTS:
        try:
            user = User.objects.get(id=user_id)
            return HttpResponse(json.dumps({'alert': 'success', 'id': user.id, 'email': user.email}), content_type='application/json')
        except Exception as e:
            print(traceback.format_exc())
            return HttpResponse(json.dumps({'alert': 'error', 'details': str(e), 'msg': 'Unable to get user, see details'}), content_type='application/json')
    else:
        return HttpResponse(json.dumps({'alert': 'error', 'details': 'Sorry, you are not an allowed url to get this information.', 'msg': 'Unable to get user, see details'}), content_type='application/json')


@login_required
@user_passes_test(check_has_user_activated, login_url='/accounts/login')
@user_passes_test(check_has_user_confirmed_registration, login_url='/accounts/login')
@user_passes_test(check_has_user_filled_required_information, login_url='/accounts/login')
def disclaimer(request):
    if check_has_user_read_disclaimer(request.user):
        return redirect('/portal/')
    else:
        return render(request, 'disclaimer.html')


@login_required
@user_passes_test(check_has_user_activated, login_url='/accounts/login')
@user_passes_test(check_has_user_confirmed_registration, login_url='/accounts/login')
@user_passes_test(check_has_user_filled_required_information, login_url='/accounts/login')
def accept_disclaimer(request):
    if check_has_user_read_disclaimer(request.user):
        return redirect('/portal/')
    else:
        uprofile = worsica_portal_models.UserProfile.objects.get(user=request.user)
        uprofile.read_disclaimer = True
        uprofile.save()
        return redirect('/portal/')


@login_required
@user_passes_test(check_has_user_activated, login_url='/accounts/login')
@user_passes_test(check_has_user_confirmed_registration, login_url='/accounts/login')
@user_passes_test(check_has_user_filled_required_information, login_url='/accounts/login')
@user_passes_test(check_has_user_read_disclaimer, login_url='/accounts/disclaimer')
def home(request):
    return render(request, 'home.html')


@login_required
@user_passes_test(check_has_user_activated, login_url='/accounts/login')
@user_passes_test(check_has_user_confirmed_registration, login_url='/accounts/login')
@user_passes_test(check_has_user_filled_required_information, login_url='/accounts/login')
@user_passes_test(check_has_user_read_disclaimer, login_url='/accounts/disclaimer')
def metrics(request):
    if request.user.is_superuser or request.user.is_staff:
        return render(request, 'metrics.html')
    else:
        return redirect('/portal/')


@login_required
@user_passes_test(check_has_user_activated, login_url='/accounts/login')
@user_passes_test(check_has_user_confirmed_registration, login_url='/accounts/login')
@user_passes_test(check_has_user_filled_required_information, login_url='/accounts/login')
@user_passes_test(check_has_user_read_disclaimer, login_url='/accounts/disclaimer')
def get_json_metrics(request):
    monthYear = request.GET.get('monthYear').split('-')  # 2020-11
    metrics = get_metrics(monthYear)
    return HttpResponse(json.dumps(metrics), content_type='application/json')


@login_required
@user_passes_test(check_has_user_activated, login_url='/accounts/login')
@user_passes_test(check_has_user_confirmed_registration, login_url='/accounts/login')
@user_passes_test(check_has_user_filled_required_information, login_url='/accounts/login')
@user_passes_test(check_has_user_read_disclaimer, login_url='/accounts/disclaimer')
def export_xls_metrics(request):
    monthYear = request.GET.get('monthYear').split('-')
    response = get_xls_metrics(monthYear)
    return response


def get_xls_metrics(monthYear):
    beginDate = monthYear[0]+'-'+monthYear[1]+'-01'
    endDate = monthYear[0]+'-'+monthYear[1]+'-' + \
        str(calendar.monthrange(int(monthYear[0]), int(monthYear[1]))[1])
    metrics = get_metrics(monthYear)

    response = HttpResponse(content_type='application/ms-excel')
    response['Content-Disposition'] = 'attachment; filename="metrics-' + \
        monthYear[0]+'-'+monthYear[1]+'.xls"'

    wb = xlwt.Workbook(encoding='utf-8')
    ws = wb.add_sheet('Metrics')

    # date header
    font_style = xlwt.XFStyle()
    font_style.font.bold = True
    row_num = 0
    rh = [
        ['Metrics period', str(beginDate)+' - '+str(endDate)],
        ['Date/time', str(datetime.datetime.today().strftime('%Y-%m-%d %H:%M:%S'))]
    ]
    for r in rh:
        row_num += 1
        for col_num in range(len(r)):
            ws.write(row_num, col_num, r[col_num], font_style)

    # Sheet header, first row
    row_num += 3
    font_style = xlwt.XFStyle()
    font_style.font.bold = True
    columns = ['Metric', 'Explanation', 'Value', 'Units', ]
    for col_num in range(len(columns)):
        ws.write(row_num, col_num, columns[col_num], font_style)

    # Sheet body, remaining rows
    font_style = xlwt.XFStyle()
    rows = [
        ['MU_NUS', 'Number of different direct users who have accessed the service in a given period.',
            metrics['mu_nus'], 'Users/month'],
        ['MU_NUSA', 'Accumulative Number of direct different users who have accessed the service since PM6.',
         metrics['mu_nusa'], 'Users'],
        ['MU_NCEA', 'Accumulative Number of different centers where the users are based since PM6.',
         metrics['mu_ncea'], 'Centers'],
        ['MU_NCOA', 'Accumulative Number of different countries of origin of the users since PM6.',
         metrics['mu_ncoa'], 'Countries'],
        ['MU_NRUSA', 'Accumulative number of different users that accessed the service more than once since PM6.',
         metrics['mu_nrusa'], 'Users'],
    ]
    for row in rows:
        row_num += 1
        for col_num in range(len(row)):
            ws.write(row_num, col_num, row[col_num], font_style)
    wb.save(response)
    return response


def get_metrics(monthYear):
    beginDate = monthYear[0]+'-'+monthYear[1]+'-01'
    endDate = monthYear[0]+'-'+monthYear[1]+'-' + \
        str(calendar.monthrange(int(monthYear[0]), int(monthYear[1]))[1])
    # to find only the users, assure these requests have user id registered
    # Number of different direct users who have accessed the service in a given period.
    q = request_models.Request.objects.filter(
        time__lte=endDate, path__icontains='/portal').exclude(user_id=None)
    mu_nus = q.filter(time__gte=beginDate).order_by('user').distinct('user')
    # Accumulative Number of direct different users who have accessed the service since PM6.
    mu_nusa = q.order_by('user').distinct('user')
    # Accumulative Number of different centers where the users are based since PM6.
    mu_ncea = q.order_by('user__userprofile__affiliation').distinct('user__userprofile__affiliation')
    # Accumulative Number of different countries of origin of the users since PM6.
    mu_ncoa = q.order_by('user__userprofile__affiliation_country').distinct(
        'user__userprofile__affiliation_country')
    # Accumulative number of different users that accessed the service more than once since PM6.
    num_accesses = q.values('user').annotate(num_accesses=Count('time')).order_by('user')
    mu_nrusa = num_accesses.filter(num_accesses__gte=2)
    metrics = {
        'mu_nus': mu_nus.count(),
        'mu_nusa': mu_nusa.count(),
        'mu_ncea': mu_ncea.count(),
        'mu_ncoa': mu_ncoa.count(),
        'mu_nrusa': mu_nrusa.count(),
    }
    return metrics


@login_required
@user_passes_test(check_has_user_activated, login_url='/accounts/login')
@user_passes_test(check_has_user_confirmed_registration, login_url='/accounts/login')
@user_passes_test(check_has_user_filled_required_information, login_url='/accounts/login')
@user_passes_test(check_has_user_read_disclaimer, login_url='/accounts/disclaimer')
def home_coastal(request):
    ctx = {'openlayers_api_key': settings.OPENLAYERS_API_KEY}
    return render(request, 'detection-coastal/home_coastal.html', ctx)


@login_required
@user_passes_test(check_has_user_activated, login_url='/accounts/login')
@user_passes_test(check_has_user_confirmed_registration, login_url='/accounts/login')
@user_passes_test(check_has_user_filled_required_information, login_url='/accounts/login')
@user_passes_test(check_has_user_read_disclaimer, login_url='/accounts/disclaimer')
def home_inland(request):
    ctx = {'openlayers_api_key': settings.OPENLAYERS_API_KEY}
    return render(request, 'detection-inland/home_inland.html', ctx)


@login_required
@user_passes_test(check_has_user_activated, login_url='/accounts/login')
@user_passes_test(check_has_user_confirmed_registration, login_url='/accounts/login')
@user_passes_test(check_has_user_filled_required_information, login_url='/accounts/login')
@user_passes_test(check_has_user_read_disclaimer, login_url='/accounts/disclaimer')
def home_waterleak(request):
    ctx = {'openlayers_api_key': settings.OPENLAYERS_API_KEY}
    return render(request, 'detection-waterleak/home_waterleak.html', ctx)


@login_required
def upload_roi_coords(request):
    if request.method == 'POST':
        try:
            r = {}
            myfile = request.FILES['myfile']
            tmpfile = myfile.file.name  # file path name
            MAX_FILESIZE = 512
            if myfile.size > MAX_FILESIZE:  # 512B
                return HttpResponse(json.dumps({'alert': 'error', 'message': 'Error on upload: File size exceeded ('+str(MAX_FILESIZE)+'KB)'}), content_type='application/json')
            elif not myfile.name.endswith('.csv'):
                return HttpResponse(json.dumps({'alert': 'error', 'message': 'Error on upload: File extension is not csv'}), content_type='application/json')
            else:  # if everything goes well
                try:
                    with open(tmpfile, 'r') as f:
                        coords = f.read().split(',')
                        if (len(coords) == 4):
                            r = {
                                'alert': 'uploaded',
                                'latMax': max(coords[0], coords[2]),
                                'latMin': min(coords[0], coords[2]),
                                'lonMax': max(coords[1], coords[3]),
                                'lonMin': min(coords[1], coords[3]),
                            }
                            return HttpResponse(json.dumps(r), content_type='application/json')
                        else:
                            return HttpResponse(json.dumps({'alert': 'error', 'message': 'Error on reading file: There must be exactly 4 values for the coordinates, found '+str(len(coords))}), content_type='application/json')
                except Exception as e:
                    print(traceback.format_exc())
                    return HttpResponse(json.dumps({'alert': 'error', 'message': 'Error on reading file '}), content_type='application/json')
        except Exception as e:
            print(traceback.format_exc())
            return HttpResponse(json.dumps({'alert': 'error', 'message': 'Error on upload '}), content_type='application/json')
    else:
        return HttpResponse(json.dumps({'alert': 'error', 'message': 'Not a POST request!'}), content_type='application/json')


@login_required
def upload_sea_tides(request):
    if request.method == 'POST':
        try:
            myfile = request.FILES['myfile']
            tmpfile = myfile.file.name  # file path name
            if not myfile.name.endswith('.txt'):
                return HttpResponse(json.dumps({'alert': 'error', 'message': 'Error on upload: File extension is not txt'}), content_type='application/json')
            else:  # if everything goes well
                try:
                    # encode file
                    with open(tmpfile, 'r') as f:
                        encodedFile = b64encode(f.read().encode('ascii')).decode('ascii')
                    # os.remove(tmpfile)
                    return HttpResponse(json.dumps({'alert': 'success', 'encodedFile': encodedFile}), content_type='application/json')
                except Exception as e:
                    print(traceback.format_exc())
                    return HttpResponse(json.dumps({'alert': 'error', 'message': 'Error on reading file '}), content_type='application/json')
        except Exception as e:
            print(traceback.format_exc())
            return HttpResponse(json.dumps({'alert': 'error', 'message': 'Error on upload '}), content_type='application/json')
    else:
        return HttpResponse(json.dumps({'alert': 'error', 'message': 'Not a POST request!'}), content_type='application/json')


@login_required
def generate_topography_roi_simulation(request):
    try:
        jsonReq = json.loads(request.body.decode('utf-8'))
        roi_id, simulation_id = jsonReq['roi_id'], jsonReq['simulation_id']
        simulation = worsica_portal_models.Simulation.objects.get(aos__id=roi_id, pk=simulation_id)
        interm_generate_topography = 'http://'+settings.WORSICA_INTERMEDIATE_URL + \
            '/api/job_submissions/'+str(simulation.job_submission_id)+'/generate_topography'
        response = requests.post(interm_generate_topography, json=jsonReq)
        return HttpResponse(response.content, content_type='application/json')

    except Exception as e:
        print(traceback.format_exc())
        return HttpResponse(json.dumps({'alert': 'error', 'message': 'Error on upload '}), content_type='application/json')


@login_required
def probe_sea_tides(request):
    try:
        interm_probe_sea_tides = 'http://'+settings.WORSICA_INTERMEDIATE_URL+'/api/probe_sea_tides'
        jsonReq = json.loads(request.body.decode('utf-8'))
        response = requests.post(interm_probe_sea_tides, json=jsonReq)
        return HttpResponse(response.content, content_type='application/json')
    except Exception as e:
        return HttpResponse(json.dumps({'alert': 'error', 'error': str(e)}), content_type='application/json')


@login_required
def get_user_rois(request):
    service = request.GET.get('service')
    # from user
    kwargs = {}
    kwargs['is_visible'] = True
    if service:
        kwargs['service'] = service
    aoss = worsica_portal_models.AreaOfStudy.objects.filter(
        **kwargs).filter(Q(user__id=request.user.id))
    aoss2 = [a for a in aoss]
    # shared with
    shared_sims = worsica_portal_models.Simulation.objects.filter(
        Q(shared_with__id__in=[request.user.id]) & Q(aos__service=service) & Q(is_visible=True))
    aoss3 = [a.aos for a in shared_sims]
    return aoss2+aoss3


def get_user_roi(rois, roi_id):
    try:
        found_aos = None
        for aos in rois:
            # print(aos.id)
            if aos.id == int(roi_id):
                found_aos = aos
                break
        if found_aos is not None:
            return found_aos
        else:
            raise Exception('Area of study not found!')
    except Exception as e:
        raise Exception(e)


@login_required
def regions_of_interest(request):
    roi = []
    for aos in get_user_rois(request):
        is_owned_by_user = (aos.user.id == request.user.id)
        roi.append({
            'roi_id': aos.id,
            'service': aos.service,
            'name': aos.name+(" (shared)" if not is_owned_by_user else ""),
            'upperXcoordinate': aos.upperXcoordinate,
            'upperYcoordinate': aos.upperYcoordinate,
            'lowerXcoordinate': aos.lowerXcoordinate,
            'lowerYcoordinate': aos.lowerYcoordinate,
            'color': aos.color,
            'is_owned_by_user': is_owned_by_user
        })
    return HttpResponse(json.dumps(roi), content_type='application/json')


@login_required
def get_region_of_interest(request, roi_id):
    roi = {}
    aos = worsica_portal_models.AreaOfStudy.objects.get(id=roi_id)
    if aos:
        roi = {
            'roi_id': aos.id,
            'service': aos.service,
            'name': aos.name,
            'upperXcoordinate': aos.upperXcoordinate,
            'upperYcoordinate': aos.upperYcoordinate,
            'lowerXcoordinate': aos.lowerXcoordinate,
            'lowerYcoordinate': aos.lowerYcoordinate,
            'color': aos.color
        }
    return HttpResponse(json.dumps(roi), content_type='application/json')


@login_required
def delete_region_of_interest(request, roi_id):
    try:
        aos = worsica_portal_models.AreaOfStudy.objects.get(id=roi_id)
        if aos:
            simulations = worsica_portal_models.Simulation.objects.filter(aos=aos)
            for simulation in simulations:
                delete_simulation(request, roi_id, simulation.id)
            aos.delete()
        return HttpResponse(json.dumps({'alert': 'deleted', 'roi_id': roi_id}), content_type='application/json')
    except Exception as e:
        return HttpResponse(json.dumps({'alert': 'error', 'error': str(e)}), content_type='application/json')


@login_required
def create_region_of_interest(request):
    try:
        jsonReq = json.loads(request.body.decode('utf-8'))
        roi = worsica_portal_models.AreaOfStudy.objects.create(
            name=jsonReq['name'],
            service=jsonReq['service'],
            user=request.user,
            upperXcoordinate=jsonReq['upperXcoordinate'],
            upperYcoordinate=jsonReq['upperYcoordinate'],
            lowerXcoordinate=jsonReq['lowerXcoordinate'],
            lowerYcoordinate=jsonReq['lowerYcoordinate'],
            color=jsonReq['color'],
            reference='temp-ref')
        roi.reference = slugify('roi-'+str(roi.id))
        roi.save()
        return HttpResponse(json.dumps({
            'alert': 'created', 'roi_id': roi.id,
            'is_owned_by_user': (roi.user.id == request.user.id),
            'service': roi.service, 'name': roi.name,
            'upperXcoordinate': roi.upperXcoordinate, 'upperYcoordinate': roi.upperYcoordinate,
            'lowerXcoordinate': roi.lowerXcoordinate, 'lowerYcoordinate': roi.lowerYcoordinate,
            'color': roi.color
        }), content_type='application/json')
    except Exception as e:
        return HttpResponse(json.dumps({'alert': 'error', 'error': str(e)}), content_type='application/json')


@login_required
def proxy_get_imageset_thumbnail(request, uuid):
    esaCredentials = SSecrets.getCredentials()['user1']
    quicklook_url = "https://scihub.copernicus.eu/dhus/odata/v1/Products('" + \
        uuid+"')/Products('Quicklook')/$value"
    response = requests.get(quicklook_url, auth=(esaCredentials["user"], esaCredentials["password"]))
    return HttpResponse(response.content, content_type="image/jpeg")


def _list_esa_query_products(footprint, date, platformname, s1_producttype=None, s1_sensoroperationalmode=None, s2_processinglevel=None, s2_cloudcoverpercentage=None):
    querySuccess = False
    esaCredentials = SSecrets.getCredentials()
    for user in esaCredentials.keys():
        try:
            worsica_logger.info('[_list_esa_query_products]: trying esa query with '+user)
            api = SentinelAPI(esaCredentials[user]["user"], esaCredentials[user]["password"])
            # sentinel2
            if platformname == 'Sentinel-2':
                p = api.query(footprint, date=date, platformname=platformname,
                              processinglevel=s2_processinglevel, cloudcoverpercentage=s2_cloudcoverpercentage)
                querySuccess = True
                break
            # sentinel1
            elif platformname == 'Sentinel-1':
                p = api.query(footprint, date=date, platformname=platformname,
                              producttype=s1_producttype, sensoroperationalmode=s1_sensoroperationalmode)
                querySuccess = True
                break
        except Exception as e:
            print(traceback.format_exc())
            worsica_logger.info('[_list_esa_query_products]: query fail! wait 5 seconds...')
            time.sleep(5)
            continue
    if querySuccess:
        worsica_logger.info('[_list_esa_query_products]: query success!')
        products = OrderedDict(sorted(p.items(), key=lambda v: v[1]['beginposition'], reverse=True))
        return products
    else:
        # continue
        worsica_logger.info(
            '[_list_esa_query_products]: tried all available accounts with no sucess, giving up!')
        raise Exception('Query failed')


def _start_esa_imagery_search(bD, eD, uX, uY, lX, lY, minCloudCov, maxCloudCov, platformname, level=None, sensorOM=None):
    footprint = geojson_to_wkt({"type": "Polygon", "coordinates": [
                               [[lX, lY], [lX, uY], [uX, uY], [uX, lY], [lX, lY]]]})
    imageryJson = []
    if platformname == 'Sentinel-2':
        ls = level.split(',')  # ['Level-1C','Level-2A']
        if 'Level-2A' in ls and len(ls) > 1:  # ['Level-2A','Level-1C']
            aux = ls[0]
            ls[0] = ls[1]
            ls[1] = aux
        print(ls)
        for lv in ls:
            print(lv)
            products = _list_esa_query_products(footprint, date=(
                bD, eD), platformname=platformname, s2_processinglevel=lv, s2_cloudcoverpercentage=(minCloudCov, maxCloudCov))
            loadedProducts = {}
            for Id in products.keys():
                # e.g: S2A_MSIL2A_20180301T112111_N0206_R037_T29SPC_20180301T114356
                splitIdentifier = products[Id]["identifier"].split('_')
                _extent, _startAt = utils.parse_wkt_to_extent(str(products[Id]["footprint"]))
                jayson = {'name': products[Id]["identifier"], 'uuid': str(products[Id]['uuid']), 'size': str(products[Id]['size']), 'satelliteKind': splitIdentifier[0],
                          'image': '/portal/data/thumbnail/'+str(products[Id]['uuid'])+'/show', 'processinglevel': str(products[Id]["processinglevel"]),
                          'date': str(products[Id]["beginposition"]), 'pd': splitIdentifier[6], 'tilenumber': splitIdentifier[5], 'bbox': str(products[Id]["footprint"]),
                          'cloudcoverpercentage': str(products[Id]["cloudcoverpercentage"]), 'extent': _extent, 'startAt': _startAt}
                if (splitIdentifier[2]+"_"+splitIdentifier[5] not in loadedProducts):  # if not repeated, load it
                    worsica_logger.info('[get_satellite_imagery_from_esa]: add ' +
                                        splitIdentifier[2]+"_"+splitIdentifier[5]+' (pd: '+splitIdentifier[6]+')')
                    loadedProducts[splitIdentifier[2]+"_"+splitIdentifier[5]] = jayson
                    # get the least recent for the next query l1c
                    eD = products[Id]["beginposition"].strftime("%Y%m%d")
                else:
                    # check if product descriptor is most recent (assuming it's timestamps)
                    if splitIdentifier[6].split('T')[1] > loadedProducts[splitIdentifier[2]+"_"+splitIdentifier[5]]['pd'].split('T')[1]:
                        loadedProducts[splitIdentifier[2]+"_"+splitIdentifier[5]] = jayson
            imageryJson += [v for _, v in loadedProducts.items()]

    elif platformname == 'Sentinel-1':
        ls = level.split(',')  # ['Level-1C','Level-2A']
        sms = sensorOM.split(',')
        for lv in ls:
            for sm in sms:
                products = _list_esa_query_products(footprint, date=(
                    bD, eD), platformname=platformname, s1_producttype=lv, s1_sensoroperationalmode=sm)
                loadedProducts = {}
                for Id in products.keys():
                    # e.g: S2A_MSIL2A_20180301T112111_N0206_R037_T29SPC_20180301T114356
                    splitIdentifier = products[Id]["identifier"].split('_')
                    _extent, _startAt = utils.parse_wkt_to_extent(str(products[Id]["footprint"]))
                    jayson = {'name': products[Id]["identifier"], 'uuid': str(products[Id]['uuid']), 'size': str(products[Id]['size']), 'satelliteKind': splitIdentifier[0],
                              'image': '/portal/data/thumbnail/'+str(products[Id]['uuid'])+'/show', 'producttype': str(products[Id]["producttype"]), 'sensoroperationalmode': str(products[Id]["sensoroperationalmode"]),
                              'date': str(products[Id]["beginposition"]), 'pd': splitIdentifier[6], 'tilenumber': splitIdentifier[5], 'bbox': str(products[Id]["footprint"]),
                              'extent': _extent, 'startAt': _startAt}
                    # if not repeated, load it
                    if (splitIdentifier[2]+"_"+splitIdentifier[5] not in loadedProducts):
                        worsica_logger.info('[get_satellite_imagery_from_esa]: add ' +
                                            splitIdentifier[2]+"_"+splitIdentifier[5]+' (pd: '+splitIdentifier[6]+')')
                        loadedProducts[splitIdentifier[2]+"_"+splitIdentifier[5]] = jayson
                        # get the least recent for the next query l1c
                        eD = products[Id]["beginposition"].strftime("%Y%m%d")
                    else:
                        # check if product descriptor is most recent (assuming it's timestamps)
                        if splitIdentifier[6].split('T')[1] > loadedProducts[splitIdentifier[2]+"_"+splitIdentifier[5]]['pd'].split('T')[1]:
                            loadedProducts[splitIdentifier[2]+"_"+splitIdentifier[5]] = jayson
                imageryJson += [v for _, v in loadedProducts.items()]
    return imageryJson


@login_required
def get_satellite_imagery_from_esa(request):
    bD, eD = request.GET.get('beginDate').replace(
        "-", ""), request.GET.get('endDate').replace("-", "")
    uX, uY = float(request.GET.get('uX')), float(request.GET.get('uY'))
    lX, lY = float(request.GET.get('lX')), float(request.GET.get('lY'))
    minCloudCov, maxCloudCov = 0, float(request.GET.get('cloudCoverage'))  # 10
    platformname = request.GET.get('platformname')  # 'Sentinel-2'
    level = (request.GET.get('processinglevel') if platformname ==
             'Sentinel-2' else request.GET.get('producttype'))  # 'Level-1C,Level-2A'
    sensorOM = request.GET.get('sensoroperationalmode')  # 'IW,'
    imageryJson = _start_esa_imagery_search(
        bD, eD, uX, uY, lX, lY, minCloudCov, maxCloudCov, platformname, level, sensorOM)
    return HttpResponse(json.dumps(imageryJson), content_type='application/json')


def _build_job_submission(jsonReq, simulation, roi):
    providerDict = {
        'optInput1': 'sentinel2',
        'optInput2': 'pleiades',
        'optInput3': 'drone',
        'optInput4': 'terrasarx',
        'optInput5': 'sentinel1',
    }
    # send this detection to WorsicaIntermediate>Simulation
    extentS = [str(jsonReq['step1ROI']['topLeftX']), str(jsonReq['step1ROI']['topLeftY'])]
    extentF = [str(jsonReq['step1ROI']['bottomRightX']), str(jsonReq['step1ROI']['bottomRightY'])]
    payload = {
        "exec_arguments": {
            "service": roi.service,
            "roi": 'POLYGON (('+extentF[0]+' '+extentF[1]+','+extentS[0]+' '+extentF[1]+','+extentS[0]+' '+extentS[1]+','+extentF[0]+' '+extentS[1]+','+extentF[0]+' '+extentF[1]+'))',
            "inputs": {
                "provider": providerDict[jsonReq['step2Inputs']['optInput']],
                "listOfImagesets": [{'uuid': i['uuid'], 'small_name': i['small_name'], 'name':i['name'], 'convertToL2A': ('L1C' in i['name'] and jsonReq['step2Inputs']['conversion-l1-l2'])} for i in jsonReq['step3InputsRevision']['listOfImagesets']],
            },
            "detection": {
                "waterIndex": jsonReq['step4Detection']['waterindex'],
                "wiThreshold": jsonReq['step4Detection']['wi-threshold'],
                "topoHeight": jsonReq['step4Detection']['topography-depth'],
                "bathDepth": jsonReq['step4Detection']['bathymetry-depth'],
                "kMeansClusters": jsonReq['step4Detection']['kmeans-clusters']
            }
        },
        "object": {
            "areaOfStudy": {
                "id": roi.id,
                "user_id": roi.user.id,
                "user_email": roi.user.email,
                "service": roi.service,
                "simulation": {
                    "id": simulation.id,
                    "name": simulation.name,
                    "reference": simulation.reference
                }
            }
        }
    }
    return payload


@login_required
def edit_simulation(request, roi_id, simulation_id):
    try:
        # print(request.encoding)
        jsonReq = json.loads(request.body.decode('utf-8'))
        rois = get_user_rois(request)
        # check if you are not trying to cheat the system
        roi = get_user_roi(rois, roi_id)  # rois.get(pk = roi_id)
        is_owned_by_user = (roi.user.id == request.user.id)
        jsonReq_roi_id = jsonReq['step1ROI']['selectROI'].split('_')[1]  # roi_1
        if jsonReq_roi_id != roi_id:
            return HttpResponse(json.dumps({"alert": "error", "exception": "You are trying to edit a simulation for a different roi_id!"}), content_type='application/json')
        elif not is_owned_by_user:
            return HttpResponse(json.dumps({"alert": "error", "exception": "You do not own this simulation, thus have no permissions to edit!"}), content_type='application/json')
        else:
            simulation = worsica_portal_models.Simulation.objects.get(aos=roi, pk=simulation_id)
            simulation.name = jsonReq['simulationName']
            simulation.blob_text = json.dumps(jsonReq)
            simulation.reference = roi.service+'-aos'+str(roi.id)+'-simulation'+str(simulation.id)
            simulation.save()

            createdSim = []
            failedCreation = False
            payload = _build_job_submission(jsonReq, simulation, roi)

            reqPOST = requests.post('http://'+settings.WORSICA_INTERMEDIATE_URL +
                                    '/api/job_submissions/'+str(simulation.job_submission_id)+'/edit', json=payload)
            cs = reqPOST.json()
            if cs['alert'] == 'created':
                s = cs['job_submission']
                createdSim.append(s)
            else:
                failedCreation = True
                createdSim = []

            print(failedCreation)
            if (failedCreation):
                return HttpResponse(json.dumps({"alert": "error", "exception": cs}), content_type='application/json')
            else:
                # print(createdSim)
                return HttpResponse(json.dumps({"alert": "submitted", "simulation_id": simulation.id, "simulations": createdSim}), content_type='application/json')

    except Exception as e:
        print(traceback.format_exc())
        return HttpResponse(json.dumps({"alert": "error", "exception": "worsica-web:"+str(e)}), content_type='application/json')


@login_required
def create_simulation(request, roi_id):
    providerDict = {
        'optInput1': 'sentinel2',
        'optInput2': 'pleiades',
        'optInput3': 'drone',
        'optInput4': 'terrasarx',
        'optInput5': 'sentinel1',
    }
    try:
        request.encoding = 'utf-8'
        jsonReq = json.loads(request.body.decode('utf-8'))
        rois = get_user_rois(request)
        # check if you are not trying to cheat the system
        jsonReq_roi_id = jsonReq['step1ROI']['selectROI'].split('_')[1]  # roi_1
        if jsonReq_roi_id != roi_id:
            return HttpResponse(json.dumps({"alert": "error", "exception": "You are trying to create a simulation for a different roi_id!"}), content_type='application/json')
        else:
            roi = get_user_roi(rois, roi_id)  # rois.get(pk = roi_id)
            service = roi.service  # jsonReq['service']
            provider = providerDict[jsonReq['step2Inputs']['optInput']]

            simulation = worsica_portal_models.Simulation.objects.create(
                aos=roi,
                name=jsonReq['simulationName'],
                reference=jsonReq['simulationName'],
                blob_text=json.dumps(jsonReq)
            )
            simulation.reference = roi.service+'-aos'+str(roi.id)+'-simulation'+str(simulation.id)
            simulation.save()

            createdSim = []
            failedCreation = False
            payload = _build_job_submission(jsonReq, simulation, roi)

            reqPOST = requests.post('http://'+settings.WORSICA_INTERMEDIATE_URL +
                                    '/api/job_submissions/create', json=payload)
            cs = reqPOST.json()
            if cs['alert'] == 'created':
                s = cs['job_submission']
                # if success, update simulation_id
                # 'simulation'+str(satelliteImageSet.id)+'-'+satelliteImageSet.name
                simulation.name = s['name']
                simulation.job_submission_id = s['id']
                simulation.save()
                createdSim.append(s)
            else:
                failedCreation = True
                simulation.delete()
                createdSim = []
                # break

            print(failedCreation)
            if (failedCreation):
                return HttpResponse(json.dumps({"alert": "error", "exception": "Error on creating simulation!"}), content_type='application/json')
            else:
                return HttpResponse(json.dumps({"alert": "submitted", "simulation_id": simulation.id, "simulations": createdSim}), content_type='application/json')

    except Exception as e:
        return HttpResponse(json.dumps({"alert": "error", "exception": "worsica-web:"+str(e)}), content_type='application/json')


@login_required
def get_user_share_simulation(request, roi_id, simulation_id):
    try:
        rois = get_user_rois(request)
        roi = get_user_roi(rois, roi_id)  # rois.get(pk = roi_id)
        is_owned_by_user = (roi.user.id == request.user.id)
        if not is_owned_by_user:
            return HttpResponse(json.dumps({"alert": "error", "exception": "You do not own this simulation, thus have no permissions to share!"}), content_type='application/json')
        else:
            simulation = worsica_portal_models.Simulation.objects.get(aos=roi, pk=simulation_id)
            return HttpResponse(json.dumps({"alert": "success", "simulation_id": simulation.id, "shared_with_users": [{'id': u.id, 'name': u.first_name, 'email': u.email} for u in simulation.shared_with.all()]}), content_type='application/json')

    except Exception as e:
        print(traceback.format_exc())
        return HttpResponse(json.dumps({"alert": "error", "exception": "worsica-web:"+str(e)}), content_type='application/json')


@login_required
def get_simulation_dataverse_datasets(request, roi_id, simulation_id):
    try:
        rois = get_user_rois(request)
        roi = get_user_roi(rois, roi_id)  # rois.get(pk = roi_id)
        is_owned_by_user = (roi.user.id == request.user.id)
        if not is_owned_by_user:
            return HttpResponse(json.dumps({"alert": "error", "exception": "You do not own this simulation, thus have no permissions to see dataverses!"}), content_type='application/json')
        else:
            simulation = worsica_portal_models.Simulation.objects.get(
                id=simulation_id, aos__id=roi_id)
            reqGET = requests.get('http://'+settings.WORSICA_INTERMEDIATE_URL +
                                  '/api/job_submissions/'+str(simulation.job_submission_id)+'/dataverses')
            show_simulation_dv = reqGET.json()
            return HttpResponse(json.dumps(show_simulation_dv), content_type='application/json')

    except Exception as e:
        print(traceback.format_exc())
        return HttpResponse(json.dumps({'alert': 'error', 'roi_id': roi_id, 'id': simulation_id, 'error': str(e)}), content_type='application/json')


@login_required
def add_user_share_simulation(request, roi_id, simulation_id):
    try:
        jsonReq = json.loads(request.body.decode('utf-8'))
        rois = get_user_rois(request)
        roi = get_user_roi(rois, roi_id)  # rois.get(pk = roi_id)
        # check if you are not trying to cheat the system
        new_share_user_ids = jsonReq['new_share_user_id'].split(',')
        is_owned_by_user = (roi.user.id == request.user.id)
        if not is_owned_by_user:
            return HttpResponse(json.dumps({"alert": "error", "exception": "You do not own this simulation, thus have no permissions to share!"}), content_type='application/json')
        elif request.user.id in new_share_user_ids:
            return HttpResponse(json.dumps({"alert": "error", "exception": "You cannot share your own simulation with yourself!"}), content_type='application/json')
        else:
            failedAdd = False
            added_users = []
            try:
                for new_share_user_id in new_share_user_ids:
                    new_user = worsica_portal_models.User.objects.get(id=new_share_user_id)
                    added_users.append(new_user)
            except Exception as e:
                failedAdd = True
            if not failedAdd:
                simulation = worsica_portal_models.Simulation.objects.get(aos=roi, pk=simulation_id)
                for new_user in added_users:
                    if new_user not in simulation.shared_with.all():
                        simulation.shared_with.add(new_user)
                return HttpResponse(json.dumps({"alert": "shared", "simulation_id": simulation.id}), content_type='application/json')
            else:
                return HttpResponse(json.dumps({"alert": "error", "exception": "User with ID "+str(new_share_user_id)+" does not exist!"}), content_type='application/json')

    except Exception as e:
        print(traceback.format_exc())
        return HttpResponse(json.dumps({"alert": "error", "exception": "worsica-web:"+str(e)}), content_type='application/json')


@login_required
def add_simulation_dataverse_datasets(request, roi_id, simulation_id):
    try:
        jsonReq = json.loads(request.body.decode('utf-8'))  # title
        rois = get_user_rois(request)
        roi = get_user_roi(rois, roi_id)  # rois.get(pk = roi_id)
        # check if you are not trying to cheat the system
        is_owned_by_user = (roi.user.id == request.user.id)
        if not is_owned_by_user:
            return HttpResponse(json.dumps({"alert": "error", "exception": "You do not own this simulation, thus have no permissions to submit!"}), content_type='application/json')
        else:
            failedCreation = False
            simulation = worsica_portal_models.Simulation.objects.get(
                id=simulation_id, aos__id=roi_id)
            user = worsica_portal_models.User.objects.get(id=request.user.id)
            up = worsica_portal_models.UserProfile.objects.get(user=user)
            payload = jsonReq  # _build_leak_detection_submission(jsonReq,leakdetection, roi)
            payload['owner'] = {'name': user.first_name+' '+user.last_name,
                                'email': user.email, 'affiliation': up.affiliation}
            reqPOST = requests.post('http://'+settings.WORSICA_INTERMEDIATE_URL+'/api/job_submissions/' +
                                    str(simulation.job_submission_id)+'/dataverses/submit', json=payload)
            cs = reqPOST.json()
            createdDataverse = []
            print(cs)
            if cs['state'] == 'submitted':
                print('submitted')
            else:
                failedCreation = True

            print(failedCreation)
            if (failedCreation):
                return HttpResponse(json.dumps({"alert": "error", "exception": "Error on submitting dataverse!"}), content_type='application/json')
            else:
                return HttpResponse(json.dumps({"alert": "submitted", 'roi_id': roi_id, 'id': simulation_id, "submitted_dataverse": createdDataverse}), content_type='application/json')
    except Exception as e:
        print(traceback.format_exc())
        return HttpResponse(json.dumps({"alert": "error", "exception": "worsica-web:"+str(e)}), content_type='application/json')


@login_required
def remove_user_share_simulation(request, roi_id, simulation_id, existing_user_id):
    try:
        rois = get_user_rois(request)
        roi = get_user_roi(rois, roi_id)
        # check if you are not trying to cheat the system
        is_owned_by_user = (roi.user.id == request.user.id)
        if not is_owned_by_user:
            return HttpResponse(json.dumps({"alert": "error", "exception": "You do not own this simulation, thus have no permissions to remove sharing to a user!"}), content_type='application/json')
        else:
            existing_user = worsica_portal_models.User.objects.get(id=existing_user_id)
            if existing_user is None:
                return HttpResponse(json.dumps({"alert": "error", "exception": "User with that ID does not exist!"}), content_type='application/json')
            else:
                simulation = worsica_portal_models.Simulation.objects.get(aos=roi, pk=simulation_id)
                if existing_user in simulation.shared_with.all():
                    simulation.shared_with.remove(existing_user)
                return HttpResponse(json.dumps({"alert": "removed", "simulation_id": simulation.id}), content_type='application/json')
    except Exception as e:
        print(traceback.format_exc())
        return HttpResponse(json.dumps({"alert": "error", "exception": "worsica-web:"+str(e)}), content_type='application/json')


@login_required
def waterleak_edit_leak_detection(request, roi_id, simulation_id, leak_detection_id):
    try:
        request.encoding = 'utf-8'
        jsonReq = json.loads(request.body.decode('utf-8'))
        rois = get_user_rois(request)
        # check if you are not trying to cheat the system
        jsonReq_roi_id = jsonReq['step1ImageSelection']['roi_id']  # roi_1
        jsonReq_sim_id = jsonReq['step1ImageSelection']['simulation_id']
        if jsonReq_roi_id != roi_id:
            return HttpResponse(json.dumps({"alert": "error", "exception": "You are trying to create a leak detection for a different roi_id!"}), content_type='application/json')
        elif jsonReq_sim_id != simulation_id:
            return HttpResponse(json.dumps({"alert": "error", "exception": "You are trying to create a leak detection for a different sim_id!"}), content_type='application/json')
        else:
            roi = get_user_roi(rois, roi_id)  # rois.get(pk = roi_id)
            simulation = worsica_portal_models.Simulation.objects.get(aos=roi, pk=simulation_id)
            leakdetection = worsica_portal_models.LeakDetection.objects.get(
                simulation=simulation, id=leak_detection_id)
            leakdetection.blob_text = json.dumps(jsonReq)
            leakdetection.save()

            createdLD = []
            failedCreation = False
            payload = jsonReq

            reqPOST = requests.post('http://'+settings.WORSICA_INTERMEDIATE_URL+'/api/job_submissions/'+str(
                simulation.job_submission_id)+'/leak_detections/'+str(leakdetection.interm_leak_detection_id)+'/edit', json=payload)
            cs = reqPOST.json()
            print(cs)
            if cs['alert'] == 'created':
                s = cs['leak_detection']
                # if success, update simulation_id
                createdLD.append(s)
            else:
                failedCreation = True
                createdLD = []

            print(failedCreation)
            if (failedCreation):
                return HttpResponse(json.dumps({"alert": "error", "exception": "Error on editing leak detection!"}), content_type='application/json')
            else:
                return HttpResponse(json.dumps({"alert": "submitted", "simulation_id": simulation.id, "leak_detection_id": leakdetection.id, "leak_detections": createdLD}), content_type='application/json')

    except Exception as e:
        return HttpResponse(json.dumps({"alert": "error", "exception": "worsica-web:"+str(e)}), content_type='application/json')


@login_required
def waterleak_create_leak_detection(request, roi_id, simulation_id):
    try:
        request.encoding = 'utf-8'
        jsonReq = json.loads(request.body.decode('utf-8'))
        rois = get_user_rois(request)
        # check if you are not trying to cheat the system
        jsonReq_roi_id = jsonReq['step1ImageSelection']['roi_id']  # roi_1
        jsonReq_sim_id = jsonReq['step1ImageSelection']['simulation_id']
        if jsonReq_roi_id != roi_id:
            return HttpResponse(json.dumps({"alert": "error", "exception": "You are trying to create a leak detection for a different roi_id!"}), content_type='application/json')
        elif jsonReq_sim_id != simulation_id:
            return HttpResponse(json.dumps({"alert": "error", "exception": "You are trying to create a leak detection for a different sim_id!"}), content_type='application/json')
        else:
            roi = get_user_roi(rois, roi_id)
            service = roi.service
            simulation = worsica_portal_models.Simulation.objects.get(
                aos=roi,
                id=simulation_id
            )
            leakdetection = worsica_portal_models.LeakDetection.objects.create(
                simulation=simulation,
                name=jsonReq['leakDetectionName'],
                reference=slugify(jsonReq['leakDetectionName']),
                blob_text=json.dumps(jsonReq)
            )
            leakdetection.reference = roi.service+'-aos' + \
                str(roi.id)+'-simulation'+str(simulation.id)+'-leakdetection'+str(leakdetection.id)
            leakdetection.save()

            createdLD = []
            failedCreation = False
            payload = jsonReq

            reqPOST = requests.post('http://'+settings.WORSICA_INTERMEDIATE_URL+'/api/job_submissions/' +
                                    str(simulation.job_submission_id)+'/leak_detections/create', json=payload)
            cs = reqPOST.json()
            print(cs)
            if cs['alert'] == 'created':
                s = cs['leak_detection']
                leakdetection.name = s['name']
                leakdetection.interm_leak_detection_id = s['id']
                leakdetection.save()
                createdLD.append(s)
            else:
                failedCreation = True
                leakdetection.delete()
                createdLD = []

            print(failedCreation)
            if (failedCreation):
                return HttpResponse(json.dumps({"alert": "error", "exception": "Error on creating leak detection!"}), content_type='application/json')
            else:
                return HttpResponse(json.dumps({"alert": "submitted", "simulation_id": simulation.id, "leak_detection_id": leakdetection.id, "leak_detections": createdLD}), content_type='application/json')

    except Exception as e:
        return HttpResponse(json.dumps({"alert": "error", "exception": "worsica-web:"+str(e)}), content_type='application/json')


@login_required
def waterleak_check_existing_simulation(request, roi_id):
    providerDict = {
        'optInput1': 'sentinel2',
        'optInput2': 'pleiades',
        'optInput3': 'drone',
        'optInput4': 'terrasarx',
        'optInput5': 'sentinel1',
    }
    try:
        if (request.GET.get('provider')):
            provider = request.GET.get('provider')
        else:
            return HttpResponse(json.dumps({'state': 'error', 'roi_id': roi_id, 'error': 'No provider argument set.'}), content_type='application/json')

        simulations = worsica_portal_models.Simulation.objects.filter(
            aos__id=roi_id, aos__service='waterleak', is_visible=True)
        exists = False
        simulation_id = None
        simulation_state = None
        for simulation in simulations:
            if simulation.job_submission_id is not None:
                reqGET = requests.get('http://'+settings.WORSICA_INTERMEDIATE_URL +
                                      '/api/job_submissions/'+str(simulation.job_submission_id))
                j = reqGET.json()
                if (j['alert'] != 'error' and j['provider'] == providerDict[provider]):
                    exists = True
                    simulation_id = simulation.id
                    simulation_state = j['state']
                    break
        return HttpResponse(json.dumps({'state': 'success', 'roi_id': roi_id, 'provider': providerDict[provider], 'exists': exists, 'simulation_id': simulation_id, 'simulation_state': simulation_state}), content_type='application/json')
    except Exception as e:
        return HttpResponse(json.dumps({'state': 'error', 'roi_id': roi_id, 'error': str(e)}), content_type='application/json')


@login_required
def get_simulations(request, roi_id):
    try:
        user_id = request.user.id
        # get list of uploaded prods
        aos = worsica_portal_models.AreaOfStudy.objects.get(id=roi_id)
        is_owned_by_user = (aos.user.id == user_id)
        jsonResponseUserRepository = []
        service_type = aos.service
        if is_owned_by_user:
            simulations = worsica_portal_models.Simulation.objects.filter(aos__id=roi_id)
        else:
            simulations = worsica_portal_models.Simulation.objects.filter(
                shared_with__id__in=[user_id], aos__service=service_type, is_visible=True)

        roi_polygon = str(aos.upperYcoordinate)+'|'+str(aos.upperXcoordinate) + \
            '|'+str(aos.lowerYcoordinate)+'|'+str(aos.lowerXcoordinate)
        list_url = 'http://'+settings.WORSICA_INTERMEDIATE_URL+'/api/user_repository/user' + \
            str(user_id)+'/list?service_type='+service_type+'&roi_polygon='+roi_polygon
        reqGET = requests.get(list_url)
        j = reqGET.json()
        jsonResponseUserRepository.append(j)
        # get simulations
        jsonResponseSimulations = []
        for simulation in simulations:
            if simulation.job_submission_id is not None:
                reqGET = requests.get('http://'+settings.WORSICA_INTERMEDIATE_URL +
                                      '/api/job_submissions/'+str(simulation.job_submission_id), params=request.GET)
                j = reqGET.json()
                if (j['alert'] != 'error'):
                    j['is_owned_by_user'] = is_owned_by_user
                    if 'leakDetections' in j:
                        for k in j['leakDetections']:  # reverse ld_id to provide the correct id on portal side
                            try:
                                pld = worsica_portal_models.LeakDetection.objects.get(
                                    interm_leak_detection_id=k['ld_id'])
                                k['portal_ld_id'] = (pld.id if pld is not None else None)
                            except Exception as e:
                                k['portal_ld_id'] = None
                                pass
                            for m in k['outputs']:
                                m['is_owned_by_user'] = is_owned_by_user
                    jsonResponseSimulations.append(j)
        return HttpResponse(json.dumps({'state': 'success', 'roi_id': roi_id, 'simulations': jsonResponseSimulations, 'user_repository': jsonResponseUserRepository[0]}), content_type='application/json')
    except Exception as e:
        return HttpResponse(json.dumps({'state': 'error', 'roi_id': roi_id, 'error': str(e)}), content_type='application/json')


@login_required
def show_simulation(request, roi_id, simulation_id):
    try:
        simulation = worsica_portal_models.Simulation.objects.get(id=simulation_id, aos__id=roi_id)
        is_owned_by_user = (simulation.aos.user.id == request.user.id) or (
            request.user in simulation.shared_with.all())
        if not is_owned_by_user:
            return HttpResponse(json.dumps({"alert": "error", 'roi_id': roi_id, 'id': simulation_id, 'error': "You do not own this simulation, thus have no permissions to view!"}), content_type='application/json')
        else:
            reqGET = requests.get('http://'+settings.WORSICA_INTERMEDIATE_URL +
                                  '/api/job_submissions/'+str(simulation.job_submission_id))
            show_simulation = reqGET.json()
            return HttpResponse(json.dumps(show_simulation), content_type='application/json')

    except Exception as e:
        return HttpResponse(json.dumps({'state': 'error', 'roi_id': roi_id, 'id': simulation_id, 'error': str(e)}), content_type='application/json')


@login_required
def show_simulation_details(request, roi_id, simulation_id):
    try:
        simulation = worsica_portal_models.Simulation.objects.get(id=simulation_id, aos__id=roi_id)
        reqGET = requests.get('http://'+settings.WORSICA_INTERMEDIATE_URL +
                              '/api/job_submissions/'+str(simulation.job_submission_id)+'/details')
        show_simulation = reqGET.json()
        return HttpResponse(json.dumps(show_simulation), content_type='application/json')

    except Exception as e:
        return HttpResponse(json.dumps({'state': 'error', 'roi_id': roi_id, 'id': simulation_id, 'error': str(e)}), content_type='application/json')


@login_required
def load_json_blob_simulation(request, roi_id, simulation_id):
    try:
        simulation = worsica_portal_models.Simulation.objects.get(id=simulation_id, aos__id=roi_id)
        return HttpResponse(json.dumps({'state': 'loaded', 'blob': json.loads(simulation.blob_text)}), content_type='application/json')

    except Exception as e:
        return HttpResponse(json.dumps({'state': 'error', 'roi_id': roi_id, 'id': simulation_id, 'error': str(e)}), content_type='application/json')


@login_required
def show_simulation_procimageset_coastline(request, roi_id, simulation_id, intermediate_process_imageset_id, shp_mpis_id):
    try:
        simulation = worsica_portal_models.Simulation.objects.get(id=simulation_id, aos__id=roi_id)
        reqGET = requests.get('http://'+settings.WORSICA_INTERMEDIATE_URL+'/api/job_submissions/'+str(simulation.job_submission_id) +
                              '/processimageset/'+str(intermediate_process_imageset_id)+'/coastline/'+shp_mpis_id, params=request.GET)
        show_simulation = reqGET.json()
        return HttpResponse(json.dumps(show_simulation), content_type='application/json')

    except Exception as e:
        return HttpResponse(json.dumps({'state': 'error', 'roi_id': roi_id, 'id': simulation_id, 'error': str(e)}), content_type='application/json')


@login_required
def clone_cleanup_simulation_coastlines(request, roi_id, simulation_id):
    try:
        simulation = worsica_portal_models.Simulation.objects.get(id=simulation_id, aos__id=roi_id)
        payload = json.loads(request.body.decode('utf-8'))
        reqGET = requests.get('http://'+settings.WORSICA_INTERMEDIATE_URL+'/api/job_submissions/' +
                              str(simulation.job_submission_id)+'/clone_cleanup_all', json=payload)
        show_simulation = reqGET.json()
        return HttpResponse(json.dumps(show_simulation), content_type='application/json')

    except Exception as e:
        return HttpResponse(json.dumps({'state': 'error', 'roi_id': roi_id, 'id': simulation_id, 'error': str(e)}), content_type='application/json')


@login_required
def clone_cleanup_simulation_procimageset_coastline(request, roi_id, simulation_id, intermediate_process_imageset_id, shp_mpis_id):
    try:
        simulation = worsica_portal_models.Simulation.objects.get(id=simulation_id, aos__id=roi_id)
        payload = json.loads(request.body.decode('utf-8'))
        reqGET = requests.get('http://'+settings.WORSICA_INTERMEDIATE_URL+'/api/job_submissions/'+str(simulation.job_submission_id) +
                              '/processimageset/'+str(intermediate_process_imageset_id)+'/coastline/'+shp_mpis_id+'/clone_cleanup', json=payload)
        show_simulation = reqGET.json()
        return HttpResponse(json.dumps(show_simulation), content_type='application/json')

    except Exception as e:
        return HttpResponse(json.dumps({'state': 'error', 'roi_id': roi_id, 'id': simulation_id, 'error': str(e)}), content_type='application/json')


@login_required
def delete_cleanup_simulation_procimageset_coastline(request, roi_id, simulation_id, intermediate_process_imageset_id, shp_mpis_id):
    try:
        simulation = worsica_portal_models.Simulation.objects.get(id=simulation_id, aos__id=roi_id)
        reqGET = requests.get('http://'+settings.WORSICA_INTERMEDIATE_URL+'/api/job_submissions/'+str(simulation.job_submission_id) +
                              '/processimageset/'+str(intermediate_process_imageset_id)+'/coastline/'+shp_mpis_id+'/delete_cleanup')
        show_simulation = reqGET.json()
        return HttpResponse(json.dumps(show_simulation), content_type='application/json')

    except Exception as e:
        return HttpResponse(json.dumps({'state': 'error', 'roi_id': roi_id, 'id': simulation_id, 'error': str(e)}), content_type='application/json')


@login_required
def download_cleanup_simulation_procimageset_coastline(request, roi_id, simulation_id, intermediate_process_imageset_id, shp_mpis_id):
    try:
        CHUNK_SIZE = 5*1024*1024  # 5MB
        simulation = worsica_portal_models.Simulation.objects.get(id=simulation_id, aos__id=roi_id)
        interm_download_url = 'http://'+settings.WORSICA_INTERMEDIATE_URL+'/api/job_submissions/' + \
            str(simulation.job_submission_id)+'/processimageset/' + \
            str(intermediate_process_imageset_id)+'/coastline/'+str(shp_mpis_id)+'/download_cleanup'
        response = requests.get(interm_download_url, params=request.GET, stream=True)
        if response.status_code == 200:
            show_download = response.json()
            r = requests.get(show_download['url'], stream=True, auth=(
                show_download['user'], show_download['pwd']))
            appropriateFileName = str(simulation.aos.name)+'-' + \
                str(simulation.name)+'-'+show_download['appropriateFileName']
            if r.status_code == 200:
                fr = FileResponse(
                    (i for i in r.iter_content(chunk_size=CHUNK_SIZE)),
                    content_type='application/zip'
                )
                fr['Content-Disposition'] = 'attachment; filename="{0}"'.format(appropriateFileName)
                return fr
            else:
                return HttpResponse(r.text)
        else:
            return HttpResponse(response.text)
    except Exception as e:
        return HttpResponse(json.dumps({'state': 'error', 'roi_id': roi_id, 'id': simulation_id, 'error': str(e)}), content_type='application/json')

# ---------------------------------
# leak detection procimageset


@login_required
def show_simulation_procimageset_raster_leakdetection(request, roi_id, simulation_id, leak_detection_id, intermediate_process_imageset_id, determine_leak, leak_type, intermediate_raster_type, intermediate_raster_id):
    try:
        simulation = worsica_portal_models.Simulation.objects.get(id=simulation_id, aos__id=roi_id)
        ld = worsica_portal_models.LeakDetection.objects.get(id=leak_detection_id)
        reqGET = requests.get('http://'+settings.WORSICA_INTERMEDIATE_URL+'/api/job_submissions/'+str(simulation.job_submission_id)+'/leak_detections/'+str(ld.interm_leak_detection_id) +
                              '/processimageset/'+str(intermediate_process_imageset_id)+'/'+determine_leak+'/'+leak_type+'/'+str(intermediate_raster_type)+'/'+str(intermediate_raster_id))
        show_simulation = reqGET.json()
        show_simulation['response']['url'] = request.build_absolute_uri(
            '/portal/proxy/intermediate'+show_simulation['response']['url'])  # raster/tiles/'+str(intermediate_raster_id))
        show_simulation['simulation_id'] = simulation_id
        return HttpResponse(json.dumps(show_simulation), content_type='application/json')

    except Exception as e:
        return HttpResponse(json.dumps({'state': 'error', 'roi_id': roi_id, 'id': simulation_id, 'error': str(e)}), content_type='application/json')


@login_required
def show_simulation_procimageset_raster_leakdetection_leakpoints(request, roi_id, simulation_id, leak_detection_id, intermediate_process_imageset_id, determine_leak, leak_type, intermediate_raster_type, intermediate_raster_id):
    try:
        simulation = worsica_portal_models.Simulation.objects.get(id=simulation_id, aos__id=roi_id)
        ld = worsica_portal_models.LeakDetection.objects.get(id=leak_detection_id)
        reqGET = requests.get('http://'+settings.WORSICA_INTERMEDIATE_URL+'/api/job_submissions/'+str(simulation.job_submission_id)+'/leak_detections/'+str(ld.interm_leak_detection_id)+'/processimageset/' +
                              str(intermediate_process_imageset_id)+'/'+determine_leak+'/'+leak_type+'/'+str(intermediate_raster_type)+'/'+str(intermediate_raster_id)+'/leak_points/show', params=request.GET)
        show_simulation = reqGET.json()
        return HttpResponse(json.dumps(show_simulation), content_type='application/json')
    except Exception as e:
        return HttpResponse(json.dumps({'state': 'error', 'roi_id': roi_id, 'id': simulation_id, 'error': str(e)}), content_type='application/json')


@login_required
def download_simulation_procimageset_raster_leakdetection_leakpoints(request, roi_id, simulation_id, leak_detection_id, intermediate_process_imageset_id, determine_leak, leak_type, intermediate_raster_type, intermediate_raster_id):
    try:
        simulation = worsica_portal_models.Simulation.objects.get(id=simulation_id, aos__id=roi_id)
        ld = worsica_portal_models.LeakDetection.objects.get(id=leak_detection_id)
        reqGET = requests.get('http://'+settings.WORSICA_INTERMEDIATE_URL+'/api/job_submissions/'+str(simulation.job_submission_id)+'/leak_detections/'+str(ld.interm_leak_detection_id)+'/processimageset/' +
                              str(intermediate_process_imageset_id)+'/'+determine_leak+'/'+leak_type+'/'+str(intermediate_raster_type)+'/'+str(intermediate_raster_id)+'/leak_points/download', params=request.GET)
        show_request = reqGET.json()
        response = HttpResponse(show_request['kml'],
                                content_type='application/vnd.google-earth.kml+xml')
        response['Content-Disposition'] = 'attachment; filename="{0}"'.format(
            simulation.aos.name+'-'+show_request['filename'])
        return response
    except Exception as e:
        return HttpResponse(json.dumps({'state': 'error', 'roi_id': roi_id, 'id': simulation_id, 'error': str(e)}), content_type='application/json')


@login_required
def change_simulation_procimageset_raster_leakdetection_leakpoint(request, roi_id, simulation_id, leak_detection_id, intermediate_process_imageset_id, determine_leak, leak_type, intermediate_raster_type, intermediate_raster_id, leak_point_id):
    try:
        simulation = worsica_portal_models.Simulation.objects.get(id=simulation_id, aos__id=roi_id)
        ld = worsica_portal_models.LeakDetection.objects.get(id=leak_detection_id)
        reqGET = requests.get('http://'+settings.WORSICA_INTERMEDIATE_URL+'/api/job_submissions/'+str(simulation.job_submission_id)+'/leak_detections/'+str(ld.interm_leak_detection_id)+'/processimageset/'+str(
            intermediate_process_imageset_id)+'/'+determine_leak+'/'+leak_type+'/'+str(intermediate_raster_type)+'/'+str(intermediate_raster_id)+'/leak_points/'+str(leak_point_id)+'/change_visibility', params=request.GET)
        show_simulation = reqGET.json()
        return HttpResponse(json.dumps(show_simulation), content_type='application/json')
    except Exception as e:
        return HttpResponse(json.dumps({'state': 'error', 'roi_id': roi_id, 'id': simulation_id, 'error': str(e)}), content_type='application/json')

# leak detection user chosen procimageset


@login_required
def show_simulation_ucprocimageset_raster_leakdetection(request, roi_id, simulation_id, leak_detection_id, intermediate_ucprocess_imageset_id, determine_leak, leak_type, intermediate_raster_type, intermediate_raster_id):
    try:
        simulation = worsica_portal_models.Simulation.objects.get(id=simulation_id, aos__id=roi_id)
        ld = worsica_portal_models.LeakDetection.objects.get(id=leak_detection_id)
        reqGET = requests.get('http://'+settings.WORSICA_INTERMEDIATE_URL+'/api/job_submissions/'+str(simulation.job_submission_id)+'/leak_detections/'+str(ld.interm_leak_detection_id) +
                              '/ucprocessimageset/'+str(intermediate_ucprocess_imageset_id)+'/'+determine_leak+'/'+leak_type+'/'+str(intermediate_raster_type)+'/'+str(intermediate_raster_id))
        show_simulation = reqGET.json()
        show_simulation['response']['url'] = request.build_absolute_uri(
            '/portal/proxy/intermediate'+show_simulation['response']['url'])  # raster/tiles/'+str(intermediate_raster_id))
        show_simulation['simulation_id'] = simulation_id
        return HttpResponse(json.dumps(show_simulation), content_type='application/json')

    except Exception as e:
        return HttpResponse(json.dumps({'state': 'error', 'roi_id': roi_id, 'id': simulation_id, 'error': str(e)}), content_type='application/json')


@login_required
def show_simulation_ucprocimageset_raster_leakdetection_leakpoints(request, roi_id, simulation_id, leak_detection_id, intermediate_ucprocess_imageset_id, determine_leak, leak_type, intermediate_raster_type, intermediate_raster_id):
    try:
        simulation = worsica_portal_models.Simulation.objects.get(id=simulation_id, aos__id=roi_id)
        ld = worsica_portal_models.LeakDetection.objects.get(id=leak_detection_id)
        reqGET = requests.get('http://'+settings.WORSICA_INTERMEDIATE_URL+'/api/job_submissions/'+str(simulation.job_submission_id)+'/leak_detections/'+str(ld.interm_leak_detection_id)+'/ucprocessimageset/' +
                              str(intermediate_ucprocess_imageset_id)+'/'+determine_leak+'/'+leak_type+'/'+str(intermediate_raster_type)+'/'+str(intermediate_raster_id)+'/leak_points/show', params=request.GET)
        show_simulation = reqGET.json()
        return HttpResponse(json.dumps(show_simulation), content_type='application/json')
    except Exception as e:
        return HttpResponse(json.dumps({'state': 'error', 'roi_id': roi_id, 'id': simulation_id, 'error': str(e)}), content_type='application/json')


@login_required
def download_simulation_ucprocimageset_raster_leakdetection_leakpoints(request, roi_id, simulation_id, leak_detection_id, intermediate_ucprocess_imageset_id, determine_leak, leak_type, intermediate_raster_type, intermediate_raster_id):
    try:
        simulation = worsica_portal_models.Simulation.objects.get(id=simulation_id, aos__id=roi_id)
        ld = worsica_portal_models.LeakDetection.objects.get(id=leak_detection_id)
        reqGET = requests.get('http://'+settings.WORSICA_INTERMEDIATE_URL+'/api/job_submissions/'+str(simulation.job_submission_id)+'/leak_detections/'+str(ld.interm_leak_detection_id)+'/ucprocessimageset/' +
                              str(intermediate_ucprocess_imageset_id)+'/'+determine_leak+'/'+leak_type+'/'+str(intermediate_raster_type)+'/'+str(intermediate_raster_id)+'/leak_points/download', params=request.GET)
        show_request = reqGET.json()
        response = HttpResponse(show_request['kml'],
                                content_type='application/vnd.google-earth.kml+xml')
        response['Content-Disposition'] = 'attachment; filename="{0}"'.format(
            simulation.aos.name+'-'+show_request['filename'])
        return response
    except Exception as e:
        return HttpResponse(json.dumps({'state': 'error', 'roi_id': roi_id, 'id': simulation_id, 'error': str(e)}), content_type='application/json')


# -----------------------------------
@login_required
def show_simulation_procimageset_raster(request, roi_id, simulation_id, intermediate_process_imageset_id, intermediate_raster_type, intermediate_raster_id):
    try:
        simulation = worsica_portal_models.Simulation.objects.get(id=simulation_id, aos__id=roi_id)
        reqGET = requests.get('http://'+settings.WORSICA_INTERMEDIATE_URL+'/api/job_submissions/'+str(simulation.job_submission_id) +
                              '/processimageset/'+str(intermediate_process_imageset_id)+'/'+str(intermediate_raster_type)+'/'+str(intermediate_raster_id))
        show_simulation = reqGET.json()
        show_simulation['response']['url'] = request.build_absolute_uri(
            '/portal/proxy/intermediate'+show_simulation['response']['url'])  # raster/tiles/'+str(intermediate_raster_id))
        show_simulation['simulation_id'] = simulation_id
        return HttpResponse(json.dumps(show_simulation), content_type='application/json')

    except Exception as e:
        return HttpResponse(json.dumps({'state': 'error', 'roi_id': roi_id, 'id': simulation_id, 'error': str(e)}), content_type='application/json')


@login_required
def show_simulation_procimageset_raster_histogram(request, roi_id, simulation_id, intermediate_process_imageset_id, intermediate_raster_type, intermediate_raster_id):
    try:
        simulation = worsica_portal_models.Simulation.objects.get(id=simulation_id, aos__id=roi_id)
        reqGET = requests.get('http://'+settings.WORSICA_INTERMEDIATE_URL+'/api/job_submissions/'+str(simulation.job_submission_id)+'/processimageset/' +
                              str(intermediate_process_imageset_id)+'/'+str(intermediate_raster_type)+'/'+str(intermediate_raster_id)+'/show_histogram')
        show_simulation = reqGET.json()
        show_simulation['simulation_id'] = simulation_id
        return HttpResponse(json.dumps(show_simulation), content_type='application/json')

    except Exception as e:
        return HttpResponse(json.dumps({'state': 'error', 'roi_id': roi_id, 'id': simulation_id, 'error': str(e)}), content_type='application/json')


@login_required
def create_threshold_simulation_procimageset(request, roi_id, simulation_id, intermediate_process_imageset_id, intermediate_raster_type):
    try:
        jsonReq = json.loads(request.body.decode('utf-8'))
        simulation = worsica_portal_models.Simulation.objects.get(id=simulation_id, aos__id=roi_id)
        reqGET = requests.post('http://'+settings.WORSICA_INTERMEDIATE_URL+'/api/job_submissions/'+str(simulation.job_submission_id) +
                               '/processimageset/'+str(intermediate_process_imageset_id)+'/'+str(intermediate_raster_type)+'/create_threshold', json=jsonReq)
        show_simulation = reqGET.json()
        show_simulation['simulation_id'] = simulation_id
        return HttpResponse(json.dumps(show_simulation), content_type='application/json')

    except Exception as e:
        return HttpResponse(json.dumps({'state': 'error', 'roi_id': roi_id, 'id': simulation_id, 'error': str(e)}), content_type='application/json')


@login_required
def download_threshold_simulation_procimageset(request, roi_id, simulation_id, intermediate_process_imageset_id, intermediate_raster_type):
    try:
        CHUNK_SIZE = 5*1024*1024  # 5MB
        simulation = worsica_portal_models.Simulation.objects.get(id=simulation_id, aos__id=roi_id)
        interm_download_url = 'http://'+settings.WORSICA_INTERMEDIATE_URL+'/api/job_submissions/' + \
            str(simulation.job_submission_id)+'/processimageset/'+str(intermediate_process_imageset_id) + \
            '/'+str(intermediate_raster_type)+'/download_threshold'
        response = requests.get(interm_download_url, params=request.GET, stream=True)
        if response.status_code == 200:
            show_download = response.json()
            r = requests.get(show_download['url'], stream=True, auth=(
                show_download['user'], show_download['pwd']))
            appropriateFileName = str(simulation.aos.name)+'-' + \
                str(simulation.name)+'-'+show_download['appropriateFileName']
            if r.status_code == 200:
                fr = FileResponse(
                    (i for i in r.iter_content(chunk_size=CHUNK_SIZE)),
                    content_type='application/zip'
                )
                fr['Content-Disposition'] = 'attachment; filename="{0}"'.format(appropriateFileName)
                return fr
            else:
                return HttpResponse(r.text)
        else:
            return HttpResponse(response.text)
    except Exception as e:
        return HttpResponse(json.dumps({'state': 'error', 'roi_id': roi_id, 'id': simulation_id, 'error': str(e)}), content_type='application/json')


@login_required
def show_simulation_procimageset_raster_climatology(request, roi_id, simulation_id, intermediate_process_imageset_id, intermediate_raster_type, intermediate_raster_id):
    try:
        simulation = worsica_portal_models.Simulation.objects.get(id=simulation_id, aos__id=roi_id)
        reqGET = requests.get('http://'+settings.WORSICA_INTERMEDIATE_URL+'/api/job_submissions/'+str(simulation.job_submission_id) +
                              '/averageprocessimageset/'+str(intermediate_process_imageset_id)+'/'+str(intermediate_raster_type)+'/'+str(intermediate_raster_id))
        show_simulation = reqGET.json()
        show_simulation['response']['url'] = request.build_absolute_uri(
            '/portal/proxy/intermediate'+show_simulation['response']['url'])  # raster/tiles/'+str(intermediate_raster_id))
        show_simulation['simulation_id'] = simulation_id
        return HttpResponse(json.dumps(show_simulation), content_type='application/json')

    except Exception as e:
        traceback.print_exc()
        return HttpResponse(json.dumps({'state': 'error', 'roi_id': roi_id, 'id': simulation_id, 'error': str(e)}), content_type='application/json')


@login_required
def show_simulation_topography_raster(request, roi_id, simulation_id, intermediate_gt_id, intermediate_raster_type, intermediate_raster_id):
    try:
        simulation = worsica_portal_models.Simulation.objects.get(id=simulation_id, aos__id=roi_id)
        reqGET = requests.get('http://'+settings.WORSICA_INTERMEDIATE_URL+'/api/job_submissions/'+str(simulation.job_submission_id) +
                              '/generatetopography/'+str(intermediate_gt_id)+'/'+str(intermediate_raster_type)+'/'+str(intermediate_raster_id))
        show_simulation = reqGET.json()
        show_simulation['response']['url'] = request.build_absolute_uri(
            '/portal/proxy/intermediate'+show_simulation['response']['url'])  # raster/tiles/'+str(intermediate_raster_id))
        show_simulation['simulation_id'] = simulation_id
        return HttpResponse(json.dumps(show_simulation), content_type='application/json')

    except Exception as e:
        return HttpResponse(json.dumps({'state': 'error', 'roi_id': roi_id, 'id': simulation_id, 'error': str(e)}), content_type='application/json')


@login_required
def proxy_get_intermediate_download_topography(request, roi_id, simulation_id, intermediate_gt_id):
    try:
        CHUNK_SIZE = 5*1024*1024  # 5MB
        simulation = worsica_portal_models.Simulation.objects.get(id=simulation_id, aos__id=roi_id)
        interm_download_url = 'http://'+settings.WORSICA_INTERMEDIATE_URL+'/api/job_submissions/' + \
            str(simulation.job_submission_id)+'/generatetopography/' + \
            str(intermediate_gt_id)+'/download_topography'
        response = requests.get(interm_download_url, params=request.GET, stream=True)
        if response.status_code == 200:
            show_download = response.json()
            r = requests.get(show_download['url'], stream=True, auth=(
                show_download['user'], show_download['pwd']))
            appropriateFileName = str(simulation.aos.name)+'-' + \
                str(simulation.name)+'-'+show_download['appropriateFileName']
            if r.status_code == 200:
                fr = FileResponse(
                    (i for i in r.iter_content(chunk_size=CHUNK_SIZE)),
                    content_type='application/zip'
                )
                fr['Content-Disposition'] = 'attachment; filename="{0}"'.format(appropriateFileName)
                return fr
            else:
                return HttpResponse(r.text)
        else:
            return HttpResponse(response.text)
    except Exception as e:
        return HttpResponse(json.dumps({'state': 'error', 'error': 'worsica-web:'+str(e)}), content_type='application/json')


@login_required
def proxy_get_intermediate_delete_topography(request, roi_id, simulation_id, intermediate_gt_id):
    try:
        simulation = worsica_portal_models.Simulation.objects.get(id=simulation_id, aos__id=roi_id)
        reqGET = requests.get('http://'+settings.WORSICA_INTERMEDIATE_URL+'/api/job_submissions/'+str(
            simulation.job_submission_id)+'/generatetopography/'+str(intermediate_gt_id)+'/delete_topography')
        show_simulation = reqGET.json()
        return HttpResponse(json.dumps(show_simulation), content_type='application/json')
    except Exception as e:
        return HttpResponse(json.dumps({'state': 'error', 'roi_id': roi_id, 'id': simulation_id, 'error': str(e)}), content_type='application/json')


@login_required
def proxy_get_intermediate_procimageset_raster(request, intermediate_path):
    try:
        procimageset_raster_url = 'http://' + \
            settings.WORSICA_INTERMEDIATE_URL+'/'+str(intermediate_path)
        response = requests.get(procimageset_raster_url, params=request.GET)
        return HttpResponse(response.content, content_type="image/png")
    except Exception as e:
        return HttpResponse(json.dumps({'state': 'error', 'error': str(e)}), content_type='application/json')


@login_required
def proxy_get_intermediate_raster_endpoint(request, intermediate_path):
    try:
        procimageset_raster_url = 'http://' + \
            settings.WORSICA_INTERMEDIATE_URL+'/'+str(intermediate_path)
        response = requests.get(procimageset_raster_url, params=request.GET)
        return HttpResponse(response.content)
    except Exception as e:
        return HttpResponse(json.dumps({'state': 'error', 'error': str(e)}), content_type='application/json')


@login_required
def proxy_get_intermediate_download_simulation_products_climatology(request, roi_id, simulation_id,  intermediate_process_imageset_id):
    try:
        CHUNK_SIZE = 5*1024*1024  # 5MB
        simulation = worsica_portal_models.Simulation.objects.get(id=simulation_id, aos__id=roi_id)
        interm_download_url = 'http://'+settings.WORSICA_INTERMEDIATE_URL+'/api/job_submissions/' + \
            str(simulation.job_submission_id)+'/averageprocessimageset/' + \
            str(intermediate_process_imageset_id)+'/download_products'
        response = requests.get(interm_download_url, params=request.GET, stream=True)
        if response.status_code == 200:
            show_download = response.json()
            r = requests.get(show_download['url'], stream=True, auth=(
                show_download['user'], show_download['pwd']))
            appropriateFileName = str(simulation.aos.name)+'-' + \
                str(simulation.name)+'-'+show_download['appropriateFileName']
            if r.status_code == 200:
                fr = FileResponse(
                    (i for i in r.iter_content(chunk_size=CHUNK_SIZE)),
                    content_type='application/zip'
                )
                fr['Content-Disposition'] = 'attachment; filename="{0}"'.format(appropriateFileName)
                return fr
            else:
                return HttpResponse(r.text)
        else:
            return HttpResponse(response.text)
    except Exception as e:
        return HttpResponse(json.dumps({'state': 'error', 'error': 'worsica-web:'+str(e)}), content_type='application/json')


@login_required
def proxy_get_intermediate_download_simulation_products(request, roi_id, simulation_id,  intermediate_process_imageset_id):
    try:
        CHUNK_SIZE = 5*1024*1024  # 5MB
        simulation = worsica_portal_models.Simulation.objects.get(id=simulation_id, aos__id=roi_id)
        interm_download_url = 'http://'+settings.WORSICA_INTERMEDIATE_URL+'/api/job_submissions/' + \
            str(simulation.job_submission_id)+'/processimageset/' + \
            str(intermediate_process_imageset_id)+'/download_products'
        response = requests.get(interm_download_url, params=request.GET, stream=True)
        if response.status_code == 200:
            show_download = response.json()
            r = requests.get(show_download['url'], stream=True, auth=(
                show_download['user'], show_download['pwd']))
            appropriateFileName = str(simulation.aos.name)+'-' + \
                str(simulation.name)+'-'+show_download['appropriateFileName']
            if r.status_code == 200:
                fr = FileResponse(
                    (i for i in r.iter_content(chunk_size=CHUNK_SIZE)),
                    content_type='application/zip'
                )
                fr['Content-Disposition'] = 'attachment; filename="{0}"'.format(appropriateFileName)
                return fr
            else:
                return HttpResponse(r.text)
        else:
            return HttpResponse(response.text)
    except Exception as e:
        return HttpResponse(json.dumps({'state': 'error', 'error': 'worsica-web:'+str(e)}), content_type='application/json')


@login_required
def waterleak_run_leak_detection(request, roi_id, simulation_id, leak_detection_id):
    try:
        simulation = worsica_portal_models.Simulation.objects.get(id=simulation_id, aos__id=roi_id)
        leakdetection = worsica_portal_models.LeakDetection.objects.get(
            id=leak_detection_id, simulation=simulation)
        reqGET = requests.get('http://'+settings.WORSICA_INTERMEDIATE_URL+'/api/job_submissions/'+str(
            simulation.job_submission_id)+'/leak_detections/'+str(leakdetection.interm_leak_detection_id)+'/run')
        run_ld = reqGET.json()
        return HttpResponse(json.dumps(run_ld), content_type='application/json')

    except Exception as e:
        return HttpResponse(json.dumps({'state': 'error', 'roi_id': roi_id, 'id': simulation_id, 'leak_detection_id': leak_detection_id, 'error': str(e)}), content_type='application/json')


@login_required
def waterleak_run_leak_detection_identify_leaks(request, roi_id, simulation_id, leak_detection_id):
    try:
        simulation = worsica_portal_models.Simulation.objects.get(id=simulation_id, aos__id=roi_id)
        leakdetection = worsica_portal_models.LeakDetection.objects.get(
            id=leak_detection_id, simulation=simulation)
        reqGET = requests.get('http://'+settings.WORSICA_INTERMEDIATE_URL+'/api/job_submissions/'+str(
            simulation.job_submission_id)+'/leak_detections/'+str(leakdetection.interm_leak_detection_id)+'/run_identify_leaks')
        run_ld2 = reqGET.json()
        return HttpResponse(json.dumps(run_ld2), content_type='application/json')

    except Exception as e:
        return HttpResponse(json.dumps({'state': 'error', 'roi_id': roi_id, 'id': simulation_id, 'leak_detection_id': leak_detection_id, 'error': str(e)}), content_type='application/json')


@login_required
def waterleak_get_user_leak_points(request, roi_id, simulation_id, leak_detection_id):
    try:
        simulation = worsica_portal_models.Simulation.objects.get(id=simulation_id, aos__id=roi_id)
        leakdetection = worsica_portal_models.LeakDetection.objects.get(
            id=leak_detection_id, simulation=simulation)
        reqGET = requests.get('http://'+settings.WORSICA_INTERMEDIATE_URL+'/api/job_submissions/'+str(
            simulation.job_submission_id)+'/leak_detections/'+str(leakdetection.interm_leak_detection_id)+'/get_user_leak_points')
        get_ulds = reqGET.json()
        return HttpResponse(json.dumps(get_ulds), content_type='application/json')

    except Exception as e:
        return HttpResponse(json.dumps({'state': 'error', 'roi_id': roi_id, 'id': simulation_id, 'leak_detection_id': leak_detection_id, 'error': str(e)}), content_type='application/json')


@login_required
def waterleak_save_user_leak_points(request, roi_id, simulation_id, leak_detection_id):
    try:
        request.encoding = 'utf-8'
        jsonReq = json.loads(request.body.decode('utf-8'))
        rois = get_user_rois(request)
        # check if you are not trying to cheat the system
        roi = get_user_roi(rois, roi_id)  # rois.get(pk = roi_id)
        simulation = worsica_portal_models.Simulation.objects.get(aos=roi, pk=simulation_id)
        leakdetection = worsica_portal_models.LeakDetection.objects.get(
            simulation=simulation, id=leak_detection_id)

        createdUserLeak = []
        failedCreation = False
        payload = jsonReq

        reqPOST = requests.post('http://'+settings.WORSICA_INTERMEDIATE_URL+'/api/job_submissions/'+str(simulation.job_submission_id) +
                                '/leak_detections/'+str(leakdetection.interm_leak_detection_id)+'/save_user_leak_points', json=payload)
        cs = reqPOST.json()
        print(cs)
        if cs['alert'] == 'created':
            s = cs['user_leak']
            # if success, update simulation_id
            createdUserLeak.append(s)
        else:
            failedCreation = True
            createdUserLeak = []

        print(failedCreation)
        if (failedCreation):
            return HttpResponse(json.dumps({"alert": "error", "exception": "Error on editing leak detection!"}), content_type='application/json')
        else:
            return HttpResponse(json.dumps({"alert": "submitted", "simulation_id": simulation.id, "leak_detection_id": leakdetection.id, "leak_detections": createdUserLeak}), content_type='application/json')

    except Exception as e:
        return HttpResponse(json.dumps({"alert": "error", "exception": "worsica-web:"+str(e)}), content_type='application/json')


@login_required
def waterleak_show_leak_points(request, roi_id, simulation_id, leak_detection_id):
    try:
        simulation = worsica_portal_models.Simulation.objects.get(id=simulation_id, aos__id=roi_id)
        leakdetection = worsica_portal_models.LeakDetection.objects.get(
            id=leak_detection_id, simulation=simulation)
        reqGET = requests.get('http://'+settings.WORSICA_INTERMEDIATE_URL+'/api/job_submissions/'+str(simulation.job_submission_id) +
                              '/leak_detections/'+str(leakdetection.interm_leak_detection_id)+'/show_leak_points', params=request.GET)
        get_lps = reqGET.json()
        return HttpResponse(json.dumps(get_lps), content_type='application/json')

    except Exception as e:
        return HttpResponse(json.dumps({'state': 'error', 'roi_id': roi_id, 'id': simulation_id, 'leak_detection_id': leak_detection_id, 'error': str(e)}), content_type='application/json')


@login_required
def waterleak_show_user_leak_point(request, roi_id, simulation_id, leak_detection_id):
    try:
        simulation = worsica_portal_models.Simulation.objects.get(id=simulation_id, aos__id=roi_id)
        leakdetection = worsica_portal_models.LeakDetection.objects.get(
            id=leak_detection_id, simulation=simulation)
        reqGET = requests.get('http://'+settings.WORSICA_INTERMEDIATE_URL+'/api/job_submissions/'+str(simulation.job_submission_id) +
                              '/leak_detections/'+str(leakdetection.interm_leak_detection_id)+'/show_user_leak_point', params=request.GET)
        get_lps = reqGET.json()
        return HttpResponse(json.dumps(get_lps), content_type='application/json')

    except Exception as e:
        return HttpResponse(json.dumps({'state': 'error', 'roi_id': roi_id, 'id': simulation_id, 'leak_detection_id': leak_detection_id, 'error': str(e)}), content_type='application/json')


@login_required
def waterleak_delete_user_leak_points(request, roi_id, simulation_id, leak_detection_id):
    try:
        simulation = worsica_portal_models.Simulation.objects.get(id=simulation_id, aos__id=roi_id)
        leakdetection = worsica_portal_models.LeakDetection.objects.get(
            id=leak_detection_id, simulation=simulation)
        reqGET = requests.get('http://'+settings.WORSICA_INTERMEDIATE_URL+'/api/job_submissions/'+str(simulation.job_submission_id) +
                              '/leak_detections/'+str(leakdetection.interm_leak_detection_id)+'/delete_user_leak_points', params=request.GET)
        get_lps = reqGET.json()
        return HttpResponse(json.dumps(get_lps), content_type='application/json')

    except Exception as e:
        return HttpResponse(json.dumps({'state': 'error', 'roi_id': roi_id, 'id': simulation_id, 'leak_detection_id': leak_detection_id, 'error': str(e)}), content_type='application/json')


@login_required
def waterleak_delete_a_user_leak_point(request, roi_id, simulation_id, leak_detection_id):
    try:
        simulation = worsica_portal_models.Simulation.objects.get(id=simulation_id, aos__id=roi_id)
        leakdetection = worsica_portal_models.LeakDetection.objects.get(
            id=leak_detection_id, simulation=simulation)
        reqGET = requests.get('http://'+settings.WORSICA_INTERMEDIATE_URL+'/api/job_submissions/'+str(simulation.job_submission_id) +
                              '/leak_detections/'+str(leakdetection.interm_leak_detection_id)+'/delete_a_user_leak_point', params=request.GET)
        get_lps = reqGET.json()
        return HttpResponse(json.dumps(get_lps), content_type='application/json')

    except Exception as e:
        return HttpResponse(json.dumps({'state': 'error', 'roi_id': roi_id, 'id': simulation_id, 'leak_detection_id': leak_detection_id, 'error': str(e)}), content_type='application/json')


@login_required
def waterleak_edit_user_leak_point(request, roi_id, simulation_id, leak_detection_id):
    try:
        simulation = worsica_portal_models.Simulation.objects.get(id=simulation_id, aos__id=roi_id)
        leakdetection = worsica_portal_models.LeakDetection.objects.get(
            id=leak_detection_id, simulation=simulation)
        reqGET = requests.get('http://'+settings.WORSICA_INTERMEDIATE_URL+'/api/job_submissions/'+str(simulation.job_submission_id) +
                              '/leak_detections/'+str(leakdetection.interm_leak_detection_id)+'/edit_user_leak_point', params=request.GET)
        get_lps = reqGET.json()
        return HttpResponse(json.dumps(get_lps), content_type='application/json')

    except Exception as e:
        return HttpResponse(json.dumps({'state': 'error', 'roi_id': roi_id, 'id': simulation_id, 'leak_detection_id': leak_detection_id, 'error': str(e)}), content_type='application/json')


@login_required
def waterleak_download_user_leak_point(request, roi_id, simulation_id, leak_detection_id):
    try:
        simulation = worsica_portal_models.Simulation.objects.get(id=simulation_id, aos__id=roi_id)
        leakdetection = worsica_portal_models.LeakDetection.objects.get(
            id=leak_detection_id, simulation=simulation)
        reqGET = requests.get('http://'+settings.WORSICA_INTERMEDIATE_URL+'/api/job_submissions/'+str(simulation.job_submission_id) +
                              '/leak_detections/'+str(leakdetection.interm_leak_detection_id)+'/download_user_leak_point', params=request.GET)
        show_request = reqGET.json()
        response = HttpResponse(show_request['kml'],
                                content_type='application/vnd.google-earth.kml+xml')
        response['Content-Disposition'] = 'attachment; filename="{0}"'.format(
            simulation.aos.name+'-'+show_request['filename'])
        return response

    except Exception as e:
        return HttpResponse(json.dumps({'state': 'error', 'roi_id': roi_id, 'id': simulation_id, 'leak_detection_id': leak_detection_id, 'error': str(e)}), content_type='application/json')


@login_required
def waterleak_clone_user_leak_points(request, roi_id, simulation_id, leak_detection_id):
    try:
        jsonReq = json.loads(request.body.decode('utf-8'))
        simulation = worsica_portal_models.Simulation.objects.get(id=simulation_id, aos__id=roi_id)
        leakdetection = worsica_portal_models.LeakDetection.objects.get(
            id=leak_detection_id, simulation=simulation)
        reqPOST = requests.post('http://'+settings.WORSICA_INTERMEDIATE_URL+'/api/job_submissions/'+str(simulation.job_submission_id) +
                                '/leak_detections/'+str(leakdetection.interm_leak_detection_id)+'/clone_user_leak_points', json=jsonReq)
        get_lps = reqPOST.json()
        return HttpResponse(json.dumps(get_lps), content_type='application/json')

    except Exception as e:
        return HttpResponse(json.dumps({'state': 'error', 'roi_id': roi_id, 'id': simulation_id, 'leak_detection_id': leak_detection_id, 'error': str(e)}), content_type='application/json')


@login_required
def run_simulation(request, roi_id, simulation_id):
    try:
        simulation = worsica_portal_models.Simulation.objects.get(id=simulation_id, aos__id=roi_id)
        reqGET = requests.get('http://'+settings.WORSICA_INTERMEDIATE_URL +
                              '/api/job_submissions/'+str(simulation.job_submission_id)+'/run')
        run_simulation = reqGET.json()
        return HttpResponse(json.dumps(run_simulation), content_type='application/json')

    except Exception as e:
        return HttpResponse(json.dumps({'state': 'error', 'roi_id': roi_id, 'id': simulation_id, 'error': str(e)}), content_type='application/json')


@login_required
def restart_simulation(request, roi_id, simulation_id):
    try:
        simulation = worsica_portal_models.Simulation.objects.get(id=simulation_id, aos__id=roi_id)
        reqGET = requests.get('http://'+settings.WORSICA_INTERMEDIATE_URL +
                              '/api/job_submissions/'+str(simulation.job_submission_id)+'/restart')
        restart_simulation = reqGET.json()
        return HttpResponse(json.dumps(restart_simulation), content_type='application/json')

    except Exception as e:
        return HttpResponse(json.dumps({'state': 'error', 'roi_id': roi_id, 'id': simulation_id, 'error': str(e)}), content_type='application/json')


@login_required
def update_simulation(request, roi_id, simulation_id):
    try:
        simulation = worsica_portal_models.Simulation.objects.get(id=simulation_id, aos__id=roi_id)
        reqGET = requests.get('http://'+settings.WORSICA_INTERMEDIATE_URL +
                              '/api/job_submissions/'+str(simulation.job_submission_id)+'/update')
        update_simulation = reqGET.json()
        return HttpResponse(json.dumps(update_simulation), content_type='application/json')

    except Exception as e:
        return HttpResponse(json.dumps({'state': 'error', 'roi_id': roi_id, 'id': simulation_id, 'error': str(e)}), content_type='application/json')


@login_required
def stop_simulation(request, roi_id, simulation_id):
    try:
        simulation = worsica_portal_models.Simulation.objects.get(id=simulation_id, aos__id=roi_id)
        reqGET = requests.get('http://'+settings.WORSICA_INTERMEDIATE_URL +
                              '/api/job_submissions/'+str(simulation.job_submission_id)+'/stop')
        stop_simulation = reqGET.json()
        return HttpResponse(json.dumps(stop_simulation), content_type='application/json')

    except Exception as e:
        return HttpResponse(json.dumps({'state': 'error', 'roi_id': roi_id, 'id': simulation_id, 'error': str(e)}), content_type='application/json')


@login_required
# this is just to fake a run, just import directly
def delete_simulation(request, roi_id, simulation_id):
    try:
        simulation = worsica_portal_models.Simulation.objects.get(id=simulation_id, aos__id=roi_id)
        is_owned_by_user = (simulation.aos.user.id == request.user.id)
        if not is_owned_by_user:
            return HttpResponse(json.dumps({"alert": "error", 'roi_id': roi_id, 'id': simulation_id, 'error': "You do not own this simulation, thus have no permissions to delete!"}), content_type='application/json')
        else:
            reqGET = requests.get('http://'+settings.WORSICA_INTERMEDIATE_URL +
                                  '/api/job_submissions/'+str(simulation.job_submission_id)+'/delete')
            delete_simulation = reqGET.json()
            if (delete_simulation['state'] == 'deleted'):
                simulation.delete()
            return HttpResponse(json.dumps({'alert': 'deleted', 'roi_id': roi_id, 'id': simulation_id}), content_type='application/json')

    except Exception as e:
        return HttpResponse(json.dumps({'alert': 'error', 'roi_id': roi_id, 'id': simulation_id, 'error': str(e)}), content_type='application/json')

# WATERLEAK DETECTION


def waterleak_get_list_rois(request):
    jrois = []
    for aos in worsica_portal_models.AreaOfStudy.objects.filter(user=request.user.id, service='waterleak', is_visible=True):
        jrois.append({
            'roi_id': aos.id,
            'service': aos.service,
            'name': aos.name,
            'color': aos.color
        })
    return HttpResponse(json.dumps(jrois), content_type='application/json')


def waterleak_get_compatible_pipe_networks(request, roi_id):
    pipe_networks = []
    aos = worsica_portal_models.AreaOfStudy.objects.get(id=roi_id)
    uY = aos.upperYcoordinate
    uX = aos.upperXcoordinate
    lY = aos.lowerYcoordinate
    lX = aos.lowerXcoordinate
    _url = 'http://'+settings.WORSICA_INTERMEDIATE_URL+'/api/user_repository/user' + \
        str(request.user.id)+'/list?service_type=waterleak'
    _url += '&roi_polygon='+str(uY)+'|'+str(uX)+'|'+str(lY)+'|'+str(lX)
    reqGET = requests.get(_url)
    j = reqGET.json()
    if (j['alert'] != 'error'):
        pipe_networks = j['geometries']
    return HttpResponse(json.dumps(pipe_networks), content_type='application/json')


def waterleak_get_list_simulations(request, roi_id):
    jsimulations = []
    for simulation in worsica_portal_models.Simulation.objects.filter(aos__id=roi_id, is_visible=True):
        if simulation.job_submission_id is not None:
            blob = json.loads(simulation.blob_text)
            reqGET = requests.get('http://'+settings.WORSICA_INTERMEDIATE_URL +
                                  '/api/job_submissions/'+str(simulation.job_submission_id)+'/details')
            show_simulation = reqGET.json()
            if show_simulation['alert'] != 'error':
                if show_simulation['state'] == 'success':
                    if ((show_simulation['leastrecentdate'] is not None) and (show_simulation['mostrecentdate'] is not None)):
                        jsimulations.append({
                            'simulation_id': simulation.id,
                            'name': simulation.name,
                            'beginDate': show_simulation['leastrecentdate'],
                            'endDate': show_simulation['mostrecentdate'],
                            'job_submission_id': simulation.job_submission_id,
                        })
                    else:
                        jsimulations.append({
                            'simulation_id': simulation.id,
                            'name': simulation.name,
                            'beginDate': blob['step2Inputs']['beginDate'],
                            'endDate': blob['step2Inputs']['endDate'],
                            'job_submission_id': simulation.job_submission_id,
                        })
    return HttpResponse(json.dumps(jsimulations), content_type='application/json')


@login_required
def waterleak_get_leak_detections(request, roi_id, simulation_id):
    jld = []
    for ld in worsica_portal_models.LeakDetection.objects.filter(simulation_id=simulation_id, is_visible=True):
        if ld.interm_leak_detection_id is not None:
            blob = json.loads(ld.blob_text)
            simulation = worsica_portal_models.Simulation.objects.get(
                id=int(blob['step1ImageSelection']['simulation_id']))
            jld.append({
                'name': ld.name,
                'id': ld.id,
                'interm_leak_detection_id': ld.interm_leak_detection_id,
                'roi_id': blob['step1ImageSelection']['roi_id'],
                'roi_name': simulation.aos.name,
                'simulation_id': blob['step1ImageSelection']['simulation_id'],
                'simulation_name': simulation.name,
                'job_submission_id': simulation.job_submission_id,
            })
    return HttpResponse(json.dumps(jld), content_type='application/json')

@login_required
def waterleak_get_leak_detection_details(request, roi_id, simulation_id, leak_detection_id):
    try:
        simulation = worsica_portal_models.Simulation.objects.get(id=simulation_id)
        ld = worsica_portal_models.LeakDetection.objects.get(
            id=leak_detection_id, simulation=simulation, is_visible=True)
        if ld.interm_leak_detection_id is not None:
            reqGET = requests.get('http://'+settings.WORSICA_INTERMEDIATE_URL+'/api/job_submissions/'+str(
                simulation.job_submission_id)+'/leak_detections/'+str(ld.interm_leak_detection_id))
            j = reqGET.json()
            if (j['alert'] != 'error'):
                j['state'] = 'loaded'
                j['leak_detection']['aos_name'] = ld.simulation.aos.name
            return HttpResponse(json.dumps(j), content_type='application/json')
    except Exception as e:
        return HttpResponse(json.dumps({'state': 'error', 'roi_id': roi_id, 'id': simulation_id, 'leak_detection_id': leak_detection_id, 'error': str(e)}), content_type='application/json')


@login_required
def waterleak_get_all_leak_detections(request):
    jld = []
    for ld in worsica_portal_models.LeakDetection.objects.filter(is_visible=True, simulation__aos__user=request.user):
        if ld.interm_leak_detection_id is not None:
            blob = json.loads(ld.blob_text)
            simulation = worsica_portal_models.Simulation.objects.get(
                id=int(blob['step1ImageSelection']['simulation_id']))
            jld.append({
                'name': ld.name,
                'id': ld.id,
                'interm_leak_detection_id': ld.interm_leak_detection_id,
                'roi_id': blob['step1ImageSelection']['roi_id'],
                'roi_name': simulation.aos.name,
                'simulation_id': blob['step1ImageSelection']['simulation_id'],
                'simulation_name': simulation.name,
                'job_submission_id': simulation.job_submission_id,
            })
    return HttpResponse(json.dumps(jld), content_type='application/json')


def waterleak_get_list_imagesets(request, roi_id, simulation_id):
    try:
        simulation = worsica_portal_models.Simulation.objects.get(id=simulation_id, is_visible=True)
        if simulation.job_submission_id is not None:
            begin_date_ld = request.GET.get('begin_date_ld')
            end_date_ld = request.GET.get('end_date_ld')
            reqGET = requests.get('http://'+settings.WORSICA_INTERMEDIATE_URL+'/api/job_submissions/' +
                                  str(simulation.job_submission_id)+'/list_imagesets', params=request.GET)
            j = reqGET.json()
            jimagesets = []
            if (j['alert'] != 'error'):
                # list imagesets
                jimagesets = [{"type": 'existing', "processState": js['processState'], "name": js['name'], "small_name": js['small_name'],
                               "id": js['id'], "date":js['sensingDate'], 'uuids':js['uuids']} for js in j['processedImagesets']]
                # list esa images
                if ((j['leastrecentdate'] is not None) and (j['mostrecentdate'] is not None)):
                    dtjleastrecentdate = datetime.datetime.strptime(
                        j['leastrecentdate'], '%Y-%m-%d')-datetime.timedelta(days=1)
                    dtjmostrecentdate = datetime.datetime.strptime(
                        j['mostrecentdate'], '%Y-%m-%d')+datetime.timedelta(days=1)
                    dtbegin_date_ld = datetime.datetime.strptime(begin_date_ld, '%Y-%m-%d')
                    dtend_date_ld = datetime.datetime.strptime(end_date_ld, '%Y-%m-%d')
                    dtleastrecentdate = min(dtjleastrecentdate, dtend_date_ld)
                    dtmostrecentdate = max(dtjmostrecentdate, dtbegin_date_ld)
                    uX, uY = simulation.aos.upperXcoordinate, simulation.aos.upperYcoordinate
                    lX, lY = simulation.aos.lowerXcoordinate, simulation.aos.lowerYcoordinate
                    minCloudCov, maxCloudCov = 0, 100
                    platformname = 'Sentinel-2'
                    level = "Level-1C,Level-2A"
                    esaFail = False
                    esaFail1 = False
                    esaFail2 = False
                    if dtbegin_date_ld < dtleastrecentdate:
                        # search before least recent
                        print('===========ESA search before least recent=============')
                        bD, eD = dtbegin_date_ld.strftime('%Y%m%d').replace(
                            "-", ""), dtleastrecentdate.strftime('%Y%m%d').replace("-", "")
                        try:
                            imageryJson = _start_esa_imagery_search(
                                bD, eD, uX, uY, lX, lY, minCloudCov, maxCloudCov, platformname, level, None)
                            sorted_imageryJson = sorted(imageryJson, key=itemgetter('date'))
                            for key, group in itertools.groupby(sorted_imageryJson, key=lambda x: x['date']):
                                lgroup = list(group)
                                key_ymd = key.split(' ')[0].replace("-", "")
                                jimagesets.append({
                                    "type": "new",
                                    "processState": None,
                                    "name": "esa_images_"+str(key_ymd),
                                    "small_name": "ESA images of "+str(key_ymd),
                                    "id": None,
                                    "date": str(key),
                                    "uuids": [i['uuid'] for i in lgroup],
                                    "esa_imagesets": [{
                                            'uuid': i['uuid'],
                                            'name':i['name'],
                                            'small_name':'Sentinel-2 '+i['processinglevel']+' ('+i['tilenumber']+') ('+i['date'].split('.')[0]+')',
                                            'convertToL2A': (False if i['processinglevel'] == 'Level-2A' else True)
                                    } for i in lgroup]
                                })
                        except Exception as e:
                            print('===========FAIL ESA search before least recent=============')
                            esaFail1 = True
                            pass

                    if dtend_date_ld > dtmostrecentdate:
                        print('dtend_date_ld='+str(dtend_date_ld))
                        print('dtmostrecentdate='+str(dtmostrecentdate))

                        # search after most recent
                        print('================ESA search after most recent=====================')
                        bD, eD = dtmostrecentdate.strftime('%Y%m%d').replace(
                            "-", ""), dtend_date_ld.strftime('%Y%m%d').replace("-", "")
                        try:
                            imageryJson = _start_esa_imagery_search(
                                bD, eD, uX, uY, lX, lY, minCloudCov, maxCloudCov, platformname, level, None)
                            sorted_imageryJson = sorted(imageryJson, key=itemgetter('date'))
                            for key, group in itertools.groupby(sorted_imageryJson, key=lambda x: x['date']):
                                lgroup = list(group)
                                key_ymd = key.split(' ')[0].replace("-", "")  # 20210213
                                jimagesets.append({
                                    "type": "new",
                                    "processState": None,
                                    "name": "esa_images_"+str(key_ymd),
                                    "small_name": "ESA images of "+str(key_ymd),
                                    "id": None,
                                    "date": str(key),
                                    "uuids": [i['uuid'] for i in lgroup],
                                    "esa_imagesets": [{
                                            'uuid': i['uuid'],
                                            'name':i['name'],
                                            'small_name':'Sentinel-2 '+i['processinglevel']+' ('+i['tilenumber']+') ('+i['date'].split('.')[0]+')',
                                            'convertToL2A': (False if i['processinglevel'] == 'Level-2A' else True)
                                    } for i in lgroup]
                                })
                        except Exception as e:
                            print('================FAIL ESA search after most recent=====================')
                            esaFail2 = True
                            pass

                esaFail = (esaFail1 or esaFail2)  # if one of queries fail, throw error
                jimagesets = sorted(jimagesets, key=itemgetter('date'), reverse=True)

                return HttpResponse(json.dumps({'state': 'success', 'leastrecentdate': j['leastrecentdate'], 'mostrecentdate': j['mostrecentdate'], 'imagesets': jimagesets, 'esaFail': esaFail}), content_type='application/json')
            else:
                return HttpResponse(json.dumps({'state': 'error', 'roi_id': roi_id, 'id': simulation_id, 'job_submission_id': j['job_submission_id'], 'response': j['response']}), content_type='application/json')
        else:
            return HttpResponse(json.dumps({'state': 'error', 'roi_id': roi_id, 'id': simulation_id, 'error': 'Job submission not found'}), content_type='application/json')
    except Exception as e:
        print(traceback.format_exc())
        return HttpResponse(json.dumps({'state': 'error', 'roi_id': roi_id, 'id': simulation_id, 'error': str(e)}), content_type='application/json')


def waterleak_get_list_imageset_indexes(request, roi_id, simulation_id, intermediate_process_imageset_id):
    pass

# USER REPOSITORY


@login_required
def proxy_intermediate_show_user_repository(request, service_type):
    user_id = request.user.id
    try:
        reqGET = requests.get('http://'+settings.WORSICA_INTERMEDIATE_URL +
                              '/api/user_repository/user'+str(user_id)+'/'+service_type+'/show')
        response = reqGET.json()
        return HttpResponse(json.dumps(response), content_type='application/json')
    except Exception as e:
        return HttpResponse(json.dumps({'alert': 'error', 'error': str(e)}), content_type='application/json')


@login_required
def proxy_intermediate_preview_user_repository_geometry(request, service_type):
    user_id = request.user.id
    if request.method == 'POST':
        try:
            myfile = request.FILES['myfile']
            myfilenametmp = myfile.file.name  # file path name
            myfilename = slugify(myfile.name.split('.')[0])
            print('filename: '+myfilename)
            print('tmpfile: '+str(myfilenametmp))
            if not myfilenametmp.endswith('.zip'):
                return HttpResponse(json.dumps({'alert': 'error', 'message': 'Error on upload: File extension is not zip'}), content_type='application/json')
            else:
                zf = zipfile.ZipFile(myfilenametmp, 'r')
                hasSHP, hasDBF, hasSHX = False, False, False
                for file_name in zf.namelist():
                    if file_name.endswith('.shp'):
                        hasSHP = True
                    if file_name.endswith('.dbf'):
                        hasDBF = True
                    if file_name.endswith('.shx'):
                        hasSHX = True
                if (hasSHP and hasDBF and hasSHX):
                    print('[proxy_intermediate_preview_user_repository_geometry]: start upload')
                    print(
                        '[proxy_intermediate_preview_user_repository_geometry]: upload file directly to worsica intermediate')
                    f = open(myfilenametmp, 'rb')
                    files = {'myfile': f}
                    reqPOST = requests.post('http://'+settings.WORSICA_INTERMEDIATE_URL+'/api/user_repository/user'+str(
                        user_id)+'/'+service_type+'/geometries/preview', files=files)
                    response = reqPOST.json()
                    print('[proxy_intermediate_preview_user_repository_geometry]: success')
                    f.close()
                    os.remove(myfilenametmp)
                    return HttpResponse(json.dumps(response), content_type='application/json')

                else:
                    raise Exception(
                        'Sorry, this ZIP file must have at least shp, dbf and shx files.')

        except Exception as e:
            print(traceback.format_exc())
            os.remove(myfilenametmp)
            return HttpResponse(json.dumps({'alert': 'error', 'message': 'An error occured during upload', 'details': str(e)}), content_type='application/json')
    else:
        return HttpResponse(json.dumps({'alert': 'error', 'message': 'Not a POST request, abort'}), content_type='application/json')


@login_required
def proxy_intermediate_upload_user_repository_geometry(request, service_type):
    user_id = request.user.id
    if request.method == 'POST':
        try:
            _create_user_repository_frontend(user_id)
            myfile = request.FILES['myfile']
            myfilenametmp = myfile.file.name  # file path name
            myfilename = slugify(myfile.name.split('.')[0])
            print('filename: '+myfilename)
            print('tmpfile: '+str(myfilenametmp))
            if not myfilenametmp.endswith('.zip'):
                return HttpResponse(json.dumps({'alert': 'error', 'message': 'Error on upload: File extension is not zip'}), content_type='application/json')
            else:
                zf = zipfile.ZipFile(myfilenametmp, 'r')
                hasSHP, hasDBF, hasSHX = False, False, False
                for file_name in zf.namelist():
                    if file_name.endswith('.shp'):
                        hasSHP = True
                    if file_name.endswith('.dbf'):
                        hasDBF = True
                    if file_name.endswith('.shx'):
                        hasSHX = True
                if (hasSHP and hasDBF and hasSHX):
                    print('[proxy_intermediate_upload_user_repository_geometry]: start upload')
                    print(
                        '[proxy_intermediate_upload_user_repository_geometry]: upload file directly to nextcloud')
                    auth = (nextcloud_access.NEXTCLOUD_USER, nextcloud_access.NEXTCLOUD_PWD)
                    with open(myfilenametmp, 'rb') as f:
                        r = requests.put(nextcloud_access.NEXTCLOUD_URL_PATH+'/user_repository/user'+str(
                            user_id)+'/geometries/'+service_type+'/'+myfilename+'.zip', data=f, auth=auth)
                        if (r.status_code == 201 or r.status_code == 204):
                            print('[proxy_intermediate_upload_user_repository_geometry]: upload successful')
                            print(
                                '[proxy_intermediate_upload_user_repository_geometry]: start storing on intermediate side')
                            payload = {'user_id': user_id,
                                       'filename': myfilename+'.zip', 'type': 'geometry'}
                            reqPOST = requests.post('http://'+settings.WORSICA_INTERMEDIATE_URL+'/api/user_repository/user'+str(
                                user_id)+'/'+service_type+'/geometries/upload', json=payload)
                            response = reqPOST.json()
                            print('[proxy_intermediate_upload_user_repository_geometry]: success')
                            return HttpResponse(json.dumps(response), content_type='application/json')
                        else:
                            print(
                                '[proxy_intermediate_upload_user_repository_geometry]: upload error '+str(r.status_code))
                            return HttpResponse(json.dumps({'alert': 'error', 'message': 'error '+str(r.status_code), 'details': 'error '+str(r.status_code)}), content_type='application/json')
                    os.remove(myfilenametmp)
                else:
                    raise Exception(
                        'Sorry, this ZIP file must have at least shp, dbf and shx files.')

        except Exception as e:
            print(traceback.format_exc())
            return HttpResponse(json.dumps({'alert': 'error', 'message': 'An error occured during upload', 'details': str(e)}), content_type='application/json')
    else:
        return HttpResponse(json.dumps({'alert': 'error', 'message': 'Not a POST request, abort'}), content_type='application/json')


@login_required
def proxy_intermediate_show_user_repository_geometry(request, service_type, geometry_id):
    user_id = request.user.id
    try:
        reqGET = requests.get('http://'+settings.WORSICA_INTERMEDIATE_URL+'/api/user_repository/user' +
                              str(user_id)+'/'+service_type+'/geometries/'+str(geometry_id))
        response = reqGET.json()
        return HttpResponse(json.dumps(response), content_type='application/json')
    except Exception as e:
        return HttpResponse(json.dumps({'alert': 'error', 'geometry_id': geometry_id, 'error': str(e)}), content_type='application/json')


@login_required
def proxy_intermediate_delete_user_repository_geometry(request, service_type, geometry_id):
    user_id = request.user.id
    try:
        reqGET = requests.get('http://'+settings.WORSICA_INTERMEDIATE_URL+'/api/user_repository/user' +
                              str(user_id)+'/'+service_type+'/geometries/'+str(geometry_id)+'/delete')
        response = reqGET.json()
        return HttpResponse(json.dumps(response), content_type='application/json')
    except Exception as e:
        return HttpResponse(json.dumps({'alert': 'error', 'geometry_id': geometry_id, 'error': str(e)}), content_type='application/json')


@login_required
def proxy_intermediate_upload_user_repository_mask(request, service_type):
    user_id = request.user.id
    if request.method == 'POST':
        try:
            _create_user_repository_frontend(user_id)
            myfile = request.FILES['myfile']
            myfilenametmp = myfile.file.name  # file path name
            myfilename = slugify(myfile.name.split('.')[0])
            print('filename: '+myfilename)
            print('tmpfile: '+str(myfilenametmp))
            print(os.path.getsize(myfilenametmp))
            if not myfilenametmp.endswith('.tif'):
                return HttpResponse(json.dumps({'alert': 'error', 'message': 'Error on upload: File extension is not tif'}), content_type='application/json')
            else:
                newfilename = myfilename+'_uploaded_by_user'
                print('[proxy_intermediate_upload_user_repository_mask]: generate zip file')
                myfilenamezip = '/tmp/'+newfilename+'.zip'
                zipfile.ZipFile(myfilenamezip, mode='w').write(
                    myfilenametmp, arcname=newfilename+'.tif', compress_type=zipfile.ZIP_DEFLATED)
                print('[proxy_intermediate_upload_user_repository_mask]: start upload')
                print('[proxy_intermediate_upload_user_repository_mask]: upload file directly to nextcloud')
                auth = (nextcloud_access.NEXTCLOUD_USER, nextcloud_access.NEXTCLOUD_PWD)
                with open(myfilenametmp, 'rb') as f:
                    r = requests.put(nextcloud_access.NEXTCLOUD_URL_PATH+'/user_repository/user' +
                                     str(user_id)+'/masks/'+service_type+'/'+newfilename+'.zip', data=f, auth=auth)
                    if (r.status_code == 201 or r.status_code == 204):
                        print('[proxy_intermediate_upload_user_repository_mask]: upload successful')
                        print(
                            '[proxy_intermediate_upload_user_repository_mask]: start storing on intermediate side')
                        payload = {'user_id': user_id,
                                   'filename': newfilename+'.zip', 'type': 'mask'}
                        reqPOST = requests.post('http://'+settings.WORSICA_INTERMEDIATE_URL+'/api/user_repository/user'+str(
                            user_id)+'/'+service_type+'/masks/upload', json=payload)
                        response = reqPOST.json()
                        print('[proxy_intermediate_upload_user_repository_mask]: success')
                        return HttpResponse(json.dumps(response), content_type='application/json')
                    else:
                        print(
                            '[proxy_intermediate_upload_user_repository_mask]: upload error '+str(r.status_code))
                        return HttpResponse(json.dumps({'alert': 'error', 'message': 'error '+str(r.status_code), 'details': 'error '+str(r.status_code)}), content_type='application/json')
                os.remove(myfilenametmp)  # delete tmp file
                os.remove(myfilenamezip)  # delete zip file

        except Exception as e:
            print(traceback.format_exc())
            return HttpResponse(json.dumps({'alert': 'error', 'message': 'An error occured during upload', 'details': str(e)}), content_type='application/json')
    else:
        return HttpResponse(json.dumps({'alert': 'error', 'message': 'Not a POST request, abort'}), content_type='application/json')


@login_required
def proxy_intermediate_show_user_repository_mask(request, service_type, mask_id, raster_id):
    user_id = request.user.id
    try:
        reqGET = requests.get('http://'+settings.WORSICA_INTERMEDIATE_URL+'/api/user_repository/user' +
                              str(user_id)+'/'+service_type+'/masks/'+str(mask_id)+'/'+str(raster_id))
        response = reqGET.json()
        response['response']['url'] = request.build_absolute_uri(
            '/portal/proxy/intermediate'+response['response']['url'])
        return HttpResponse(json.dumps(response), content_type='application/json')
    except Exception as e:
        return HttpResponse(json.dumps({'alert': 'error', 'mask_id': mask_id, 'raster_id': raster_id, 'error': str(e)}), content_type='application/json')


@login_required
def proxy_intermediate_delete_user_repository_mask(request, service_type, mask_id):
    user_id = request.user.id
    try:
        reqGET = requests.get('http://'+settings.WORSICA_INTERMEDIATE_URL+'/api/user_repository/user' +
                              str(user_id)+'/'+service_type+'/masks/'+str(mask_id)+'/delete')
        response = reqGET.json()
        return HttpResponse(json.dumps(response), content_type='application/json')
    except Exception as e:
        return HttpResponse(json.dumps({'alert': 'error', 'mask_id': mask_id, 'error': str(e)}), content_type='application/json')


@login_required
def proxy_intermediate_upload_user_repository_leak(request, service_type):
    user_id = request.user.id
    if request.method == 'POST':
        try:
            _create_user_repository_frontend(user_id)
            myfile = request.FILES['myfile']
            myfilenametmp = myfile.file.name  # file path name
            myfilename = slugify(myfile.name.split('.')[0])
            print('filename: '+myfilename)
            print('tmpfile: '+str(myfilenametmp))
            print(os.path.getsize(myfilenametmp))
            if not myfilenametmp.endswith('.kml'):
                return HttpResponse(json.dumps({'alert': 'error', 'message': 'Error on upload: File extension is not kml'}), content_type='application/json')
            else:
                newfilename = myfilename+'_uploaded_by_user'
                print('[proxy_intermediate_upload_user_repository_leak_point]: generate zip file')
                myfilenamezip = '/tmp/'+newfilename+'.zip'
                zipfile.ZipFile(myfilenamezip, mode='w').write(
                    myfilenametmp, arcname=newfilename+'.kml', compress_type=zipfile.ZIP_DEFLATED)
                print('[proxy_intermediate_upload_user_repository_leak_point]: start upload')
                print('[proxy_intermediate_upload_user_repository_leak_point]: upload file directly to nextcloud')
                auth = (nextcloud_access.NEXTCLOUD_USER, nextcloud_access.NEXTCLOUD_PWD)
                with open(myfilenametmp, 'rb') as f:
                    r = requests.put(nextcloud_access.NEXTCLOUD_URL_PATH+'/user_repository/user' +
                                     str(user_id)+'/leakpoints/'+service_type+'/'+newfilename+'.zip', data=f, auth=auth)
                    if (r.status_code == 201 or r.status_code == 204):
                        print('[proxy_intermediate_upload_user_repository_leak_point]: upload successful')
                        print(
                            '[proxy_intermediate_upload_user_repository_leak_point]: start storing on intermediate side')
                        payload = {'user_id': user_id,
                                   'filename': newfilename+'.zip', 'type': 'leakpoint'}
                        reqPOST = requests.post('http://'+settings.WORSICA_INTERMEDIATE_URL+'/api/user_repository/user'+str(
                            user_id)+'/'+service_type+'/leaks/upload', json=payload)
                        response = reqPOST.json()
                        print('[proxy_intermediate_upload_user_repository_leak_point]: success')
                        return HttpResponse(json.dumps(response), content_type='application/json')
                    else:
                        print(
                            '[proxy_intermediate_upload_user_repository_leak_point]: upload error '+str(r.status_code))
                        return HttpResponse(json.dumps({'alert': 'error', 'message': 'error '+str(r.status_code), 'details': 'error '+str(r.status_code)}), content_type='application/json')
                os.remove(myfilenametmp)  # delete tmp file
                os.remove(myfilenamezip)  # delete zip file

        except Exception as e:
            print(traceback.format_exc())
            return HttpResponse(json.dumps({'alert': 'error', 'message': 'An error occured during upload', 'details': str(e)}), content_type='application/json')
    else:
        return HttpResponse(json.dumps({'alert': 'error', 'message': 'Not a POST request, abort'}), content_type='application/json')


@login_required
def proxy_intermediate_show_user_repository_leak(request, service_type, leak_id):
    user_id = request.user.id
    try:
        reqGET = requests.get('http://'+settings.WORSICA_INTERMEDIATE_URL +
                              '/api/user_repository/user'+str(user_id)+'/'+service_type+'/leaks/'+str(leak_id))
        response = reqGET.json()
        return HttpResponse(json.dumps(response), content_type='application/json')
    except Exception as e:
        return HttpResponse(json.dumps({'alert': 'error', 'leak_id': leak_id, 'error': str(e)}), content_type='application/json')


@login_required
def proxy_intermediate_delete_user_repository_leak(request, service_type, leak_id):
    user_id = request.user.id
    try:
        reqGET = requests.get('http://'+settings.WORSICA_INTERMEDIATE_URL+'/api/user_repository/user' +
                              str(user_id)+'/'+service_type+'/leaks/'+str(leak_id)+'/delete')
        response = reqGET.json()
        return HttpResponse(json.dumps(response), content_type='application/json')
    except Exception as e:
        return HttpResponse(json.dumps({'alert': 'error', 'leak_id': leak_id, 'error': str(e)}), content_type='application/json')


@login_required
def proxy_intermediate_list_user_repository_imageset(request, service_type):
    user_id = request.user.id
    try:
        user_id = request.user.id
        # get list of uploaded prods
        roi_id = request.GET.get('roi_id')
        if not roi_id:
            raise Exception('Provide valid roi_id')
        aos = worsica_portal_models.AreaOfStudy.objects.get(id=roi_id)
        is_owned_by_user = (aos.user.id == user_id)
        if not is_owned_by_user:
            raise Exception('Defined ROI does not belong to user')

        roi_polygon = str(aos.upperYcoordinate)+'|'+str(aos.upperXcoordinate) + \
            '|'+str(aos.lowerYcoordinate)+'|'+str(aos.lowerXcoordinate)
        list_url = 'http://'+settings.WORSICA_INTERMEDIATE_URL+'/api/user_repository/user' + \
            str(user_id)+'/'+service_type+'/imagesets?roi_polygon='+roi_polygon
        reqGET = requests.get(list_url)
        j = reqGET.json()
        return HttpResponse(json.dumps(j), content_type='application/json')
    except Exception as e:
        return HttpResponse(json.dumps({'alert': 'error', 'roi_id': roi_id, 'error': str(e)}), content_type='application/json')


@login_required
def proxy_intermediate_upload_user_repository_imageset(request, service_type):
    user_id = request.user.id
    if request.method == 'POST':
        try:
            _create_user_repository_frontend(user_id)
            myfile = request.FILES['myfile']
            myfilenametmp = myfile.file.name  # file path name
            myfilename = slugify(myfile.name.split('.')[0])
            print('filename: '+myfilename)
            print('tmpfile: '+str(myfilenametmp))
            print(os.path.getsize(myfilenametmp))
            if not myfilenametmp.endswith('.zip'):
                return HttpResponse(json.dumps({'alert': 'error', 'message': 'Error on upload: File extension is not zip'}), content_type='application/json')
            else:
                # USERID_FILENAME_YYYYmmddTHHMMSS
                newfilename = 'uploaded-user'+str(user_id)+'_'+myfilename.replace('_', '-')
                print('[proxy_intermediate_upload_user_repository_imageset]: start upload')
                print('[proxy_intermediate_upload_user_repository_imageset]: upload file directly to nextcloud')
                auth = (nextcloud_access.NEXTCLOUD_USER, nextcloud_access.NEXTCLOUD_PWD)
                with open(myfilenametmp, 'rb') as f:
                    r = requests.put(nextcloud_access.NEXTCLOUD_URL_PATH+'/user_repository/user' +
                                     str(user_id)+'/imagesets/'+newfilename+'.zip', data=f, auth=auth)
                    if (r.status_code == 201 or r.status_code == 204):
                        print('[proxy_intermediate_upload_user_repository_imageset]: upload successful')
                        print(
                            '[proxy_intermediate_upload_user_repository_imageset]: start storing on intermediate side')
                        payload = {'user_id': user_id,
                                   'filename': newfilename+'.zip', 'type': 'imageset'}
                        reqPOST = requests.post('http://'+settings.WORSICA_INTERMEDIATE_URL+'/api/user_repository/user'+str(
                            user_id)+'/'+service_type+'/imagesets/upload', json=payload)
                        response = reqPOST.json()
                        print('[proxy_intermediate_upload_user_repository_imageset]: success')
                        return HttpResponse(json.dumps(response), content_type='application/json')
                    else:
                        print(
                            '[proxy_intermediate_upload_user_repository_imageset]: upload error '+str(r.status_code))
                        return HttpResponse(json.dumps({'alert': 'error', 'message': 'error '+str(r.status_code), 'details': 'error '+str(r.status_code)}), content_type='application/json')
                os.remove(myfilenametmp)  # delete tmp file
                os.remove(myfilenamezip)  # delete zip file

        except Exception as e:
            print(traceback.format_exc())
            return HttpResponse(json.dumps({'alert': 'error', 'message': 'An error occured during upload', 'details': str(e)}), content_type='application/json')
    else:
        return HttpResponse(json.dumps({'alert': 'error', 'message': 'Not a POST request, abort'}), content_type='application/json')


@login_required
def proxy_intermediate_show_user_repository_imageset(request, service_type, imageset_id):
    user_id = request.user.id
    try:
        reqGET = requests.get('http://'+settings.WORSICA_INTERMEDIATE_URL+'/api/user_repository/user' +
                              str(user_id)+'/'+service_type+'/imagesets/'+str(imageset_id))
        response = reqGET.json()
        return HttpResponse(json.dumps(response), content_type='application/json')
    except Exception as e:
        return HttpResponse(json.dumps({'alert': 'error', 'imageset_id': imageset_id, 'error': str(e)}), content_type='application/json')


@login_required
def proxy_intermediate_show_thumbnail_user_repository_imageset(request, service_type, imageset_id):
    user_id = request.user.id
    try:
        reqGET = requests.get('http://'+settings.WORSICA_INTERMEDIATE_URL+'/api/user_repository/user' +
                              str(user_id)+'/'+service_type+'/imagesets/'+str(imageset_id)+'/show_thumbnail')
        response = reqGET.json()
        print(response)
        return HttpResponse(json.dumps(response), content_type='application/json')
    except Exception as e:
        return HttpResponse(json.dumps({'alert': 'error', 'imageset_id': imageset_id, 'error': str(e)}), content_type='application/json')


@login_required
def proxy_intermediate_edit_user_repository_imageset(request, service_type, imageset_id):
    user_id = request.user.id
    try:
        jsonReq = json.loads(request.body.decode('utf-8'))
        reqPOST = requests.post('http://'+settings.WORSICA_INTERMEDIATE_URL+'/api/user_repository/user'+str(
            user_id)+'/'+service_type+'/imagesets/'+str(imageset_id)+'/edit', json=jsonReq)
        response = reqPOST.json()
        return HttpResponse(json.dumps(response), content_type='application/json')
    except Exception as e:
        return HttpResponse(json.dumps({'alert': 'error', 'imageset_id': imageset_id, 'error': str(e)}), content_type='application/json')


@login_required
def proxy_intermediate_delete_user_repository_imageset(request, service_type, imageset_id):
    user_id = request.user.id
    try:
        reqGET = requests.get('http://'+settings.WORSICA_INTERMEDIATE_URL+'/api/user_repository/user' +
                              str(user_id)+'/'+service_type+'/imagesets/'+str(imageset_id)+'/delete')
        response = reqGET.json()
        return HttpResponse(json.dumps(response), content_type='application/json')
    except Exception as e:
        return HttpResponse(json.dumps({'alert': 'error', 'imageset_id': imageset_id, 'error': str(e)}), content_type='application/json')
