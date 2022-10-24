"""worsica_web URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/2.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  url(r'^$', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  url(r'^$', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.conf.urls import url, include
    2. Add a URL to urlpatterns:  url(r'^blog/', include('blog.urls'))
"""
from django.conf.urls import include, url
from django.contrib import admin

from django.http import HttpResponseRedirect
from django.views.static import serve
from worsica_portal import views

from . import settings
if not settings.DEBUG:
    from worsica_web.forms import MultiCaptchaAdminAuthenticationForm
    admin.autodiscover()
    admin.site.login_form = MultiCaptchaAdminAuthenticationForm

urlpatterns = [
    url(r'^admin/', admin.site.urls),
    url(r'^index/$', views.index, name='index'),

    url(r'^accounts/login/$', views.login, name='login'),
    url(r'^accounts/register/$', views.register, name='register'),
    url(r'^accounts/register/post/$', views.register_post, name='register_post'),
    url(
        r'^accounts/activation/(?P<uidb64>[0-9A-Za-z_\-]+)/(?P<token>[0-9A-Za-z]{1,13}-[0-9A-Za-z]{1,20})/$', views.activation, name='activation'),
    url(r'^accounts/activate/(?P<uidb64>[0-9A-Za-z_\-]+)/(?P<token>[0-9A-Za-z]{1,13}-[0-9A-Za-z]{1,20})/$',
        views.userprofile_activate, name='userprofile_activate'),
    url(r'^activate_user/(?P<username>[\w.%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,4})/$',
        views.activate_user, name='activate_user'),
    url(r'^deactivate_user/(?P<username>[\w.%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,4})/$',
        views.deactivate_user, name='deactivate_user'),

    url(r'^accounts/recovery/post/$', views.recovery_post, name='recovery_post'),
    url(r'^accounts/recovery_set_pwd/(?P<uidb64>[0-9A-Za-z_\-]+)/(?P<token>[0-9A-Za-z]{1,13}-[0-9A-Za-z]{1,20})/$',
        views.recovery_set_pwd, name='recovery_set_pwd'),
    url(r'^accounts/recovery_set_pwd/(?P<uidb64>[0-9A-Za-z_\-]+)/(?P<token>[0-9A-Za-z]{1,13}-[0-9A-Za-z]{1,20})/post/$',
        views.recovery_set_pwd_post, name='recovery_set_pwd_post'),

    url(r'^accounts/auth/$', views.auth_view, name='authenticate'),
    url(r'^accounts/logout/$', views.logout, name='logout'),

    url(r'^$', lambda r: HttpResponseRedirect('index/')),
    url(r'^portal/', include('worsica_portal.urls')),
    url(r'^auth/', include('django_auth_oidc.urls')),
    url(r'^login-egi/$', views.login_egi, name='login_egi'),
    url(r'^login-egi/complete/$', views.login_egi_complete, name='login_egi_complete'),
    url(r'^logout-egi/$', views.logout_egi, name='logout_egi'),

    url(r'^metrics/', views.metrics, name='metrics'),
    url(r'^metrics.json', views.get_json_metrics, name='get_json_metrics'),
    url(r'^metrics.xls', views.export_xls_metrics, name='export_xls_metrics'),

]

if not settings.DEBUG:
    urlpatterns += [
        url(r'^static/(?P<path>.*)$', serve, {'document_root': settings.STATIC_ROOT}),
    ]
