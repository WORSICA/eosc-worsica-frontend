from worsica_web import settings
from . import logger

worsica_logger = logger.init_logger('WorSiCa-Portal.Admin', settings.LOG_PATH)
worsica_logger.info('worsica_portal.admin')

from django.contrib import admin
from django.contrib.auth.admin import UserAdmin

from .models import *
import worsica_portal.models as worsica_portal_models

# Register your models here.
@admin.register(AreaOfStudy)
class AreaOfStudyAdmin(admin.ModelAdmin):
    pass

@admin.register(Simulation)
class SimulationAdmin(admin.ModelAdmin):
    list_display = (
        'name',
        'aos',
        'job_submission_id'
    )
@admin.register(LeakDetection)
class LeakDetectionAdmin(admin.ModelAdmin):
    list_display = (
        'name',
        'simulation',
        'interm_leak_detection_id'
    )

@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    change_list_template = 'admin/user_profile.html'

    list_display = (
        'username',
        'first_name',
        'last_name',
        'affiliation',
        'affiliation_country',
        'confirm_registration',
        'is_active'
    )
    def username(self, obj):
        # Truncating long emails (e.g. EGI users)
        max_length = 20
        if len(obj.user.username) > max_length:
            return "%s..." % obj.user.username[:max_length]
        return obj.user.username
    def changelist_view(self, request, extra_context=None):
        extra_context = extra_context or {}
        if 'activate_new_user' in request.session:
            extra_context['new_user'] = request.session['activate_new_user']
            request.session.pop('activate_new_user')
        if 'activate_msg' in request.session:
            extra_context['msg'] = request.session['activate_msg']
            request.session.pop('activate_msg')
        return super().changelist_view(
            request,
            extra_context=extra_context
        )


class CustomUserAdmin(UserAdmin):
    def save_model(self, request, obj, form, change):
        print(obj)
        print(change)
        super().save_model(request, obj, form, change)
        if not change: #create userprofile if user create
            worsica_portal_models.UserProfile.objects.create(user=obj)
admin.site.unregister(User)
admin.site.register(User, CustomUserAdmin)
    
#@admin.register(SatelliteImageSet)
#class SatelliteImageSetAdmin(admin.ModelAdmin):
#    pass
