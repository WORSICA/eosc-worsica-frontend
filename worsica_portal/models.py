from worsica_web import settings
from . import logger

worsica_logger = logger.init_logger('WorSiCa-Portal.Models', settings.LOG_PATH)
worsica_logger.info('worsica_portal.models')

from django.db.models import (
    Model, ForeignKey, OneToOneField, ManyToManyField, BooleanField, CharField, ImageField,
    IntegerField, DateTimeField, FloatField, DecimalField, SET_NULL, CASCADE
)
#from django.contrib.gis.db import models as gis_models
from django_countries.fields import CountryField

from django.contrib.auth.models import User, Group
from django.db import models
from datetime import datetime 

from .models_base import *

from django.contrib.admin.templatetags.admin_list import _boolean_icon


class AreaOfStudy(Name, BlobTextTrait):    
    #aos-[ID]
    #workspace = ForeignKey(Workspace)
    class Service:
        INLAND = 'inland'
        COASTAL = 'coastal'
        WATERLEAK = 'waterleak'

        _CHOICES = (
            (INLAND, 'Inland Detection'),
            (COASTAL, 'Coastline Detection'),
            (WATERLEAK, 'Water-Leak Detection'),
        )
    service = CharField(editable=True, choices=Service._CHOICES, default=Service.COASTAL, max_length=40)
    user = ForeignKey(User, on_delete=CASCADE)

    shared_with = ManyToManyField(User, blank=True, related_name='shared_with_users')
    groups = ManyToManyField(Group, blank=True)
    #name = CharField(max_length = 100, default="Unnamed")

    upperXcoordinate = FloatField()
    upperYcoordinate = FloatField()
    lowerXcoordinate = FloatField()
    lowerYcoordinate = FloatField()

    color = CharField(max_length = 10, default='#00aa55')

    is_visible = BooleanField(default=True)
    is_enabled = BooleanField(default=True)

class Simulation(Name, BlobTextTrait):
    #simulation-[ID]
    aos = ForeignKey(AreaOfStudy, on_delete=CASCADE)
    #job submission
    shared_with = ManyToManyField(User, blank=True, related_name='sim_shared_with_users')
    job_submission_id = IntegerField('Intermediate Job Id', null=True, blank=True)
    is_visible = BooleanField(default=True)

class LeakDetection(Name, BlobTextTrait):
    #leakdetection-[ID]
    simulation = ForeignKey(Simulation, null=True, on_delete=CASCADE)
    #job submission
    interm_leak_detection_id = IntegerField('Intermediate Leak detection Id', null=True, blank=True)
    is_visible = BooleanField(default=True)


class UserProfile(Model):
    user = OneToOneField(User, on_delete=CASCADE)
    affiliation = CharField(max_length=100)
    affiliation_country = CountryField(blank_label='Select affiliation country')
    confirm_registration = BooleanField(default=False, verbose_name="Has confirmed registration?")
    read_disclaimer = BooleanField(default=False, verbose_name="Has accepted disclaimer?")
    #profile_picture = models.ImageField(upload_to='thumbpath', blank=True)

    def __str__(self):
        return "%s %s %s" % (str(self.user.id), self.affiliation, self.user.username)
    def username(self):
        return self.user.username
    def email(self):
        return self.user.email
    def first_name(self):
        return self.user.first_name
    def last_name(self):
        return self.user.last_name
    def is_active(self):
        return _boolean_icon(self.user.is_active)
User.profile = property(lambda u: UserProfile.objects.get_or_create(user=u)[0])
