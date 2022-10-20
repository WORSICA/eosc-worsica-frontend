from worsica_web import settings
from . import logger

worsica_logger = logger.init_logger('WorSiCa-Portal.ModelsBase', settings.LOG_PATH)
worsica_logger.info('worsica_portal.models_base')

from django.db.models import (
    Model, ForeignKey, BooleanField, IntegerField, CharField, SlugField,
    TextField, FloatField, SmallIntegerField, DateField, TimeField
)

class Name(Model):

    CHAR_FIELD_MAX_LENGTH = 100

    name = CharField(max_length = CHAR_FIELD_MAX_LENGTH)
    reference = SlugField(max_length = CHAR_FIELD_MAX_LENGTH)

    class Meta:
        abstract = True

    def __str__(self):
        return self.name

class Info(Model):

    description = TextField(blank = True)
    notes = TextField(blank = True)

    class Meta:
        abstract = True


class BlobTextTrait(Model):

    blob_text = TextField(blank = True)

    class Meta:
        abstract = True