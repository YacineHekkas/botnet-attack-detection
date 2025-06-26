from rest_framework import serializers
from .models import LabelEvent

class LabelEventSerializer(serializers.ModelSerializer):
    class Meta:
        model = LabelEvent
        fields = ['timestamp','label']
