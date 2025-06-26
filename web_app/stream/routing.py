from django.urls import re_path
from .consumers import LabelConsumer

websocket_urlpatterns = [
    re_path(r'ws/labels/$', LabelConsumer.as_asgi()),
]
