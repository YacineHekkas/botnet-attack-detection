from django.urls import path
from .views import RecentEvents

urlpatterns = [
    path('api/recent/', RecentEvents.as_view(), name='recent_events'),
]
