from rest_framework.views import APIView
from rest_framework.response import Response
from django.utils import timezone
from .models import LabelEvent
from .serializers import LabelEventSerializer
from collections import Counter

class RecentEvents(APIView):
    """
    Return the last 5 minutes of events, plus an aggregate count per label.
    """
    def get(self, request):
        cutoff = timezone.now() - timezone.timedelta(minutes=5)
        qs = LabelEvent.objects.filter(timestamp__gte=cutoff)
        
        # raw events
        events = LabelEventSerializer(qs.order_by('timestamp'), many=True).data
        
        # aggregate counts
        counts = Counter([e['label'] for e in events])
        
        return Response({
            'events': events,
            'counts': counts,
        })
