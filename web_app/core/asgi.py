import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core.settings')
# Must setup Django before importing or initializing anything that touches apps
django.setup()

from django.core.asgi import get_asgi_application
from channels.routing import ProtocolTypeRouter, URLRouter
from channels.auth import AuthMiddlewareStack
import stream.routing

# Initialize Django ASGI app early to ensure models/apps are ready
django_asgi_app = get_asgi_application()

application = ProtocolTypeRouter({
    "http": django_asgi_app,
    "websocket": AuthMiddlewareStack(
        URLRouter(
            stream.routing.websocket_urlpatterns
        )
    ),
})
