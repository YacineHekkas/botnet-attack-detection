import json, asyncio, random
from asgiref.sync import sync_to_async
from channels.generic.websocket import AsyncWebsocketConsumer
from .models import LabelEvent

# Define your full list of attack labels here:
LABEL_CHOICES = [
  'DDoS-ICMP_Flood','DDoS-UDP_Flood','DDoS-TCP_Flood','DDoS-PSHACK_Flood','DDoS-SYN_Flood','DDoS-RSTFINFlood','DDoS-SynonymousIP_Flood','DoS-UDP_Flood','Recon-PingSweep','DDoS-UDP_Fragmentation','DDoS-ACK_Fragmentation','DNS_Spoofing','Recon-HostDiscovery','Recon-OSScan','Recon-PortScan','DoS-HTTP_Flood','VulnerabilityScan','DoS-TCP_Flood','DoS-SYN_Flood','BenignTraffic','Mirai-greeth_flood','Mirai-udpplain','Mirai-greip_flood','DDoS-ICMP_Fragmentation','MITM-ArpSpoofing	','Uploading_Attack','DDoS-HTTP_Flood','DDoS-SlowLoris','DictionaryBruteForce','BrowserHijacking','CommandInjection','SqlInjection','XSS','Backdoor_Malware'
]

class LabelConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        await self.accept()
        self.running = True
        # Send handshake message
        await self.send(text_data=json.dumps({"message": "CONNECTED"}))
        # Start emitting from within this process
        asyncio.create_task(self._emit_labels())

    async def disconnect(self, close_code):
        self.running = False

    async def _emit_labels(self):
        while self.running:
            label = random.choice(LABEL_CHOICES)
            # 1) Send over WebSocket
            await self.send(text_data=json.dumps({"label": label}))
            # 2) Persist to DB
            await sync_to_async(LabelEvent.objects.create)(label=label)
            await asyncio.sleep(1)
