import time
import random
from asgiref.sync   import async_to_sync
from channels.layers import get_channel_layer
from django.core.management.base import BaseCommand

class Command(BaseCommand):
    help = "Emit random labels over Redis‐backed channel layer"

    # YOUR FULL LIST OF LABELS 
    LABEL_CHOICES = [
        "DDoS-ICMP_Flood","DDoS-UDP_Flood","DDoS-TCP_Flood","DDoS-PSHACK_Flood",
        "DDoS-SYN_Flood","DDoS-RSTFINFlood","DDoS-SynonymousIP_Flood","DoS-UDP_Flood",
        "Recon-PingSweep","DDoS-UDP_Fragmentation","DDoS-ACK_Fragmentation",
        "DNS_Spoofing","Recon-HostDiscovery","Recon-OSScan","Recon-PortScan",
        "DoS-HTTP_Flood","VulnerabilityScan","DoS-TCP_Flood","DoS-SYN_Flood",
        "BenignTraffic","Mirai-greeth_flood","Mirai-udpplain","Mirai-greip_flood",
        "DDoS-ICMP_Fragmentation","MITM-ArpSpoofing","Uploading_Attack",
        "DDoS-HTTP_Flood","DDoS-SlowLoris","DictionaryBruteForce",
        "BrowserHijacking","CommandInjection","SqlInjection","XSS","Backdoor_Malware"
    ]

    def handle(self, *args, **options):
        channel_layer = get_channel_layer()
        print("[*] Starting to emit labels… (CTRL+C to stop)")
        try:
            while True:
                label = random.choice(self.LABEL_CHOICES)
                # send to the 'labels' group, matching your consumer
                async_to_sync(channel_layer.group_send)(
                    "labels",
                    {
                        "type":  "label.message",  # fires your consumer.label_message
                        "label": label
                    }
                )
                self.stdout.write(f"Emitted: {label}")
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n[!] Stopped emitting.")
