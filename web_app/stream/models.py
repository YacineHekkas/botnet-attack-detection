from django.db import models

class LabelEvent(models.Model):
    timestamp = models.DateTimeField(auto_now_add=True)
    label     = models.CharField(max_length=64)

    def __str__(self):
        return f"{self.timestamp.isoformat()} – {self.label}"
