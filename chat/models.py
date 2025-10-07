# chat/models.py
from django.db import models
from django.contrib.auth.models import User



class ChatAdminFeature(models.Model):
    """Proxy model sin tabla, solo para declarar permisos a nivel de app."""
    class Meta:
        managed = False
        default_permissions = ()
        permissions = [
            ("can_save_conversation", "Puede guardar conversaciones en n8n"),
        ]
# NUEVO MODELO PARA CARPETAS
class Folder(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='folders')
    name = models.CharField(max_length=100)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name

    class Meta:
        # Ordenar por fecha de creación y asegurar que el nombre sea único por usuario
        ordering = ['-created_at']
        unique_together = ('user', 'name')


class Conversation(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    title = models.CharField(max_length=200)
    created_at = models.DateTimeField(auto_now_add=True)
    # AÑADIR CAMPO PARA RELACIONAR CON FOLDER
    # Es opcional (blank=True, null=True) para que las conversaciones puedan estar fuera de una carpeta.
    folder = models.ForeignKey(Folder, on_delete=models.SET_NULL, null=True, blank=True, related_name='conversations')

    def __str__(self):
        return f"{self.title} by {self.user.username}"


class Message(models.Model):
    conversation = models.ForeignKey(Conversation, on_delete=models.CASCADE, related_name='messages')
    role = models.CharField(max_length=10, choices=[('user', 'User'), ('assistant', 'Assistant')])
    content = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.role}: {self.content[:50]} in {self.conversation.title}"