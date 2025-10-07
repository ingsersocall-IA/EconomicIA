# chat/management/commands/init_chat_roles.py
from django.core.management.base import BaseCommand
from django.contrib.auth.models import Group, Permission
from django.contrib.contenttypes.models import ContentType
from django.apps import apps

class Command(BaseCommand):
    help = "Crea el grupo 'ChatAdmins' y le asigna el permiso 'can_save_conversation'."

    def handle(self, *args, **options):
        # Obtén el modelo proxy que declaraste para emitir el permiso
        # Debe existir: chat/models.py -> class ChatAdminFeature(models.Model): Meta: managed=False, permissions=[(...)]
        ChatAdminFeature = apps.get_model('chat', 'ChatAdminFeature')

        # Asegura ContentType para el modelo y crea/obtiene el permiso
        ct = ContentType.objects.get_for_model(ChatAdminFeature)
        perm, _ = Permission.objects.get_or_create(
            codename='can_save_conversation',
            name='Puede guardar conversaciones en n8n',
            content_type=ct
        )

        # Crea/obtiene el grupo y asigna el permiso
        group, _ = Group.objects.get_or_create(name='ChatAdmins')
        group.permissions.add(perm)

        self.stdout.write(self.style.SUCCESS(
            "OK: grupo 'ChatAdmins' con permiso 'chat.can_save_conversation'."
        ))
