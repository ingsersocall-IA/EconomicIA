import logging
import requests
from django.http import JsonResponse, HttpResponse, HttpResponseForbidden
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib.auth import login, logout, authenticate
from django.contrib import messages
from django.contrib.auth.forms import AuthenticationForm
from datetime import datetime
from django.views.decorators.csrf import csrf_exempt
from django.shortcuts import render, redirect
from django.contrib.auth.forms import AuthenticationForm, UserCreationForm, PasswordChangeForm
from django.contrib.auth import update_session_auth_hash
from django.views.decorators.http import require_POST
from django.urls import reverse
from django.template.loader import render_to_string
import json
from django.conf import settings
from django.http import HttpResponseBadRequest
from django.views.decorators.csrf import  csrf_protect
from django.utils import timezone
from django.contrib.auth.decorators import  permission_required
from .models import Conversation, Message
from django.views.decorators.http import require_http_methods

# Añade esto al principio del archivo
logger = logging.getLogger(__name__)
from datetime import timedelta
import re
from .models import Conversation, Message, Folder
from django.contrib.auth import get_user_model
User = get_user_model()
WEBHOOK_API_URL = "http://localhost:5678/webhook/Economic"
WEBHOOK_API_URL_save = "http://localhost:5678/webhook/IngesEconmic"
logger = logging.getLogger(__name__)

def login_view(request):
    # toma el correo desde settings o usa un fallback
    support_email = getattr(settings, 'SUPPORT_EMAIL', 'admin@tudominio.com')

    if request.method == 'POST':
        form = AuthenticationForm(request, data=request.POST)
        if form.is_valid():
            user = form.get_user()
            login(request, user)
            messages.success(request, f'Bienvenido, {user.username}!', extra_tags='auth')

            # Admin/staff → puerta de re-autenticación
            if user.is_staff or user.is_superuser:
                return redirect('admin_gate')

            # Usuario normal → directo al chat
            return redirect('chat_list')
        else:
            messages.error(request, 'Usuario o contraseña incorrectos.', extra_tags='auth')
            # Render con form + support_email cuando hay error
            return render(request, 'chat/login.html', {
                'form': form,
                'support_email': support_email,
            })
    else:
        form = AuthenticationForm()

    # Render inicial (GET)
    return render(request, 'chat/login.html', {
        'form': form,
        'support_email': support_email,
    })
def _require_recent_admin_reauth(request):
    ts = request.session.get('admin_reauth_at')
    if not ts:
        return False
    try:
        dt = datetime.fromisoformat(ts)
    except Exception:
        return False
    return (timezone.now() - dt) <= timedelta(minutes=10)

def register_view(request):
    messages.error(request, 'El registro público está deshabilitado. Solicita acceso a un administrador.')
    return redirect('login')
@login_required
def logout_view(request):
    logout(request)
    messages.info(request, 'Has cerrado sesión.', extra_tags='auth')
    return redirect('login')

@login_required
def chat_view(request, conv_id=None):
    # 1) Resolver conversación activa (igual que tu código)
    if conv_id:
        conversation = get_object_or_404(Conversation, id=conv_id, user=request.user)
    else:
        conversation = Conversation.objects.filter(user=request.user).order_by('-created_at').first()
        if not conversation:
            # Comprobar límite antes de crear la primera conversación
            if Conversation.objects.filter(user=request.user).count() >= 10:
                messages.warning(request, 'Has alcanzado el límite de 10 conversaciones.')
                return redirect('chat_list')
            conversation = Conversation.objects.create(user=request.user, title="Primera conversación")
        # Redirige para fijar la URL con conv_id
        return redirect('chat', conv_id=conversation.id)

    # 2) Datos para la barra lateral
    folders = Folder.objects.filter(user=request.user)
    conversations_without_folder = (
        Conversation.objects
        .filter(user=request.user, folder__isnull=True)
        .order_by('-created_at')
    )

    # 3) Flag de permiso para mostrar UI de "Guardar conversación"
    can_save = request.user.has_perm("chat.can_save_conversation")

    # 4) Contexto final hacia la plantilla
    context = {
        'conversation': conversation,
        'chat_messages': conversation.messages.order_by('timestamp').all(),  # tu línea modificada
        'folders': folders,
        'conversations_without_folder': conversations_without_folder,
        'all_conversations_count': Conversation.objects.filter(user=request.user).count(),
        # NUEVO:
        'can_save': can_save,
        'conversation_id': conversation.id,
    }

    return render(request, "chat/chat.html", context)

# chat/views.py
LEADING_PRE_RE = re.compile(r'^\s*<pre[^>]*>\s*<code[^>]*>(.*?)</code>\s*</pre>', re.I | re.S)

def _sanitize_leading(text: str) -> str:
    """Quita indentación/saltos al inicio para evitar que Markdown u orígenes
    lo conviertan en bloque de código."""
    if not text:
        return ""
    t = text.lstrip()
    # Si la primera línea aún empieza con 4+ espacios, límpiala (sin tocar fences ```).
    lines = t.splitlines()
    if lines and lines[0].startswith("    ") and not lines[0].lstrip().startswith("```"):
        lines[0] = lines[0].lstrip()
    return "\n".join(lines)

def _unwrap_leading_pre(html: str) -> str:
    """Si el contenido empieza con <pre><code>…</code></pre>, lo convierte a <p>…</p>
    para que no 'flote' fuera del globo."""
    if not html:
        return ""
    m = LEADING_PRE_RE.match(html)
    if not m:
        return html
    inner = m.group(1)
    # Quitamos espacios/saltos iniciales y dejamos un <p>
    inner = inner.lstrip(" \t\r\n")
    return f"<p>{inner}</p>" + html[m.end():]
@login_required
@csrf_exempt  # Temporal para depuración (luego lo quitamos)
@require_http_methods(["POST"])
def generate_response(request):
    try:
        logger.info("=== Inicio de generate_response (Modo Webhook) ===")

        # 1. CAPTURA EL MENSAJE Y EL ID DE CONVERSACIÓN (Sin cambios)
        if request.content_type == 'application/json':
            data = json.loads(request.body)
            user_prompt = data.get('prompt')
            conv_id = data.get('conv_id')
        else:
            user_prompt = request.POST.get('prompt')
            conv_id = request.POST.get('conv_id')
        # 🔽 Normaliza para evitar sangría/salto al inicio del globo
        user_prompt = (user_prompt or "")
        user_prompt = _sanitize_leading(user_prompt)
        conv_id = str(conv_id or "").strip()
        if not user_prompt or not conv_id:
            return JsonResponse({'error': 'Faltan los campos "prompt" o "conv_id"'}, status=400)

        conversation = get_object_or_404(Conversation, id=int(conv_id), user=request.user)
        logger.info(f"Conversación encontrada: {conversation.id}")

        # Guardamos el mensaje del usuario ANTES de llamar a la API
        # para que el historial esté completo.
        history_messages = conversation.messages.order_by('timestamp').all()

        memoria = [
            {'role': msg.role, 'content': msg.content}
            for msg in history_messages
        ]
        logger.info(f"Historial ('memoria') recuperado con {len(memoria)} mensajes.")

        # SEGUNDO: AHORA sí guardamos el mensaje actual del usuario en la BD.
        # Esto asegura que estará en la 'memoria' para la PRÓXIMA solicitud.
        Message.objects.create(conversation=conversation, role='user', content=user_prompt)
        logger.info("Nuevo mensaje de usuario guardado en la BD.")

        # TERCERO: Creamos el payload con los datos separados correctamente.
        payload = {
            'sessionId': str(conversation.id),
            'metadata': {
                'feedback': user_prompt,  # El mensaje actual del usuario
                'memoria': memoria,       # El historial SIN el mensaje actual
                'timestamp': datetime.now().isoformat()
            }
        }
        logger.info(f"Payload que se enviará al Webhook: {json.dumps(payload, indent=2)}")

        # 3. REALIZA LA LLAMADA A LA API WEBHOOK
        logger.info(f"Llamando al Webhook: {WEBHOOK_API_URL}...")
        api_response = requests.post(
            WEBHOOK_API_URL,
            json=payload,
            headers={'Content-Type': 'application/json'},
            timeout=120  # Timeout de 2 minutos
        )
        logger.info(f"Webhook status: {api_response.status_code}")

        # 4. MANEJA LA RESPUESTA DEL WEBHOOK
        if api_response.status_code != 200:
            error_text = api_response.text
            logger.error(f"Error del Webhook: {error_text}")
            return JsonResponse({'error': f'Error del Webhook {api_response.status_code}: {error_text}'}, status=500)

        try:
            # La respuesta esperada es una lista con un objeto: `[{"reply": "...", "memoria": [...]}]`
            response_data = api_response.json()

            if isinstance(response_data, list) and len(response_data) > 0:
                data = response_data[0]
                assistant_msg = _sanitize_leading(data.get("reply", ""))
                assistant_msg = _unwrap_leading_pre(assistant_msg)
                if not assistant_msg:
                    assistant_msg = "Lo siento, no pude generar una respuesta."

                # Opcional: Podrías usar data.get('memoria') si quisieras sincronizar el historial
                # pero es más seguro confiar en tu propia base de datos.
            else:
                logger.error(f"La respuesta del Webhook no tiene el formato esperado: {response_data}")
                return JsonResponse({'error': 'Respuesta inválida del modelo'}, status=500)

        except json.JSONDecodeError:
            logger.error("La respuesta del Webhook no es un JSON válido.")
            return JsonResponse({'error': 'Respuesta inválida del modelo'}, status=500)

        # 5. GUARDA Y MUESTRA LA RESPUESTA DEL BOT (Sin cambios)
        assistant_message = Message.objects.create(
            conversation=conversation,
            role='assistant',
            content=assistant_msg
        )
        logger.info("Respuesta del Webhook guardada en la BD.")

        assistant_html = render_to_string('chat/_message.html', {'message': assistant_message})
        return HttpResponse(assistant_html, content_type='text/html')

    except Exception as e:
        logger.exception("Error inesperado en generate_response")
        return JsonResponse({'error': 'Error interno del servidor'}, status=500)
@login_required
@require_POST
def new_conversation(request):
    # El límite de 10 conversaciones es global, sin importar las carpetas.
    if Conversation.objects.filter(user=request.user).count() >= 10:
        messages.warning(request, 'Has alcanzado el límite de 10 conversaciones.')
        return redirect('chat_list')

    # Opcional: Si quieres que se cree dentro de una carpeta específica
    folder_id = request.POST.get('folder_id')
    folder = None
    if folder_id:
        folder = get_object_or_404(Folder, id=folder_id, user=request.user)

    conv = Conversation.objects.create(user=request.user, title="Nueva conversación", folder=folder)
    return redirect('chat', conv_id=conv.id)

@login_required
@require_POST
def create_folder(request):
    folder_name = request.POST.get('folder_name', '').strip()
    if folder_name:
        # Evitar nombres duplicados
        if not Folder.objects.filter(user=request.user, name=folder_name).exists():
            Folder.objects.create(user=request.user, name=folder_name)
            messages.success(request, f'Carpeta "{folder_name}" creada.')
        else:
            messages.error(request, f'Ya existe una carpeta con el nombre "{folder_name}".')
    else:
        messages.error(request, 'El nombre de la carpeta no puede estar vacío.')

    return redirect(request.META.get('HTTP_REFERER', 'chat_list'))


@login_required
@require_POST
def move_conversation_to_folder(request, conv_id):
    conversation = get_object_or_404(Conversation, id=conv_id, user=request.user)
    folder_id = request.POST.get('folder_id')

    if folder_id == "none": # Opción para sacar la conversación de la carpeta
        conversation.folder = None
    else:
        folder = get_object_or_404(Folder, id=folder_id, user=request.user)
        conversation.folder = folder

    conversation.save()
    messages.success(request, f'Conversación movida correctamente.')
    return redirect('chat', conv_id=conv_id)


# Eliminar conversación
@login_required
@require_POST
def delete_conversation(request, conv_id):
    conversation = get_object_or_404(Conversation, id=conv_id, user=request.user)
    conversation.delete()
    messages.success(request, 'Conversación eliminada correctamente.')
    remaining = Conversation.objects.filter(user=request.user).order_by('-created_at').first()
    if remaining:
        return redirect('chat', conv_id=remaining.id)
    return redirect('chat_list')
@login_required
@require_POST
def delete_folder(request, folder_id):
    folder = get_object_or_404(Folder, id=folder_id, user=request.user)

    # Importante: Eliminar las conversaciones dentro de la carpeta primero
    # Esto cumple con el requisito "si hay algo adentro que se elimine todo"
    folder.conversations.all().delete()

    folder_name = folder.name
    folder.delete()

    messages.success(request, f'Carpeta "{folder_name}" y todo su contenido han sido eliminados.')
    return redirect('chat_list')
# Vista para eliminar un único mensaje
@login_required
@require_POST
def delete_single_message(request, message_id):
    # Usamos try-except para manejar el caso en que el mensaje ya no exista
    try:
        message = Message.objects.get(id=message_id)
    except Message.DoesNotExist:
        # Si el mensaje no existe, no hacemos nada.
        return HttpResponse(status=204) # 204 No Content

    # **Control de seguridad crucial**:
    # Asegurarse de que el mensaje pertenece a una conversación del usuario que hace la petición.
    if message.conversation.user != request.user:
        return HttpResponseForbidden("No tienes permiso para eliminar este mensaje.")

    message.delete()
    # Devolvemos una respuesta vacía con código 200 OK.
    # HTMX usará esto para eliminar el elemento del DOM si usamos hx-swap="outerHTML".
    return HttpResponse(status=200)

# Vista para eliminar un mensaje y todos los anteriores en la conversación
@login_required
@require_POST
def delete_messages_upwards(request, message_id):
    try:
        target_message = Message.objects.get(id=message_id)
    except Message.DoesNotExist:
        return HttpResponse(status=204)

    # **Control de seguridad**
    if target_message.conversation.user != request.user:
        return HttpResponseForbidden("No tienes permiso para realizar esta acción.")

    conversation = target_message.conversation

    # Obtenemos el timestamp del mensaje seleccionado
    target_timestamp = target_message.timestamp

    # Eliminamos en una sola consulta todos los mensajes de esa conversación
    # cuyo timestamp es menor o igual al del mensaje seleccionado.
    messages_to_delete = Message.objects.filter(
        conversation=conversation,
        timestamp__lte=target_timestamp
    )
    count, _ = messages_to_delete.delete()

    messages.info(request, f'Se eliminaron {count} mensajes de la conversación.')

    # Como esta acción puede eliminar muchos elementos, lo más simple y efectivo
    # es redirigir al usuario a la misma conversación para que se recargue la vista.
    return redirect('chat', conv_id=conversation.id)

# Vista para editar (renombrar) una carpeta
@login_required
@require_POST
def edit_folder(request, folder_id):
    folder = get_object_or_404(Folder, id=folder_id, user=request.user)
    new_name = request.POST.get('new_folder_name', '').strip()

    if not new_name:
        messages.error(request, 'El nombre de la carpeta no puede estar vacío.')
    # Comprobar que no exista otra carpeta con el mismo nombre para el mismo usuario
    elif Folder.objects.filter(user=request.user, name=new_name).exclude(id=folder_id).exists():
        messages.error(request, f'Ya existe una carpeta con el nombre "{new_name}".')
    else:
        folder.name = new_name
        folder.save()
        messages.success(request, 'Carpeta renombrada correctamente.')

    # Redirigir a la página desde la que se hizo la petición
    return redirect(request.META.get('HTTP_REFERER', 'chat_list'))

# Vista para editar (renombrar) el título de una conversación
@login_required
@require_POST
def edit_conversation(request, conv_id):
    conversation = get_object_or_404(Conversation, id=conv_id, user=request.user)
    new_title = request.POST.get('new_conversation_title', '').strip()

    if not new_title:
        messages.error(request, 'El título de la conversación no puede estar vacío.')
    else:
        conversation.title = new_title
        conversation.save()
        messages.success(request, 'Conversación renombrada correctamente.')

    return redirect('chat', conv_id=conv_id)
# (Eliminado duplicado de login_view)

@login_required
def chat_list(request):
    # Esta vista ahora necesita la misma lógica que chat_view para la barra lateral
    folders = Folder.objects.filter(user=request.user)
    conversations_without_folder = Conversation.objects.filter(user=request.user, folder__isnull=True).order_by('-created_at')

    return render(request, 'chat/conversations.html', {
        'folders': folders,
        'conversations_without_folder': conversations_without_folder,
        'all_conversations_count': Conversation.objects.filter(user=request.user).count()
    })

@login_required
def profile_view(request):
    return render(request, 'chat/profile.html', {
        'user_obj': request.user,
    })

@login_required
def password_change_view(request):
    if request.method == 'POST':
        form = PasswordChangeForm(user=request.user, data=request.POST)
        if form.is_valid():
            user = form.save()
            update_session_auth_hash(request, user)
            messages.success(request, 'Contraseña actualizada correctamente.')
            return redirect('profile')
        else:
            messages.error(request, 'Por favor corrige los errores del formulario.')
    else:
        form = PasswordChangeForm(user=request.user)
    return render(request, 'chat/password_change.html', {'form': form})

# Esto para los admins

@login_required
@permission_required('chat.can_save_conversation', raise_exception=True)
@require_POST
@csrf_protect
def save_conversation_to_n8n(request):
    """
    Espera JSON: { "conversation_id": int, "user_message_id": int, "bot_message_id": int }
    Valida roles, construye un único payload y lo POSTea a N8N_WEBHOOK_URL.
    """
    if not WEBHOOK_API_URL_save:
        return HttpResponseBadRequest("Falta N8N_WEBHOOK_URL en settings.")

    try:
        payload = json.loads(request.body.decode('utf-8'))
        conv_id = payload.get("conversation_id")
        user_msg_id = payload.get("user_message_id")
        bot_msg_id = payload.get("bot_message_id")
    except Exception:
        return HttpResponseBadRequest("JSON inválido.")

    if not all([conv_id, user_msg_id, bot_msg_id]):
        return HttpResponseBadRequest("Faltan campos requeridos.")

    conv = get_object_or_404(Conversation, id=conv_id)
    # (Opcional) verifica que el usuario actual tenga acceso a esa conversación
    # if conv.owner != request.user: return HttpResponseForbidden("Sin acceso a esta conversación.")

    user_msg = get_object_or_404(Message, id=user_msg_id, conversation=conv)
    bot_msg  = get_object_or_404(Message, id=bot_msg_id, conversation=conv)

    if user_msg.role not in ("user", "human"):
        return HttpResponseBadRequest("El primer mensaje seleccionado debe ser de usuario.")
    if bot_msg.role not in ("assistant", "bot"):
        return HttpResponseBadRequest("El segundo mensaje seleccionado debe ser del bot.")

    merged = {
        "type": "saved_chat",
        "conversation_id": conv.id,
        "saved_by": request.user.username,
        "saved_at": timezone.now().isoformat(),
        "data": {
            "user_text": user_msg.content,
            "assistant_text": bot_msg.content,
        }
    }

    try:
        resp = requests.post(
            WEBHOOK_API_URL_save,
            json=merged,
            timeout=10
        )
        resp.raise_for_status()
    except requests.RequestException as e:
        return JsonResponse({"ok": False, "error": f"Error enviando a n8n: {e}"}, status=502)

    return JsonResponse({"ok": True, "n8n_status": resp.status_code})

# === NUEVO: Puerta de Admin (re-autenticación)
@login_required
def admin_gate(request):
    # Solo admins/staff pueden pasar por aquí
    if not (request.user.is_staff or request.user.is_superuser):
        return HttpResponseForbidden("No autorizado.")

    if request.method == 'POST':
        username = request.POST.get('username', '').strip()
        password = request.POST.get('password', '')

        # Por seguridad, el username debe ser el del usuario logueado
        if username != request.user.username:
            messages.error(request, 'Usuario no coincide con la sesión activa.')
            return redirect('admin_gate')

        user = authenticate(request, username=username, password=password)
        if user is None:
            messages.error(request, 'Credenciales inválidas.')
            return redirect('admin_gate')

        # Guardamos la marca de re-autenticación
        request.session['admin_reauth_at'] = timezone.now().isoformat()
        return redirect('admin_selector')

    return render(request, 'chat/admin_gate.html', {
        'username': request.user.username
    })

# === NUEVO: Selector de Admin (dos botones)
@login_required
def admin_selector(request):
    if not (request.user.is_staff or request.user.is_superuser):
        return HttpResponseForbidden("No autorizado.")

    # Si no hay reauth reciente, devolver a la puerta
    if not _require_recent_admin_reauth(request):
        return redirect('admin_gate')

    return render(request, 'chat/admin_selector.html')

@login_required
def admin_panel(request):
    if not (request.user.is_staff or request.user.is_superuser):
        return HttpResponseForbidden("No autorizado.")
    if not _require_recent_admin_reauth(request):
        return redirect('admin_gate')

    users = User.objects.all().order_by('username')
    return render(request, 'chat/admin_panel2.html', {'users': users})

# === NUEVO: Crear usuario simple (no admin)
@login_required
@require_POST
def admin_create_user(request):
    if not (request.user.is_staff or request.user.is_superuser):
        return HttpResponseForbidden("No autorizado.")
    if not _require_recent_admin_reauth(request):
        return redirect('admin_gate')

    username = (request.POST.get('username') or '').strip()
    email = (request.POST.get('email') or '').strip()
    p1 = request.POST.get('password1') or ''
    p2 = request.POST.get('password2') or ''

    if not username or not p1 or not p2:
        messages.error(request, 'Completa usuario y contraseñas.')
        return redirect('admin_panel')

    if p1 != p2:
        messages.error(request, 'Las contraseñas no coinciden.')
        return redirect('admin_panel')

    if User.objects.filter(username=username).exists():
        messages.error(request, 'El usuario ya existe.')
        return redirect('admin_panel')

    # Fuerza siempre usuario simple (no staff, no superuser)
    u = User.objects.create_user(username=username, email=email)
    u.is_staff = False
    u.is_superuser = False
    u.set_password(p1)
    u.save()

    messages.success(request, f'Usuario "{username}" creado (rol simple).')
    return redirect('admin_panel')
# === NUEVO: Cambiar contraseña de un usuario (prohibido para superusers)
@login_required
@require_POST
def admin_set_password(request, user_id):
    if not (request.user.is_staff or request.user.is_superuser):
        return HttpResponseForbidden("No autorizado.")
    if not _require_recent_admin_reauth(request):
        return redirect('admin_gate')

    target = get_object_or_404(User, id=user_id)
    p1 = request.POST.get('new_password1') or ''
    p2 = request.POST.get('new_password2') or ''

    if target.is_superuser:
        messages.error(request, 'No se puede modificar la contraseña de un superusuario desde este panel.')
        return redirect('admin_panel')

    if not p1 or p1 != p2:
        messages.error(request, 'Las contraseñas no coinciden.')
        return redirect('admin_panel')

    target.set_password(p1)
    target.save()
    messages.success(request, f'Contraseña actualizada para {target.username}.')
    return redirect('admin_panel')
# === NUEVO: Eliminar usuario simple (no staff / no superuser / no tú mismo)
@login_required
@require_POST
def admin_delete_user(request, user_id):
    if not (request.user.is_staff or request.user.is_superuser):
        return HttpResponseForbidden("No autorizado.")
    if not _require_recent_admin_reauth(request):
        return redirect('admin_gate')

    target = get_object_or_404(User, id=user_id)

    if target.id == request.user.id:
        messages.error(request, 'No puedes eliminar tu propia cuenta.')
        return redirect('admin_panel')

    if target.is_superuser or target.is_staff:
        messages.error(request, 'Solo se pueden eliminar usuarios simples.')
        return redirect('admin_panel')

    username = target.username
    target.delete()
    messages.success(request, f'Usuario "{username}" eliminado.')
    return redirect('admin_panel')
