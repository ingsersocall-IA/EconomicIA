# chat/urls.py
from django.urls import path
from . import views

urlpatterns = [
    path('login/', views.login_view, name='login'),
    path('register/', views.register_view, name='register'),
    path('logout/', views.logout_view, name='logout'),

    # Rutas de Chat
    path('conversations/', views.chat_list, name='chat_list'),
    path('new/', views.new_conversation, name='new_conversation'),
    path('delete/<int:conv_id>/', views.delete_conversation, name='delete_conversation'),
    path('chat/<int:conv_id>/', views.chat_view, name='chat'),
    path('chat/', views.chat_view, name='chat_default'), # Ruta por defecto sin ID

    # Rutas de API
    path('api/generate/', views.generate_response, name='generate_response'),

    # Rutas de Perfil
    path('profile/', views.profile_view, name='profile'),
    path('password/change/', views.password_change_view, name='password_change'),

    # NUEVAS RUTAS PARA CARPETAS
    path('folder/create/', views.create_folder, name='create_folder'),
    path('folder/<int:folder_id>/delete/', views.delete_folder, name='delete_folder'),
    path('folder/<int:folder_id>/edit/', views.edit_folder, name='edit_folder'),

    path('conversation/<int:conv_id>/move/', views.move_conversation_to_folder, name='move_conversation_to_folder'),
    path('conversation/<int:conv_id>/edit/', views.edit_conversation, name='edit_conversation'),
    # NUEVAS RUTAS PARA ELIMINAR MENSAJES
    path('message/<int:message_id>/delete/', views.delete_single_message, name='delete_single_message'),
    path('message/<int:message_id>/delete-upwards/', views.delete_messages_upwards, name='delete_messages_upwards'),
    path("api/save-conversation/", views.save_conversation_to_n8n, name="save_conversation"),
     # === NUEVO: flujo admin ===
      # DESPUÉS (sin conflicto)
      path('panel-admin/gate/', views.admin_gate, name='admin_gate'),
      path('panel-admin/selector/', views.admin_selector, name='admin_selector'),
      path('panel-admin/panel/', views.admin_panel, name='admin_panel'),
      path('panel-admin/create-user/', views.admin_create_user, name='admin_create_user'),
      path('panel-admin/set-password/<int:user_id>/', views.admin_set_password, name='admin_set_password'),
      path('panel-admin/delete-user/<int:user_id>/', views.admin_delete_user, name='admin_delete_user'),

]