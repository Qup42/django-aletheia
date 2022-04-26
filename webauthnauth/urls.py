from django.urls import path

from webauthnauth import views

app_name = "webauthnauth"
urlpatterns = [
    path('config/register/', views.registration_config, name="register_config"),
    path('register/', views.register, name="register"),
    path('config/login/', views.login_config, name="login_config"),
    path('login/', views.login_view, name="login")
]
