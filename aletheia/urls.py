from django.urls import path

from aletheia import views

app_name = "aletheia"
urlpatterns = [
    path('config/register/', views.registration_config, name="register_config"),
    path('register/', views.register, name="register"),
    path('config/login/', views.login_config, name="login_config"),
    path('login/', views.login_view, name="login")
]
