from django.urls import path

from webauthnauth import views

app_name = "webauthnauth"
urlpatterns = [
    path('get_registration_config', views.registration_config, name="get_registration_config"),
    path('register', views.register, name="register"),
    path('get_login_config', views.login_config, name="get_login_config"),
    path('login', views.login_view, name="login")
]
