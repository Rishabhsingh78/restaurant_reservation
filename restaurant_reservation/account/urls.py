from django.urls import path
from . import views

urlpatterns = [
    path('register/', views.create, name='register'),
    path('login/', views.login, name='login'),
    path('profile/', views.profile, name='profile'),
    path('users/', views.UserListView.as_view(), name='user-list'),
    path('logout/', views.logout, name='logout'),
    path('change-password/', views.changePassword, name='changepassword'),
    path('password-reset/', views.request_Password, name='request_password_reset'),
    path('password-reset-confirm/<uidb64>/<token>/', views.password_reset_confirm, name='password_reset_confirm'),
]
