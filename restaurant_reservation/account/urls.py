from django.urls import path
from . import views

urlpatterns = [
    path('register/', views.create, name='register'),
    path('login/', views.login, name='login'),
    path('profile/', views.profile, name='profile'),
    path('users/', views.UserListView.as_view(), name='user-list'),
    path('logout/', views.logout, name='logout'),
    path('change-password/', views.changePassword, name='changepassword'),
]
