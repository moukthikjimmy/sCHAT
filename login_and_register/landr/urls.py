from django.urls import path
from . import views

urlpatterns = [
    path('register/', views.register, name='register'),  # URL for register view
    path('', views.login, name='login'),  # URL for login view
    # Add other paths as needed for your app
]
