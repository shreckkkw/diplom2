from django.urls import path

from . import views

urlpatterns = [
  path('', views.HomeView.as_view(), name='home'),
  path('upload/', views.UploadView.as_view(), name='upload'),
  path('demo/', views.DemoView.as_view(), name='demo'),
  path('sessions/', views.SessionListView.as_view(), name='sessions'),
  path('sessions/<int:pk>/', views.SessionDetailView.as_view(), name='session_detail'),
  path('how-it-works/', views.HowItWorksView.as_view(), name='how_it_works'),
]
