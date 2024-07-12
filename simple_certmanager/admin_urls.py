from django.urls import path

from simple_certmanager.admin_views import GenerateCertificateView

urlpatterns = [
    path("generate/", GenerateCertificateView.as_view(), name="generate_certificate"),
]
