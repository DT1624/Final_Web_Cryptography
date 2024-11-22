"""
URL configuration for web_matma project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from matma.views import *
from matma.utils import *
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path('admin/', admin.site.urls),
    path('home/', home, name = 'home'),
    path('', home, name = 'home'),
    path('cryptosystem/', cryptosystem, name = 'cryptosystem'),
    path('signature/', signature, name = 'signature'),
    path('why/', why, name = 'why'),
    path('generate_cryptosystem_key/', generate_cryptosystem_key, name='generate_cryptosystem_key'),
    path('en_de_algorithm/', en_de_algorithm, name = 'en_de_algorithm'),
    path('sig_ver_algorithm/', sig_ver_algorithm, name = 'sig_ver_algorithm'),
    
]+ static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)

handler404 = custom_page_not_found
