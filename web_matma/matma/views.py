from django.shortcuts import render
from matma.utils import *

# Create your views here.
def home(request):
    return render(request, 'home.html')

def cryptosystem(request):
    return render(request, 'cryptosystem.html')

def signature(request):
    return render(request, 'signature.html')

def custom_page_not_found(request, exception):
    return render(request, '404.html', status=404)

def why(request):
    return render(request, 'why.html')

