from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect
from django.contrib import messages
from .forms import CustomUserCreationForm
from django_otp import devices_for_user
from django_otp.plugins.otp_totp.models import TOTPDevice

def register(request):
    if request.method == 'POST':
        form = CustomUserCreationForm(request.POST)
        if form.is_valid():
            user = form.save()
            messages.success(request, 'Account created successfully!')
            return redirect('account_login')
    else:
        form = CustomUserCreationForm()
    return render(request, 'account/register.html', {'form': form})

@login_required
def setup_mfa(request):
    user = request.user
    devices = devices_for_user(user)
    
    if request.method == 'POST':
        device = TOTPDevice.objects.create(user=user, name='default')
        device.save()
        return render(request, 'account/show_qr.html', {'device': device})
        
    return render(request, 'account/setup_mfa.html', {'devices': devices})

@login_required
def dashboard(request):
    return render(request, 'account/dashboard.html') 