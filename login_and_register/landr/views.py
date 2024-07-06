from django.shortcuts import render, redirect
from .models import masters, User, IpTable
from django.http import HttpResponse
from django.contrib import messages
from django.contrib.auth.decorators import login_required  # Import login_required decorator

global flag
flag = 0

def register(request):
    global flag
    if flag == 1:
        if request.method == 'POST':
            username = request.POST.get('username')
            password = request.POST.get('password')
            department = request.POST.get('department')
            designation = request.POST.get('designation')
            ip_address = request.POST.get('ip_address')

            if User.objects.filter(username=username).exists():
                messages.error(request, 'Username already exists.')
            elif IpTable.objects.filter(ip_address=ip_address).exists():
                messages.error(request, 'IP Address already registered.')
            else:
                User.objects.create(
                    username=username,
                    password=password,
                    department=department,
                    designation=designation
                )
                IpTable.objects.create(
                    username=username,
                    ip_address=ip_address
                )
                messages.success(request, 'Registration successful.')
                flag = 0
                return redirect('login')  # Replace 'login' with your login URL name
        return render(request, 'register.html')
    else:
        messages.error(request, 'Only logged in users can register.')
        return redirect('login')

def login(request):
    global flag
    flag = 0
    if request.method == 'POST':
        username = request.POST.get('loginUsername')
        password = request.POST.get('loginPassword')

        try:
            user = masters.objects.get(master_name=username)
            if user.password == password:
                flag = 1
                messages.success(request, 'Login successful.')
                return redirect('register')
            else:
                messages.error(request, 'Invalid username or password.')
        
        except masters.DoesNotExist:
            messages.error(request, 'Invalid username or password.')

    return render(request, 'login.html')
