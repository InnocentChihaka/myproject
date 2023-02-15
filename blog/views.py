from django.shortcuts import render, HttpResponse
from django.views import View
from .forms import LoginForm
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import AnonymousUser
from django.contrib.auth.mixins import LoginRequiredMixin
# Create your views here.


class ProtectedView(LoginRequiredMixin,View):
    
    login_url ="login"
    redirect_fieldName = "redirect_to"
    
    def get(self, req, *args, **kwargs):
        user = req.user
        
        if isinstance(user, AnonymousUser):
            return HttpResponse("you can not access this page!")
        else:
            return HttpResponse("you have access this to page!")
        
        return HttpResponse("Protected view!")

class LoginView(View):
    form_class = LoginForm
    
    def post(self, req, *args, **kwargs):
        form = self.form_class(data=req.POST)
        if form.is_valid():
            username = form.cleaned_data["username"]
            password = form.cleaned_data["password"]
            
            user = authenticate( req, username=username, password=password)
            
            if user is not None:
                login(req, user)
                
                redirect_to = req.GET.get("redirect_to")
                
                if redirect_to is None:
                    return HttpResponse("You have successfuly logged in")
                else:
                    return HttpResponse(redirect_to)
            else:
                return HttpResponse("You can not login")
        else:
            return HttpResponse("invalide creditials")
        
                
    def get(self, req, *args, **kwargs):
        form = self.form_class()
        return render(
            req, "blog/login.html",
            {"form": form},
        )
    
class LogoutView(View):
    def get(self, req, *args, **kwargs):
        user = req.user
        if isinstance(user, AnonymousUser):
            return HttpResponse("Must Login first to Logout")
        else:
            logout(req)
            return HttpResponse("Loggedout successfuly")


