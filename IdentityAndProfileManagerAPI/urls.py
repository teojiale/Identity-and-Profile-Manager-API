"""
URL configuration for IdentityAndProfileManagerAPI project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.2/topics/http/urls/
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
from django.urls import path, include
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)
from rest_framework.routers import DefaultRouter
from IdentityAndProfileManager.views import (
    IdentityProfileViewSet,
    RegisterView,
    home,
    profile_detail,
    profile_edit,
    login_page,
    logout_view,
    check_username,
    CookieTokenObtainPairView,
    CookieTokenRefreshView,
    CookieLogoutView,
    get_csrf_token,
)

router = DefaultRouter()
router.register(r"IdentityAndProfileManager", IdentityProfileViewSet, basename = "identity")

urlpatterns = [
    path("admin/", admin.site.urls),
    path("", home, name = "home"),
    path("login/", login_page, name = "login_page"),
    path("register/", RegisterView.as_view(), name = "register"),
    path("profile/edit/", profile_edit, name = "profile_edit"),
    path("profile/<str:username>/", profile_detail, name = "profile_detail"),

    path("logout/", logout_view, name = "logout"),
    path("IdentityAndProfileManagerAPI/", include(router.urls)),

    # New secure cookie-based authentication endpoints
    path("api/auth/login/", CookieTokenObtainPairView.as_view(), name="cookie_login"),
    path("api/auth/refresh/", CookieTokenRefreshView.as_view(), name="cookie_refresh"),
    path("api/auth/logout/", CookieLogoutView.as_view(), name="cookie_logout"),
    path("api/auth/csrf-token/", get_csrf_token, name="csrf_token"),

    # Legacy endpoints (still available for backward compatibility)
    path("IdentityAndProfileManagerAPI/token/", TokenObtainPairView.as_view(), name="token_obtain_pair"),
    path("IdentityAndProfileManagerAPI/token/refresh/", TokenRefreshView.as_view(), name="token_refresh"),
    path("IdentityAndProfileManagerAPI/check-username/", check_username, name="check_username"),

]
