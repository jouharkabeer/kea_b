"""
URL configuration for kea_api project.

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

from django.conf import settings
from django.conf.urls.static import static
from rest_framework import permissions
from drf_yasg.views import get_schema_view
from drf_yasg import openapi
from django.urls import path, include
from django.http import HttpResponse

# Customize admin site
admin.site.site_header = settings.ADMIN_SITE_HEADER
admin.site.site_title = settings.ADMIN_SITE_TITLE
admin.site.index_title = settings.ADMIN_INDEX_TITLE

# Define the schema view
schema_view = get_schema_view(
   openapi.Info(
      title="KEA API's",
      default_version='v1',
      description="A comprehensive list of available API endpoints",
      contact=openapi.Contact(email="jouharkabeer412@gmail.com"),
   ),
   public=True,
   permission_classes=(permissions.AllowAny,),
)
def home(request):
    return HttpResponse("Welcome to KEA API!")

urlpatterns = [
    path('admin/', admin.site.urls),
     path('', home),
    path('swagger/', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
    path('auth/', include('userdata.urls')),
    path('program/', include('programdata.urls')),

]
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
else:
    # For production, also serve media files through Django
    # This is not ideal for large scale but works for Railway
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)