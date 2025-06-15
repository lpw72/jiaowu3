from django.urls import path
from . import views
from .views import CustomLoginView, CustomLogoutView  # 导入自定义认证视图

app_name = 'education'
urlpatterns = [
    path('', CustomLoginView.as_view(), name='login'),
    path('student_list/', views.student_list, name='student_list'),
    path('student_detail/', views.student_detail, name='student_detail'),
    path('change_password/', views.change_password, name='change_password'),  # 新增密码修改路由
    path('create/', views.student_create, name='student_create'),
    path('update/<int:pk>/', views.student_update, name='student_update'),
    path('delete/<int:pk>/', views.student_delete, name='student_delete'),
    path('register/', views.register, name='register'),
    path('logout/', CustomLogoutView.as_view(), name='logout'),
    path('roles/', views.role_list, name='role_list'),
    path('roles/create/', views.role_create, name='role_create'),
    path('roles/update/<int:pk>/', views.role_update, name='role_update'),
    path('roles/delete/<int:pk>/', views.role_delete, name='role_delete'),
    path('permissions/', views.permission_list, name='permission_list'),
    path('permissions/create/', views.permission_create, name='permission_create'),
    path('permissions/update/<int:pk>/', views.permission_update, name='permission_update'),
    path('permissions/delete/<int:pk>/', views.permission_delete, name='permission_delete'),
]