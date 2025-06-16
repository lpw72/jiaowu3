from django.urls import path
from .views import (
    student_list, student_update, student_create, student_delete,
    register, CustomLoginView, CustomLogoutView,
    role_list, role_create, role_update, role_delete,
    permission_list, permission_create, permission_update, permission_delete,
    change_password, student_detail
)
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)

urlpatterns = [
    # 学生相关路由
    path('api/students/', student_list, name='student-list'),  # 获取学生列表
    path('api/students/<int:pk>/', student_update, name='student-update'),  # 更新学生信息
    path('api/students/create/', student_create, name='student-create'),  # 创建新学生
    path('api/students/<int:pk>/delete/', student_delete, name='student-delete'),  # 删除学生
    path('api/student/detail/', student_detail, name='student-detail'),  # 获取学生详情

    # 注册、登录、登出路由
    path('api/register/', register, name='register'),  # 用户注册
    path('api/login/', CustomLoginView.as_view(), name='login'),  # 用户登录
    path('api/logout/', CustomLogoutView.as_view(), name='logout'),  # 用户登出

    # 角色相关路由
    path('api/roles/', role_list, name='role-list'),  # 获取角色列表
    path('api/roles/create/', role_create, name='role-create'),  # 创建新角色
    path('api/roles/<int:pk>/', role_update, name='role-update'),  # 更新角色信息
    path('api/roles/<int:pk>/delete/', role_delete, name='role-delete'),  # 删除角色

    # 权限相关路由
    path('api/permissions/', permission_list, name='permission-list'),  # 获取权限列表
    path('api/permissions/create/', permission_create, name='permission-create'),  # 创建新权限
    path('api/permissions/<int:pk>/', permission_update, name='permission-update'),  # 更新权限信息
    path('api/permissions/<int:pk>/delete/', permission_delete, name='permission-delete'),  # 删除权限

    # 修改密码路由
    path('api/change-password/', change_password, name='change-password'),

    # JWT 相关路由
    path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),  # 获取 JWT token
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),  # 刷新 JWT token
]


