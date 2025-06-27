from django.shortcuts import get_object_or_404
from django.http import JsonResponse
from django.contrib.auth import login, update_session_auth_hash, authenticate,logout
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.contrib.auth.models import User
from django.contrib.messages import success
from django.utils.decorators import method_decorator
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated,AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status
from .forms import StudentForm, UserRegistrationForm, PasswordChangeForm, RoleForm, PermissionForm, StudentRegistrationForm
from .models import Student, Role, Permission
from .serializers import StudentSerializer, RoleSerializer, PermissionSerializer
from rest_framework_simplejwt.tokens import RefreshToken

# 学生列表视图，返回所有学生的JSON数据
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def student_list(request):
    init_system_permissions()  # 初始化系统权限
    students = Student.objects.all()  # 获取所有学生对象
    serializer = StudentSerializer(students, many=True)  # 使用序列化器将学生对象转换为JSON格式
    current_user = request.user  # 获取当前用户
    is_admin = hasattr(current_user, 'student') and current_user.student.roles.filter(name__icontains='管理员').exists()  # 检查用户是否为管理员
    return Response({'status': 'success', 'data': {'students': serializer.data, 'is_admin': is_admin}})  # 返回学生列表和管理员状态的JSON响应

# 更新学生信息视图
@api_view(['PUT'])
@permission_classes([IsAuthenticated])
def student_update(request, pk):
    student = get_object_or_404(Student, pk=pk)
    current_user = request.user
    is_admin = hasattr(current_user, 'student') and current_user.student.roles.filter(name__icontains='管理员').exists()
    
    if request.method == 'PUT':
        # 直接从请求数据更新学生模型字段
        student.name = request.data.get('name', student.name)
        student.gender = request.data.get('gender', student.gender)
        student.mobile = request.data.get('mobile', student.mobile)
        student.email = request.data.get('email', student.email)
        student.save()
        
        # 添加角色更新逻辑
        if 'roles' in request.data:
            roles = Role.objects.filter(id__in=request.data.get('roles', []))
            student.roles.set(roles)
        
        return Response({'status': 'success', 'data': {'message': '学生信息更新成功'}})
    
    # GET请求处理逻辑
    data = {
        'id': student.id,
        'name': student.name,
        'gender': student.gender,
        'mobile': student.mobile,
        'email': student.email,
        'is_admin': is_admin,
        'roles': [role.id for role in student.roles.all()]
    }
    return Response({'status': 'success', 'data': data})

# 创建新学生视图
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def student_create(request):
    current_user = request.user
    is_admin = hasattr(current_user, 'student') and current_user.student.roles.filter(name='管理员').exists()
    
    if not is_admin:
        return Response({'status': 'error', 'data': {'message': '无权限创建学生'}}, status=403)
        
    if request.method == 'POST':
        form = StudentRegistrationForm(request.data)
        if form.is_valid():
            user = form.save()
            return Response({
                'status': 'success', 
                'data': {'message': '学生创建成功', 'username': user.username}
            })
        else:
            return Response({'status': 'error', 'data': {'errors': form.errors}}, status=400)
    else:
        return Response({'status': 'success', 'data': {'is_admin': is_admin}})  # 返回管理员状态的JSON响应

# 删除学生视图
@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def student_delete(request, pk):
    student = get_object_or_404(Student, pk=pk)
    # 获取关联的用户对象
    user = student.user
    # 删除用户会级联删除关联的学生记录
    user.delete()
    return Response({'status': 'success', 'data': {'message': '用户及关联学生记录已删除'}})

# 用户注册视图
@api_view(['POST'])
def register(request):
    if request.method == 'POST':
        form = UserRegistrationForm(request.data)
        if form.is_valid():
            invitation_code = form.cleaned_data.get('invitation_code', '')
            user = form.save(commit=False)
            # 修复：使用 'password1' 代替 'password'
            user.set_password(form.cleaned_data['password1'])  # 设置密码
            user.is_staff = (invitation_code == '123456')
            user.save()

            gender = form.cleaned_data['gender']
            mobile = form.cleaned_data['mobile']
            student = Student.objects.create(
                name=user.username,
                gender=gender,
                mobile=mobile,
                email=user.email,
                user=user
            )

            admin_role, _ = Role.objects.get_or_create(name='管理员')
            common_role, _ = Role.objects.get_or_create(name='普通用户')

            if user.is_staff:
                student.roles.add(admin_role)
            else:
                student.roles.add(common_role)

            success(request, '注册成功，请使用账号密码登录！')
            return Response({'status': 'success', 'data': {'message': 'User registered successfully'}})
        else:
            return Response({'status': 'error', 'data': {'errors': form.errors}}, status=400)
    else:
        return Response({'status': 'success', 'data': {}})
# 自定义登录视图
class CustomLoginView(APIView):
    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')
        user = authenticate(username=username, password=password)
        if user:
            # 生成JWT令牌（如果使用JWT认证）
            refresh = RefreshToken.for_user(user)
            return Response({
                'refresh': str(refresh),
                'access': str(refresh.access_token),
                'user_id': user.id,
                'username': user.username
            })
        return Response({
            'error': 'Invalid credentials'
        }, status=status.HTTP_401_UNAUTHORIZED)
# 自定义登出视图
class CustomLogoutView(APIView):
    @method_decorator(login_required)
    def post(self, request, *args, **kwargs):
        logout(request)  # 注销用户
        request.session.pop('access_token', None)  # 从session中移除访问令牌
        return Response({'status': 'success', 'data': {'message': 'Logout successful'}})  # 返回成功的JSON响应

# 角色列表视图
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def role_list(request):
    current_user = request.user  # 获取当前用户
    is_admin = hasattr(current_user, 'student') and current_user.student.roles.filter(name__icontains='管理员').exists()  # 检查用户是否为管理员
    roles = Role.objects.all()  # 获取所有角色对象
    serializer = RoleSerializer(roles, many=True)  # 使用序列化器将角色对象转换为JSON格式
    return Response({'status': 'success', 'data': {'roles': serializer.data, 'is_admin': is_admin}})  # 返回角色列表和管理员状态的JSON响应

# 创建新角色视图
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def role_create(request):
    if request.method == 'POST':  # 如果请求方法是POST
        form = RoleForm(request.data)  # 使用表单处理请求数据
        if form.is_valid():  # 如果表单有效
            form.save()  # 保存表单数据
            return Response({'status': 'success', 'data': {'message': 'Role created successfully'}})  # 返回成功的JSON响应
        else:
            return Response({'status': 'error', 'data': {'errors': form.errors}}, status=400)  # 返回包含错误信息的JSON响应
    else:
        return Response({'status': 'success', 'data': {}})  # 返回空的JSON响应

# 更新角色视图
@api_view(['PUT'])
@permission_classes([IsAuthenticated])
def role_update(request, pk):
    role = get_object_or_404(Role, pk=pk)  # 根据主键获取角色对象，如果不存在则返回404错误
    if request.method == 'PUT':  # 如果请求方法是PUT
        form = RoleForm(request.data, instance=role)  # 使用表单处理请求数据，并绑定到现有角色实例
        if form.is_valid():  # 如果表单有效
            form.save()  # 保存表单数据
            return Response({'status': 'success', 'data': {'message': 'Role updated successfully'}})  # 返回成功的JSON响应
        else:
            return Response({'status': 'error', 'data': {'errors': form.errors}}, status=400)  # 返回包含错误信息的JSON响应
    else:
        data = {
            'id': role.id,
            'name': role.name
        }
        return Response({'status': 'success', 'data': data})  # 返回角色信息的JSON响应

# 删除角色视图
@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def role_delete(request, pk):
    role = get_object_or_404(Role, pk=pk)  # 根据主键获取角色对象，如果不存在则返回404错误
    role.delete()  # 删除角色对象
    return Response({'status': 'success', 'data': {'message': 'Role deleted successfully'}})  # 返回成功的JSON响应

# 权限列表视图
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def permission_list(request):
    permissions = Permission.objects.all()  # 获取所有权限对象
    serializer = PermissionSerializer(permissions, many=True)  # 使用序列化器将权限对象转换为JSON格式
    return Response({'status': 'success', 'data': {'permissions': serializer.data}})  # 返回权限列表的JSON响应

# 创建新权限视图
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def permission_create(request):
    if request.method == 'POST':  # 如果请求方法是POST
        form = PermissionForm(request.data)  # 使用表单处理请求数据
        if form.is_valid():  # 如果表单有效
            form.save()  # 保存表单数据
            return Response({'status': 'success', 'data': {'message': 'Permission created successfully'}})  # 返回成功的JSON响应
        else:
            return Response({'status': 'error', 'data': {'errors': form.errors}}, status=400)  # 返回包含错误信息的JSON响应
    else:
        return Response({'status': 'success', 'data': {}})  # 返回空的JSON响应

# 更新权限视图
@api_view(['PUT'])
@permission_classes([IsAuthenticated])
def permission_update(request, pk):
    permission = get_object_or_404(Permission, pk=pk)  # 根据主键获取权限对象，如果不存在则返回404错误
    if request.method == 'PUT':  # 如果请求方法是PUT
        form = PermissionForm(request.data, instance=permission)  # 使用表单处理请求数据，并绑定到现有权限实例
        if form.is_valid():  # 如果表单有效
            form.save()  # 保存表单数据
            return Response({'status': 'success', 'data': {'message': 'Permission updated successfully'}})  # 返回成功的JSON响应
        else:
            return Response({'status': 'error', 'data': {'errors': form.errors}}, status=400)  # 返回包含错误信息的JSON响应
    else:
        data = {
            'id': permission.id,
            'name': permission.name,
            'code': permission.code
        }
        return Response({'status': 'success', 'data': data})  # 返回权限信息的JSON响应

# 删除权限视图
@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def permission_delete(request, pk):
    permission = get_object_or_404(Permission, pk=pk)  # 根据主键获取权限对象，如果不存在则返回404错误
    permission.delete()  # 删除权限对象
    return Response({'status': 'success', 'data': {'message': 'Permission deleted successfully'}})  # 返回成功的JSON响应

# 初始化系统权限函数
def init_system_permissions():
    view_perm, _ = Permission.objects.get_or_create(name='查看学生', code='view_student')  # 获取或创建查看学生权限
    edit_perm, _ = Permission.objects.get_or_create(name='修改学生', code='edit_student')  # 获取或创建修改学生权限
    delete_perm, _ = Permission.objects.get_or_create(name='删除学生', code='delete_student')  # 获取或创建删除学生权限
    add_perm, _ = Permission.objects.get_or_create(name='新增学生', code='add_student')  # 获取或创建新增学生权限
    admin_role, _ = Role.objects.get_or_create(name='管理员')  # 获取或创建管理员角色
    admin_role.permissions.add(view_perm, edit_perm, delete_perm, add_perm)  # 将所有权限添加到管理员角色
    common_role, _ = Role.objects.get_or_create(name='普通用户')  # 获取或创建普通用户角色
    common_role.permissions.add(view_perm, edit_perm)  # 将查看和修改权限添加到普通用户角色

# 修改密码视图
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def change_password(request):
    current_user = request.user  # 获取当前用户
    if request.method == 'POST':  # 如果请求方法是POST
        form = PasswordChangeForm(request.data)  # 使用表单处理请求数据
        if form.is_valid():  # 如果表单有效
            old_password = form.cleaned_data['old_password']  # 获取旧密码
            if not current_user.check_password(old_password):  # 检查旧密码是否正确
                return Response({'status': 'error', 'data': {'message': '旧密码错误'}}, status=400)  # 返回错误信息
            new_password = form.cleaned_data['new_password']  # 获取新密码
            current_user.set_password(new_password)  # 设置新密码
            current_user.save()  # 保存用户对象
            update_session_auth_hash(request, current_user)  # 更新会话以保持登录状态
            return Response({'status': 'success', 'data': {'message': '密码修改成功！'}})  # 返回成功的JSON响应
        else:
            return Response({'status': 'error', 'data': {'errors': form.errors}}, status=400)  # 返回包含错误信息的JSON响应
    else:
        return Response({'status': 'success', 'data': {}})  # 返回空的JSON响应

# 学生详情视图
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def student_detail(request):
    current_user = request.user  # 获取当前用户
    if not hasattr(current_user, 'student'):  # 如果用户没有关联的学生信息
        return Response({'status': 'error', 'data': {'message': '用户未关联学生信息，请联系管理员。'}}, status=400)  # 返回错误信息
    student = current_user.student  # 获取用户关联的学生对象
    serializer = StudentSerializer(student)  # 使用序列化器将学生对象转换为JSON格式
    return Response({'status': 'success', 'data': serializer.data})  # 返回学生信息的JSON响应


