from django.shortcuts import get_object_or_404, redirect
from django.http import JsonResponse
from django.contrib.auth import login, update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.contrib.auth.models import User
from django.contrib.auth.views import LoginView, LogoutView
from .forms import StudentForm, UserRegistrationForm, CustomLoginForm, RoleForm, PermissionForm, PasswordChangeForm
from .models import Student, Role, Permission

@login_required
def student_list(request):
    init_system_permissions()
    students = list(Student.objects.values())
    current_user = request.user
    is_admin = hasattr(current_user, 'student') and current_user.student.roles.filter(name__icontains='管理员').exists()
    return JsonResponse({'status': 'success', 'data': {'students': students, 'is_admin': is_admin}})

@login_required
def student_update(request, pk):
    student = get_object_or_404(Student, pk=pk)
    current_user = request.user
    is_admin = hasattr(current_user, 'student') and current_user.student.roles.filter(name__icontains='管理员').exists()
    if request.method == 'POST':
        form = StudentForm(request.POST, instance=student, is_admin=is_admin)
        if form.is_valid():
            form.save()
            return JsonResponse({'status': 'success', 'data': {'message': 'Student updated successfully'}})
        else:
            return JsonResponse({'status': 'error', 'data': {'errors': form.errors}}, status=400)
    else:
        data = {
            'id': student.id,
            'name': student.name,
            'gender': student.gender,
            'mobile': student.mobile,
            'email': student.email,
            'is_admin': is_admin
        }
        return JsonResponse({'status': 'success', 'data': data})

@login_required
def student_create(request):
    current_user = request.user
    is_admin = hasattr(current_user, 'student') and current_user.student.roles.filter(name__icontains='管理员').exists()
    if request.method == 'POST':
        form = StudentForm(request.POST, is_admin=is_admin)
        if form.is_valid():
            form.save()
            return JsonResponse({'status': 'success', 'data': {'message': 'Student created successfully'}})
        else:
            return JsonResponse({'status': 'error', 'data': {'errors': form.errors}}, status=400)
    else:
        return JsonResponse({'status': 'success', 'data': {'is_admin': is_admin}})

@login_required
def student_delete(request, pk):
    student = get_object_or_404(Student, pk=pk)
    student.delete()
    return JsonResponse({'status': 'success', 'data': {'message': 'Student deleted successfully'}})

def register(request):
    if request.method == 'POST':
        form = UserRegistrationForm(request.POST)
        if form.is_valid():
            invitation_code = form.cleaned_data.get('invitation_code', '')
            user = form.save(commit=False)
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
            messages.success(request, '注册成功，请使用账号密码登录！')
            return JsonResponse({'status': 'success', 'data': {'message': 'User registered successfully'}})
        else:
            return JsonResponse({'status': 'error', 'data': {'errors': form.errors}}, status=400)
    else:
        return JsonResponse({'status': 'success', 'data': {}})

class CustomLoginView(LoginView):
    template_name = 'education/login.html'
    success_url = '/student_list/'
    authentication_form = CustomLoginForm

class CustomLogoutView(LogoutView):
    next_page = 'education:student_list'

@login_required
def role_list(request):
    current_user = request.user
    is_admin = hasattr(current_user, 'student') and current_user.student.roles.filter(name__icontains='管理员').exists()
    roles = list(Role.objects.values())
    return JsonResponse({'status': 'success', 'data': {'roles': roles, 'is_admin': is_admin}})

@login_required
def role_create(request):
    if request.method == 'POST':
        form = RoleForm(request.POST)
        if form.is_valid():
            form.save()
            return JsonResponse({'status': 'success', 'data': {'message': 'Role created successfully'}})
        else:
            return JsonResponse({'status': 'error', 'data': {'errors': form.errors}}, status=400)
    else:
        return JsonResponse({'status': 'success', 'data': {}})

@login_required
def role_update(request, pk):
    role = get_object_or_404(Role, pk=pk)
    if request.method == 'POST':
        form = RoleForm(request.POST, instance=role)
        if form.is_valid():
            form.save()
            return JsonResponse({'status': 'success', 'data': {'message': 'Role updated successfully'}})
        else:
            return JsonResponse({'status': 'error', 'data': {'errors': form.errors}}, status=400)
    else:
        data = {
            'id': role.id,
            'name': role.name
        }
        return JsonResponse({'status': 'success', 'data': data})

@login_required
def role_delete(request, pk):
    role = get_object_or_404(Role, pk=pk)
    role.delete()
    return JsonResponse({'status': 'success', 'data': {'message': 'Role deleted successfully'}})

@login_required
def permission_list(request):
    permissions = list(Permission.objects.values())
    return JsonResponse({'status': 'success', 'data': {'permissions': permissions}})

@login_required
def permission_create(request):
    if request.method == 'POST':
        form = PermissionForm(request.POST)
        if form.is_valid():
            form.save()
            return JsonResponse({'status': 'success', 'data': {'message': 'Permission created successfully'}})
        else:
            return JsonResponse({'status': 'error', 'data': {'errors': form.errors}}, status=400)
    else:
        return JsonResponse({'status': 'success', 'data': {}})

@login_required
def permission_update(request, pk):
    permission = get_object_or_404(Permission, pk=pk)
    if request.method == 'POST':
        form = PermissionForm(request.POST, instance=permission)
        if form.is_valid():
            form.save()
            return JsonResponse({'status': 'success', 'data': {'message': 'Permission updated successfully'}})
        else:
            return JsonResponse({'status': 'error', 'data': {'errors': form.errors}}, status=400)
    else:
        data = {
            'id': permission.id,
            'name': permission.name,
            'code': permission.code
        }
        return JsonResponse({'status': 'success', 'data': data})

@login_required
def permission_delete(request, pk):
    permission = get_object_or_404(Permission, pk=pk)
    permission.delete()
    return JsonResponse({'status': 'success', 'data': {'message': 'Permission deleted successfully'}})

def init_system_permissions():
    view_perm, _ = Permission.objects.get_or_create(name='查看学生', code='view_student')
    edit_perm, _ = Permission.objects.get_or_create(name='修改学生', code='edit_student')
    delete_perm, _ = Permission.objects.get_or_create(name='删除学生', code='delete_student')
    add_perm, _ = Permission.objects.get_or_create(name='新增学生', code='add_student')
    admin_role, _ = Role.objects.get_or_create(name='管理员')
    admin_role.permissions.add(view_perm, edit_perm, delete_perm, add_perm)
    common_role, _ = Role.objects.get_or_create(name='普通用户')
    common_role.permissions.add(view_perm, edit_perm)

@login_required
def change_password(request):
    current_user = request.user
    if request.method == 'POST':
        form = PasswordChangeForm(request.POST)
        if form.is_valid():
            old_password = form.cleaned_data['old_password']
            if not current_user.check_password(old_password):
                return JsonResponse({'status': 'error', 'data': {'message': '旧密码错误'}}, status=400)
            new_password = form.cleaned_data['new_password']
            current_user.set_password(new_password)
            current_user.save()
            update_session_auth_hash(request, current_user)
            return JsonResponse({'status': 'success', 'data': {'message': '密码修改成功！'}})
        else:
            return JsonResponse({'status': 'error', 'data': {'errors': form.errors}}, status=400)
    else:
        return JsonResponse({'status': 'success', 'data': {}})

@login_required
def student_detail(request):
    current_user = request.user
    if not hasattr(current_user, 'student'):
        return JsonResponse({'status': 'error', 'data': {'message': '用户未关联学生信息，请联系管理员。'}}, status=400)
    student = current_user.student
    data = {
        'id': student.id,
        'name': student.name,
        'gender': student.gender,
        'mobile': student.mobile,
        'email': student.email
    }
    return JsonResponse({'status': 'success', 'data': data})


