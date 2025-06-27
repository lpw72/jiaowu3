from django import forms
from django.contrib.auth.models import User
from .models import Student, Role
from django.contrib.auth.forms import UserCreationForm


class StudentForm(forms.ModelForm):
    class Meta:
        model = Student
        # 移除 password 字段
        fields = ['name', 'gender', 'email', 'mobile', 'roles']  # 删除 'password'
        widgets = {
            'roles': forms.CheckboxSelectMultiple(),
            # 移除 password 相关 widgets 配置
        }

    def __init__(self, *args, is_admin=False, **kwargs):
        super().__init__(*args, **kwargs)
        # 非管理员用户隐藏 roles 字段
        if not is_admin:
            del self.fields['roles']


class StudentRegistrationForm(UserCreationForm):
    email = forms.EmailField(required=True, label='邮箱')
    # Move student-specific fields here as form-only fields
    gender = forms.ChoiceField(choices=Student.GENDER_CHOICES, label='性别')
    # Make mobile field optional to match Student model's blank=True
    mobile = forms.CharField(max_length=11, label='电话', required=False)
    roles = forms.ModelMultipleChoiceField(
        queryset=Role.objects.all(),
        widget=forms.CheckboxSelectMultiple,
        label='角色选择',
        required=False  # Add this to make roles optional
    )

    class Meta:
        model = User
        # Only include User model fields in Meta.fields
        fields = ['username', 'email', 'password1', 'password2']  # Remove gender, mobile, roles

    def save(self, commit=True):
        user = super().save(commit=False)
        user.email = self.cleaned_data['email']
        if commit:
            user.save()
            # Create Student instance with form data
            student = Student.objects.create(
                name=self.cleaned_data['username'],
                gender=self.cleaned_data['gender'],
                email=self.cleaned_data['email'],
                mobile=self.cleaned_data['mobile'],
                user=user
            )
            student.roles.set(self.cleaned_data['roles'])
        return user
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib.auth.models import User
from .models import Student
from .models import Role
from .models import Permission
from django.contrib.auth.hashers import make_password


class StudentForm(forms.ModelForm):
    class Meta:
        model = Student
        # 移除 password 字段
        fields = ['name', 'gender', 'email', 'mobile', 'roles']  # 删除 'password'
        widgets = {
            'roles': forms.CheckboxSelectMultiple(),
            # 移除 password 相关 widgets 配置
        }

    def __init__(self, *args, is_admin=False, **kwargs):
        super().__init__(*args, **kwargs)
        # 非管理员用户隐藏 roles 字段
        if not is_admin:
            del self.fields['roles']


class CustomLoginForm(AuthenticationForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['username'].label = '用户名'
        self.fields['password'].label = '密码'


class UserRegistrationForm(UserCreationForm):
    email = forms.EmailField(required=True, label='邮箱')
    gender = forms.ChoiceField(choices=[('M', '男'), ('F', '女')], label='性别')
    mobile = forms.CharField(max_length=11, label='电话')
    # 新增邀请码字段（选填）
    invitation_code = forms.CharField(
        max_length=20,
        required=False,
        label='邀请码（选填）',

    )

    class Meta:
        model = User
        fields = ['username', 'email', 'password1', 'password2', 'gender', 'mobile']

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # 移除密码字段默认帮助文本
        self.fields['password1'].help_text = None
        self.fields['password2'].help_text = None

        # 删除用户名提示（原中文提示）
        self.fields['username'].help_text = ''  # 改为空字符串
        self.fields['username'].error_messages = {
            'required': '用户名不能为空',
            'max_length': '用户名不能超过150个字符',
            'invalid': '用户名格式错误（仅限字母、数字和@/./+/-/_）'
        }

        # 新增：设置字段中文标签
        self.fields['username'].label = '用户名'  # 原 Username
        self.fields['password1'].label = '密码'  # 原 Password
        self.fields['password2'].label = '确认密码'  # 原 Password confirmation

        # 修改密码确认的错误提示（中文）
        self.fields['password2'].error_messages['password_mismatch'] = '两次输入的密码不一致'

    def clean_password2(self):
        password1 = self.cleaned_data.get("password1")
        password2 = self.cleaned_data.get("password2")
        if password1 and password2 and password1 != password2:
            raise forms.ValidationError(
                self.error_messages['password_mismatch'],
                code='password_mismatch',
            )
        return password2  # 直接返回密码2，无其他验证逻辑


class RoleForm(forms.ModelForm):
    class Meta:
        model = Role
        fields = ['name', 'permissions']
        labels = {'name': '角色名称', 'permissions': '对应权限'}
        widgets = {
            'permissions': forms.CheckboxSelectMultiple(),  # 多选框显示权限
        }
        help_texts = {'permissions': '按住Ctrl键多选权限'}


class PermissionForm(forms.ModelForm):
    class Meta:
        model = Permission
        fields = ['name', 'code']
        labels = {
            'name': '权限名称',
            'code': '对应代码'
        }
        help_texts = {
            'code': '示例：view_student（查看学生）, edit_student（编辑学生）'
        }


class PasswordChangeForm(forms.Form):
    old_password = forms.CharField(
        label='旧密码',
        widget=forms.PasswordInput,
        help_text='请输入当前登录用户的密码'
    )
    new_password = forms.CharField(
        label='新密码',
        widget=forms.PasswordInput,
        help_text='请输入新密码'
    )
    confirm_password = forms.CharField(
        label='确认新密码',
        widget=forms.PasswordInput,
        help_text='请再次输入新密码'
    )

    def clean(self):
        cleaned_data = super().clean()
        new_password = cleaned_data.get('new_password')
        confirm_password = cleaned_data.get('confirm_password')
        if new_password != confirm_password:
            raise forms.ValidationError('新密码与确认密码不一致')
        return cleaned_data

    def save(self, commit=True):
        instance = super().save(commit=False)
        # 密码哈希处理
        if self.cleaned_data.get('password'):
            instance.password = make_password(self.cleaned_data['password'])
        if commit:
            instance.save()
        return instance