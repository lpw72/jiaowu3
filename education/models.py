from django.db import models
from django.contrib.auth.models import User  # 新增：关联Django内置用户模型

class Student(models.Model):
    GENDER_CHOICES = [
        ('M', '男'),
        ('F', '女'),
    ]
    name = models.CharField('姓名', max_length=50)
    gender = models.CharField('性别', max_length=1, choices=GENDER_CHOICES, default='M')
    email = models.EmailField('邮箱', unique=True)
    mobile = models.CharField('电话', max_length=11, blank=True)
    roles = models.ManyToManyField('Role', verbose_name='角色', blank=True)  # 修正为多对多
    user = models.OneToOneField(
        User,
        on_delete=models.CASCADE,
        verbose_name='关联用户',
        null=True,  # 允许数据库为空
        blank=True   # 允许表单为空
    )

    def __str__(self):
        return self.name

    class Meta:
        verbose_name = '学生'
        verbose_name_plural = '学生管理'


class Role(models.Model):
    name = models.CharField('角色名称', max_length=50, unique=True)
    permissions = models.ManyToManyField('Permission', verbose_name='对应权限')  # 修正为多对多

    def __str__(self):
        return self.name

    class Meta:
        verbose_name = '角色'
        verbose_name_plural = '角色管理'


class Permission(models.Model):
    name = models.CharField('权限名称', max_length=50, unique=True)
    code = models.CharField('对应代码', max_length=100, help_text='示例：view_student（查看）, edit_student（编辑）')

    def __str__(self):
        return self.name

    class Meta:
        verbose_name = '权限'
        verbose_name_plural = '权限管理'
