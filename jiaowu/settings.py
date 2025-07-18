"""
Django settings for jiaowu project.

Generated by 'django-admin startproject' using Django 4.2.21.

For more information on this file, see
https://docs.djangoproject.com/en/4.2/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/4.2/ref/settings/
"""

from pathlib import Path

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/4.2/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = 'django-insecure-stfq%^qfgj@qtje(2l*=8t=33ih0726a7!$k*pxz9#ai^vcn5g'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = []


# Application definition

# 添加到INSTALLED_APPS
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'education',  # 你的应用
    'rest_framework',  #插件，构建Wed api
    'corsheaders',  # 新增的CORS支持
]

# 设置文件的中间件
MIDDLEWARE = [
    'corsheaders.middleware.CorsMiddleware',  # CORS中间件
    'django.middleware.common.CommonMiddleware',#通用中间件
    'django.middleware.csrf.CsrfViewMiddleware',#提供csrf保护的中间件
    'django.contrib.sessions.middleware.SessionMiddleware',  # 添加会话中间件
    'django.contrib.auth.middleware.AuthenticationMiddleware',#添加认证中间件
    'django.contrib.messages.middleware.MessageMiddleware',# 消息中间件
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'jiaowu.urls'

#定义了Django如何加载和渲染模板
TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'templates']
        ,
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'jiaowu.wsgi.application'


# Database
# https://docs.djangoproject.com/en/4.2/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.mysql',
        'NAME': 'jiaowu3',  # 你的 MySQL 数据库名（需提前在 MySQL 中创建）
        'USER': 'root',       # MySQL 用户名
        'PASSWORD': '123456789', # MySQL 密码
        'HOST': '127.0.0.1',  # 数据库地址
        'PORT': '3306',       # 端口
        'OPTIONS': {
            'charset': 'utf8mb4',  # 支持 emoji 字符
        }
    }
}

# 解决 MySQL 在 Python3 下的兼容问题（在文件底部添加）
import pymysql
pymysql.install_as_MySQLdb()


# Password validation
# https://docs.djangoproject.com/en/4.2/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = []  # 确保为空列表，无任何验证器配置
# {
#     'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
#     'OPTIONS': {
#         'message': '该密码与用户名或其他个人信息过于相似。'  # 中文提示
#     }
# },
# {
#     'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
#     'OPTIONS': {
#         'min_length': 8,
#         'message': '该密码太短。必须包含至少%(min_length)d个字符。'  # 中文提示
#     }
# },
# {
#     'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
#     'OPTIONS': {
#         'message': '该密码过于常见。'  # 中文提示
#     }
# },
# {
#     'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
#     'OPTIONS': {
#         'message': '该密码完全由数字组成。'  # 中文提示
#     }
#



# Internationalization
# https://docs.djangoproject.com/en/4.2/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/4.2/howto/static-files/

STATIC_URL = 'static/'  #存放静态资源

# Default primary key field type
# https://docs.djangoproject.com/en/4.2/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'



LOGIN_REDIRECT_URL = '/student_list/'  # 登录后重定向的url
LOGIN_URL = 'education:login'  # 登录的url

from datetime import timedelta
#设置令牌时间
SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(hours=2),  # As configured earlier
    'REFRESH_TOKEN_LIFETIME': timedelta(days=14),
    'ALGORITHM': 'HS256',
    'SIGNING_KEY': SECRET_KEY,
    'AUTH_HEADER_TYPES': ('Bearer',),
}
#添加jwt认证
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'rest_framework_simplejwt.authentication.JWTAuthentication',
    ),
}


# 配置CORS允许源（开发环境）
CORS_ALLOWED_ORIGINS = [
    "http://localhost:8080",  # Vue默认开发端口
    "http://192.168.100.25:8080",
]

# 可选：允许所有源（生产环境不推荐）
# CORS_ALLOW_ALL_ORIGINS = True
