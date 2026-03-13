
# Auth Server
[![.NET 10](https://img.shields.io/badge/.NET-10.0-blue.svg)](https://dotnet.microsoft.com/) [![OpenIddict](https://img.shields.io/badge/OpenIddict-7.0-purple.svg)](https://github.com/openiddict) [![Docker](https://img.shields.io/badge/Docker-Ready-2496ED.svg?logo=docker)](https://www.docker.com/) [![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-336791.svg?logo=postgresql)](https://www.postgresql.org/)

**Auth Server** — это современный, безопасный и масштабируемый сервис централизованной аутентификации и авторизации (Single Sign-On). 

Построенный на базе **.NET 10** и мощного фреймворка **OpenIddict**, этот сервер берет на себя всю "грязную работу" по управлению пользователями: хранение хешей паролей, генерацию JWT-токенов, работу с Refresh-токенами и интеграцию со сторонними соцсетями (Telegram, GitHub, Google). 

Вам больше не нужно писать логику логина в каждом новом микросервисе, веб-сайте или WPF-клиенте. Вы просто делегируете процесс авторизации этому серверу, используя самые строгие индустриальные стандарты **OpenID Connect** и **OAuth 2.0 (PKCE)**, а в ответ получаете готовый токен доступа.
## Возможности

- **Централизованная авторизация (SSO):** Единая точка входа для всех подключенных приложений (WPF, SPA, мобильные клиенты).
- **Современные стандарты безопасности:** Поддержка OpenID Connect и OAuth 2.0 (Authorization Code Flow + PKCE).
- **Внешние провайдеры:** Вход через Telegram, GitHub и Google в пару кликов.
- **Управление доступом:** Механизм Consent (согласия) и возможность пользователя отзывать доступ у подключенных приложений.
- **Долгоживущие сессии:** Поддержка Refresh-токенов для безопасного обновления доступа без участия пользователя.
- **Изоляция сессий:** Ключи шифрования хранятся в Redis и X.509 сертификатах, сессии переживают перезагрузку сервера.
## Стек технологий

**Backend:** C#, .NET 10, ASP.NET Core MVC & Razor Pages  
**Identity Provider:** OpenIddict, ASP.NET Core Identity  
**Database:** PostgreSQL (Entity Framework Core)  
**Caching & Session:** Redis, Quartz.NET (для очистки протухших токенов)  
**Infrastructure:** Docker, Docker Compose, Linux  
## Локальный запуск

Склонируйте репозиторий и перейдите в директорию проекта:

    git clone https://github.com/ВАШ_АККАУНТ/AuthServer.git ~/authserver
    cd authserver
Скопируйте пример файла конфигурации:

    cp .env.example .env
(Отредактируйте .env и задайте надежные пароли для PostgreSQL и Redis, а также добавьте Client ID от GitHub/Google).

Соберите и запустите контейнеры:

    docker compose up -d --build
Сервер будет доступен по адресу: http://localhost:7000 (порт может отличаться в зависимости от вашего docker-compose.yml).

## Интеграция с Auth Server

Наш сервер авторизации использует современные стандарты безопасности: **OpenID Connect (OIDC)** и **OAuth 2.0 (Authorization Code Flow + PKCE)**. Это означает, что клиентское приложение никогда не видит пароль пользователя, а работает исключительно с безопасными токенами.

Ниже описан процесс регистрации нового клиентского приложения и получения токенов доступа.
## 1. Регистрация клиентского приложения

Чтобы ваше приложение могло перенаправлять пользователей на страницу логина, его необходимо зарегистрировать в системе.

Откройте в браузере ссылку (замените параметры на свои):

    https://auth.shulgan-lab.ru/clients/register?clientId=ВАШ_CLIENT_ID&redirectUri=ВАШ_URL_ВОЗВРАТА&displayName=НАЗВАНИЕ_ПРИЛОЖЕНИЯ

Параметры:

***clientId*** — уникальный идентификатор вашего приложения (например, my_messenger).

***redirectUri*** — URL, куда сервер вернет пользователя после успешного входа (например, https://my-app.com/callback).

***displayName*** (опционально) — красивое имя для отображения (например, Мой Супер Мессенджер).

#### На открывшейся странице вы получите **Client Secret**.
#### ⚠️ Обязательно сохраните его! Он показывается только **один раз** и понадобится для обмена кода на токены.
## 2. Процесс авторизации (Authorization Code Flow + PKCE)

Авторизация состоит из двух шагов: получение одноразового кода через браузер и обмен этого кода на токены сервером.

### 0. Предварительная подготовка (PKCE)
Перед началом процесса ваше приложение должно сгенерировать две строки:

***code_verifier*** — случайная криптографически стойкая строка (длиной от 43 до 128 символов).

***code_challenge*** — результат хеширования code_verifier алгоритмом SHA-256, закодированный в формат Base64Url (без символов заполнения = на конце).

(Для тестирования можно использовать онлайн-генератор: PKCE Generator)

### 1. Получение Authorization Code (Редирект пользователя)
Сформируйте ссылку и перенаправьте пользователя в браузере по этому адресу:

    https://auth.shulgan-lab.ru/connect/authorize?
    response_type=code
    &client_id=ВАШ_CLIENT_ID
    &redirect_uri=ВАШ_URL_ВОЗВРАТА
    &scope=openid profile email roles offline_access
    &code_challenge_method=S256
    &code_challenge=СГЕНЕРИРОВАННЫЙ_CODE_CHALLENGE

Пользователь введет логин и пароль на сервере auth.shulgan-lab.ru. После успешного входа сервер сделает редирект обратно в ваше приложение:

    https://ВАШ_URL_ВОЗВРАТА?code=ОДНОРАЗОВЫЙ_КОД

#### Примечание: Этот code "живет" всего несколько минут.

### 2. Обмен Code на токены (Серверный запрос)
Ваше приложение (с бэкенда) должно сделать POST-запрос для получения JWT-токенов.

    URL: 
    POST https://auth.shulgan-lab.ru/connect/token

    Header: 
    Content-Type: application/x-www-form-urlencoded

    Body:
    grant_type=authorization_code
    &client_id=ВАШ_CLIENT_ID
    &client_secret=ВАШ_CLIENT_SECRET_ИЗ_ШАГА_1
    &redirect_uri=ВАШ_URL_ВОЗВРАТА
    &code=ОДНОРАЗОВЫЙ_КОД_ИЗ_ШАГА_1
    &code_verifier=ОРИГИНАЛЬНЫЙ_CODE_VERIFIER

Успешный ответ (JSON):

    json
    {
        "access_token": "eyJhbGciOi...",
        "token_type": "Bearer",
        "expires_in": 3600,
        "scope": "openid profile email roles offline_access",
        "id_token": "eyJhbGciOi...",
        "refresh_token": "eyJhbGciOi..."
    }

### 3. Использование токенов
***access_token***: Прикрепляйте его к заголовкам ваших HTTP-запросов (Authorization: Bearer <access_token>) для доступа к защищенным API.

***id_token***: Содержит базовую информацию о пользователе (ID, email, имя, аватар). Может быть декодирован (например, на jwt.io) для отображения профиля на клиенте.

***refresh_token***: Когда access_token истечет (через 1 час), отправьте refresh_token на /connect/token (указав grant_type=refresh_token), чтобы получить новую пару токенов без повторного ввода пароля пользователем.
## API Reference

Сервер реализует стандартные эндпоинты протокола OpenID Connect:

#### Get Authorization Code

    GET /connect/authorize

| Parameter | Type     | Description                |
| :-------- | :------- | :------------------------- |
| `client_id` | `string` | **Required**. Идентификатор приложения |
| `redirect_uri` | `string` | **Required**. URL возврата |
| `response_type` | `string` | **Required**. Значение **code** |
| `code_challenge` | `string` | **Required**. PKCE challenge (SHA256) |
| `scope` | `string` | **Required**. Запрашиваемые права (напр., openid profile) |

#### Get Access & Refresh Tokens

    POST /connect/token

| Parameter | Type     | Description                       |
| :-------- | :------- | :-------------------------------- |
| `grant_type`| `string` | **Required**. authorization_code или refresh_token |
| `client_id`| `string` | **Required**. Идентификатор приложения |
| `client_secret`| `string` | **Required**. Секрет приложения |
| `code`| `string` | **Required (для auth_code)**. Код из предыдущего шага |
| `code_verifier`| `string` | **Required (для auth_code)**. PKCE verifier |

#### Get User Profile

    GET /connect/userinfo

(Требует заголовок Authorization: Bearer <access_token>)
Возвращает JSON с ID пользователя, email, ролями и ссылкой на аватарку.


## Deployment

Для деплоя на Production Linux-сервер (Ubuntu/Debian) используется автоматизированный bash-скрипт, который скачивает последнюю версию из ветки `master` и пересобирает Docker-образы без использования кэша.

##### 1. Зайдите на сервер по SSH.
##### 2. Перейдите в папку с проектом.
##### 3. Создайте скрипт **update-auth.sh**:

    #!/bin/bash

    # If errors - stop script
    set -e

    echo "Starting update Auth server..."

    # GoTo API folder
    cd ~/authserver

    # Update repo
    echo "Git Pull..."
    git pull

    # ReBuild and Restard container
    echo "Docker Compose Down..."
    docker compose down

    echo "Docker Compose Up..."
    docker compose up -d --build

    # Clear image (clean hard disk memory)
    echo "Pruning old images..."
    docker image prune -f

    echo "Auth server is UPDATED!"


##### 4. Выполните скрипт:

    ./update-auth.sh

**Важно**: Для Production-окружения необходимо сгенерировать X.509 PFX-сертификат и прокинуть его через Docker Volume, чтобы токены не инвалидировались при перезапусках контейнера.

## Roadmap

- [x] Настройка OpenIddict с БД PostgreSQL.
- [x] Интеграция Redis для DataProtection ключей.
- [x] Настройка X.509 сертификатов для Production.
- [x] UI для динамической регистрации клиентских приложений.
- [x] Страница управления выданными доступами (возможность отзыва Refresh-токенов).
- [ ] Парсинг и сохранение аватарок из внешних провайдеров (Telegram, GitHub, Google).
- [ ] Полная локализация системных ошибок Identity на русский язык.



## Авторы

- [@KirillShulgan](https://github.com/ВАШ_АККАУНТ) — Архитектура и разработка


## Благодарности

- [OpenIddict](https://documentation.openiddict.com/) за создание превосходного и гибкого фреймворка для OIDC.
- [ASP.NET Core Documentation](https://learn.microsoft.com/en-us/aspnet/core/)

