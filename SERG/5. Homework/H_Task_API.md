# Домашнее задание

## Работа с API методами

Задачу буду выполнять на базе сайта - https://reqres.in/

Получаем бесплатный **API ключ** и отправляем его в каждом запросе через заголовок "**x-api-key**", как сказано в документации.

#### Метод GET (получить)

Получить всех пользователей:

```bash
serg@serg-pc:~$ curl -H "x-api-key: reqres-free-v1" \
  https://reqres.in/api/users/
{
  "page": 1,
  "per_page": 6,
  "total": 12,
  "total_pages": 2,
  "data": [
    {
      "id": 1,
      "email": "george.bluth@reqres.in",
      "first_name": "George",
      "last_name": "Bluth",
      "avatar": "https://reqres.in/img/faces/1-image.jpg"
    },
    {
      "id": 2,
      "email": "janet.weaver@reqres.in",
      "first_name": "Janet",
      "last_name": "Weaver",
      "avatar": "https://reqres.in/img/faces/2-image.jpg"
    },
    {
      "id": 3,
      "email": "emma.wong@reqres.in",
      "first_name": "Emma",
      "last_name": "Wong",
      "avatar": "https://reqres.in/img/faces/3-image.jpg"
    },
    {
      "id": 4,
      "email": "eve.holt@reqres.in",
      "first_name": "Eve",
      "last_name": "Holt",
      "avatar": "https://reqres.in/img/faces/4-image.jpg"
    },
    {
      "id": 5,
      "email": "charles.morris@reqres.in",
      "first_name": "Charles",
      "last_name": "Morris",
      "avatar": "https://reqres.in/img/faces/5-image.jpg"
    },
    {
      "id": 6,
      "email": "tracey.ramos@reqres.in",
      "first_name": "Tracey",
      "last_name": "Ramos",
      "avatar": "https://reqres.in/img/faces/6-image.jpg"
    }
  ],
  "support": {
    "url": "https://contentcaddy.io?utm_source=reqres&utm_medium=json&utm_campaign=referral",
    "text": "Tired of writing endless social media content? Let Content Caddy generate it for you."
  }
}
```

#### Лог-файл:

[Полный лог запроса](./GET_USERS_ALL.log)



#### Метод GET (получить)

Получить пользователя с **id=3**

```bash
serg@serg-pc:~$ curl -H "x-api-key: reqres-free-v1" \
  https://reqres.in/api/users/3
{
  "data": {
    "id": 3,
    "email": "emma.wong@reqres.in",
    "first_name": "Emma",
    "last_name": "Wong",
    "avatar": "https://reqres.in/img/faces/3-image.jpg"
  },
  "support": {
    "url": "https://contentcaddy.io?utm_source=reqres&utm_medium=json&utm_campaign=referral",
    "text": "Tired of writing endless social media content? Let Content Caddy generate it for you."
  }
}
```

#### 📁 Лог-файл:

[Полный лог запроса](./GET_USER_3.log)

#### Метод POST (создать)

```bash
serg@serg-pc:~$ curl -X POST -H "Content-Type: application/json" \
     -H "x-api-key: reqres-free-v1" \
     -d '{"name": "Serg", "job": "The programmer"}' \
     https://reqres.in/api/users
{
  "name": "Serg",
  "job": "The programmer",
  "id": "936",
  "createdAt": "2025-09-13T19:44:31.370Z"
}
```

#### 📁 Лог-файл:

[Полный лог запроса](./GET_USER_3.log)

#### Метод PUT (Обновить)

Поскольку ID моего пользователя - 936, обновим его данные:

```bash
serg@serg-pc:~$ curl -s -X PUT \
     -H "Content-Type: application/json" \
     -H "x-api-key: reqres-free-v1" \
     -d '{"name":"Serg","job":"teacher"}' \
     https://reqres.in/api/users/936
{
  "name": "Serg",
  "job": "teacher",
  "updatedAt": "2025-09-13T19:49:17.401Z"
}
```

#### 📁 Лог-файл:

[Полный лог запроса](./PUT.log)

#### Метод PATCH (Частично обновить)

Обновим только профессию моего пользователя с id = 936

```bash
serg@serg-pc:~$ curl -s -X PATCH \
     -H "Content-Type: application/json" \
     -H "x-api-key: reqres-free-v1" \
     -d '{"job":"Senior Boss"}' \
     https://reqres.in/api/users/936
{
  "job": "Senior Boss",
  "updatedAt": "2025-09-13T19:52:39.185Z"
}
```

#### 📁 Лог-файл:

[Полный лог запроса](./PATCH.log)

#### Метод DELETE (Удалить)

Удалим моего пользователя с id = 936

```bash
serg@serg-pc:~$ curl -s -X DELETE \
     -H "x-api-key: reqres-free-v1" \
     https://reqres.in/api/user936/2
```

Ответа от сервиса не поступило, но был HTTP код 200.

Сделав проверку GET запросом на наличие пользователя с id = 936, в ответ я получил

```bash
{}
```


