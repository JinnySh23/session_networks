# Задачи по API

## **Задание**:

Начиная с URI https://swapi.tech/api/, (https://swapi.tech/api/) создать GET-запросы, которые вернут вам информацию по Звезде Смерти и Дарту Вейдеру

## Решение

Откроем командную строку и сделаем запрос CURL для поиска Дарта Вейдера, воспользовавшись GET параметром <u>name</u>: **curl "https://www.swapi.tech/api/people/?name=darth%20vader"**

Пробел в имени кодируется как `%20`, поэтому добавляем его в GET параметр после darth

```bash
C:\Users\Evgeny>curl "https://www.swapi.tech/api/people/?name=darth%20vader"
{"message":"ok","result":[{"properties":{"created":"2025-09-15T09:37:19.660Z","edited":"2025-09-15T09:37:19.660Z","name":"Darth Vader","gender":"male","skin_color":"white","hair_color":"none","height":"202","eye_color":"yellow","mass":"136","homeworld":"https://www.swapi.tech/api/planets/1","birth_year":"41.9BBY","vehicles":[],"starships":["https://www.swapi.tech/api/starships/13"],"films":["https://www.swapi.tech/api/films/1","https://www.swapi.tech/api/films/2","https://www.swapi.tech/api/films/3","https://www.swapi.tech/api/films/6"],"url":"https://www.swapi.tech/api/people/4"},"_id":"5f63a36eee9fd7000499be45","description":"A person within the Star Wars universe","uid":"4","__v":4}],"apiVersion":"1.0","timestamp":"2025-09-15T16:02:00.682Z","support":{"contact":"admin@swapi.tech","donate":"https://www.paypal.com/donate/?business=2HGAUVTWGR5T2&no_recurring=0&item_name=Support+Swapi+and+keep+the+galaxy%27s+data+free%21+Your+donation+fuels+open-source+innovation+and+helps+us+grow.+Thank+you%21+%F0%9F%9A%80&currency_code=USD","partnerDiscounts":{"saberMasters":{"link":"https://www.swapi.tech/partner-discount/sabermasters-swapi","details":"Use this link to automatically get $10 off your purchase!"},"heartMath":{"link":"https://www.heartmath.com/ryanc","details":"Looking for some Jedi-like inner peace? Take 10% off your heart-brain coherence tools from the HeartMath Institute!"}}},"social":{"discord":"https://discord.gg/zWvA6GPeNG","reddit":"https://www.reddit.com/r/SwapiOfficial/","github":"https://github.com/semperry/swapi/blob/main/CONTRIBUTORS.md"}}
```

В ответ мы получили такой JSON:

```json
{
  "message": "ok",
  "result": [
    {
      "properties": {
        "created": "2025-09-15T09:37:19.660Z",
        "edited": "2025-09-15T09:37:19.660Z",
        "name": "Darth Vader",
        "gender": "male",
        "skin_color": "white",
        "hair_color": "none",
        "height": "202",
        "eye_color": "yellow",
        "mass": "136",
        "homeworld": "https://www.swapi.tech/api/planets/1",
        "birth_year": "41.9BBY",
        "vehicles": [],
        "starships": [
          "https://www.swapi.tech/api/starships/13"
        ],
        "films": [
          "https://www.swapi.tech/api/films/1",
          "https://www.swapi.tech/api/films/2",
          "https://www.swapi.tech/api/films/3",
          "https://www.swapi.tech/api/films/6"
        ],
        "url": "https://www.swapi.tech/api/people/4"
      },
      "_id": "5f63a36eee9fd7000499be45",
      "description": "A person within the Star Wars universe",
      "uid": "4",
      "__v": 4
    }
  ],
  "apiVersion": "1.0",
  "timestamp": "2025-09-15T16:02:00.682Z",
  "support": {
    "contact": "admin@swapi.tech",
    "donate": "https://www.paypal.com/donate/?business=2HGAUVTWGR5T2&no_recurring=0&item_name=Support+Swapi+and+keep+the+galaxy%27s+data+free%21+Your+donation+fuels+open-source+innovation+and+helps+us+grow.+Thank+you%21+%F0%9F%9A%80&currency_code=USD",
    "partnerDiscounts": {
      "saberMasters": {
        "link": "https://www.swapi.tech/partner-discount/sabermasters-swapi",
        "details": "Use this link to automatically get $10 off your purchase!"
      },
      "heartMath": {
        "link": "https://www.heartmath.com/ryanc",
        "details": "Looking for some Jedi-like inner peace? Take 10% off your heart-brain coherence tools from the HeartMath Institute!"
      }
    }
  },
  "social": {
    "discord": "https://discord.gg/zWvA6GPeNG",
    "reddit": "https://www.reddit.com/r/SwapiOfficial/",
    "github": "https://github.com/semperry/swapi/blob/main/CONTRIBUTORS.md"
  }
}
```

Тут содержится информация о Дарте Вейдере:

**Его персональные данные:**

- **Имя:** Darth Vader;

- **Пол:** male (мужской);

- **Год рождения:** 41.9BBY (за 41.9 года до битвы при Явине);

- **Родная планета:** делаем запрос **curl "https://www.swapi.tech/api/planets/1"** - ответ Tatooine;

**Физические характеристики:**

- **Рост:** 202 см;

- **Вес:** 136 кг;

- **Цвет кожи:** white (белый);

- **Цвет волос:** none (отсутствуют);

- **Цвет глаз:** yellow (жёлтые);

Также есть информация о его звездолёте, достаточно сделать CURL запрос: **curl https://www.swapi.tech/api/starships/13** и получаем информацию о данном звездолёте, имя которого - TIE Advanced x1

А Звезду смерти ищем в категории звездолётом, при помощи команды: **curl "https://www.swapi.tech/api/starships/?name=death%20star"**

```bash
C:\Users\Evgeny>curl "https://www.swapi.tech/api/starships/?name=death%20star"
{"message":"ok","result":[{"properties":{"created":"2025-09-15T09:37:19.669Z","edited":"2025-09-15T09:37:19.669Z","consumables":"3 years","name":"Death Star","cargo_capacity":"1000000000000","passengers":"843,342","max_atmosphering_speed":"n/a","crew":"342,953","length":"120000","model":"DS-1 Orbital Battle Station","cost_in_credits":"1000000000000","manufacturer":"Imperial Department of Military Research, Sienar Fleet Systems","pilots":[],"MGLT":"10","starship_class":"Deep Space Mobile Battlestation","hyperdrive_rating":"4.0","films":["https://www.swapi.tech/api/films/1"],"url":"https://www.swapi.tech/api/starships/9"},"_id":"5f63a34fee9fd7000499be21","description":"A Starship","uid":"9","__v":2}],"apiVersion":"1.0","timestamp":"2025-09-15T16:07:11.878Z","support":{"contact":"admin@swapi.tech","donate":"https://www.paypal.com/donate/?business=2HGAUVTWGR5T2&no_recurring=0&item_name=Support+Swapi+and+keep+the+galaxy%27s+data+free%21+Your+donation+fuels+open-source+innovation+and+helps+us+grow.+Thank+you%21+%F0%9F%9A%80&currency_code=USD","partnerDiscounts":{"saberMasters":{"link":"https://www.swapi.tech/partner-discount/sabermasters-swapi","details":"Use this link to automatically get $10 off your purchase!"},"heartMath":{"link":"https://www.heartmath.com/ryanc","details":"Looking for some Jedi-like inner peace? Take 10% off your heart-brain coherence tools from the HeartMath Institute!"}}},"social":{"discord":"https://discord.gg/zWvA6GPeNG","reddit":"https://www.reddit.com/r/SwapiOfficial/","github":"https://github.com/semperry/swapi/blob/main/CONTRIBUTORS.md"}}
```

В ответ мы получили такой JSON:

```json
{
  "message": "ok",
  "result": [
    {
      "properties": {
        "created": "2025-09-15T09:37:19.669Z",
        "edited": "2025-09-15T09:37:19.669Z",
        "consumables": "3 years",
        "name": "Death Star",
        "cargo_capacity": "1000000000000",
        "passengers": "843,342",
        "max_atmosphering_speed": "n/a",
        "crew": "342,953",
        "length": "120000",
        "model": "DS-1 Orbital Battle Station",
        "cost_in_credits": "1000000000000",
        "manufacturer": "Imperial Department of Military Research, Sienar Fleet Systems",
        "pilots": [],
        "MGLT": "10",
        "starship_class": "Deep Space Mobile Battlestation",
        "hyperdrive_rating": "4.0",
        "films": [
          "https://www.swapi.tech/api/films/1"
        ],
        "url": "https://www.swapi.tech/api/starships/9"
      },
      "_id": "5f63a34fee9fd7000499be21",
      "description": "A Starship",
      "uid": "9",
      "__v": 2
    }
  ],
  "apiVersion": "1.0",
  "timestamp": "2025-09-15T16:07:11.878Z",
  "support": {
    "contact": "admin@swapi.tech",
    "donate": "https://www.paypal.com/donate/?business=2HGAUVTWGR5T2&no_recurring=0&item_name=Support+Swapi+and+keep+the+galaxy%27s+data+free%21+Your+donation+fuels+open-source+innovation+and+helps+us+grow.+Thank+you%21+%F0%9F%9A%80&currency_code=USD",
    "partnerDiscounts": {
      "saberMasters": {
        "link": "https://www.swapi.tech/partner-discount/sabermasters-swapi",
        "details": "Use this link to automatically get $10 off your purchase!"
      },
      "heartMath": {
        "link": "https://www.heartmath.com/ryanc",
        "details": "Looking for some Jedi-like inner peace? Take 10% off your heart-brain coherence tools from the HeartMath Institute!"
      }
    }
  },
  "social": {
    "discord": "https://discord.gg/zWvA6GPeNG",
    "reddit": "https://www.reddit.com/r/SwapiOfficial/",
    "github": "https://github.com/semperry/swapi/blob/main/CONTRIBUTORS.md"
  }
}
```

О Звезде Смерти мы получили следующие данные:

**Размеры и масштаб:**

- **Длина:** 120,000 метров (120 км в диаметре!);

- **Класс:** "Deep Space Mobile Battlestation" (Мобильная боевая станция глубокого космоса);

**Экипаж и персонал:**

- **Экипаж:** 342,953 человека;

- **Пассажиры:** 843,342 человека;

- **Пилоты:** pilots: [] (пусто - управляется экипажем, а не пилотами);

**Технические параметры:**

- **Модель:** DS-1 Orbital Battle Station;

- **Скорость в атмосфере:** "n/a" (не предназначена для атмосферных полётов);

- **Гиперпривод:** 4.0 (средняя скорость для больших кораблей);

- **MGLT:** 10 (скорость в мегалахтах - довольно медленная для звёздолёта);

**Стоимость и производство:**

- **Стоимость:** 1,000,000,000,000 кредитов (1 триллион!);

- **Производители:** Imperial Department of Military Research, Sienar Fleet Systems;

**Грузоподъёмность и запасы:**

- **Грузоподъёмность:** 1,000,000,000,000 (1 триллион единиц);

- **Автономность:** 3 года (без дозаправки/пополнения запасов);

Также все оба ответа содержат кинематографическую информацию (в каких фильмах снимались) и служебные данные API запроса.
