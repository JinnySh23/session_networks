# Задачи по API

## **Задание**:

Начиная с URI https://swapi.tech/api/, (https://swapi.tech/api/) создать GET-запросы, которые вернут вам информацию по Звезде Смерти и Дарту Вейдеру

## Решение

Откроем терминал выполним GET запрос CURL для поиска всех людей: **curl https://swapi.tech/api/people**

```bash
serg@serg-pc:~$ curl https://swapi.tech/api/people
{"message":"ok","total_records":82,"total_pages":9,"previous":null,"next":"https://swapi.tech/api/people?page=2&limit=10","results":[{"uid":"1","name":"Luke Skywalker","url":"https://www.swapi.tech/api/people/1"},{"uid":"2","name":"C-3PO","url":"https://www.swapi.tech/api/people/2"},{"uid":"3","name":"R2-D2","url":"https://www.swapi.tech/api/people/3"},{"uid":"4","name":"Darth Vader","url":"https://www.swapi.tech/api/people/4"},{"uid":"5","name":"Leia Organa","url":"https://www.swapi.tech/api/people/5"},{"uid":"6","name":"Owen Lars","url":"https://www.swapi.tech/api/people/6"},{"uid":"7","name":"Beru Whitesun lars","url":"https://www.swapi.tech/api/people/7"},{"uid":"8","name":"R5-D4","url":"https://www.swapi.tech/api/people/8"},{"uid":"9","name":"Biggs Darklighter","url":"https://www.swapi.tech/api/people/9"},{"uid":"10","name":"Obi-Wan Kenobi","url":"https://www.swapi.tech/api/people/10"}],"apiVersion":"1.0","timestamp":"2025-09-12T16:40:29.902Z","support":{"contact":"admin@swapi.tech","donate":"https://www.paypal.com/donate/?business=2HGAUVTWGR5T2&no_recurring=0&item_name=Support+Swapi+and+keep+the+galaxy%27s+data+free%21+Your+donation+fuels+open-source+innovation+and+helps+us+grow.+Thank+you%21+%F0%9F%9A%80&currency_code=USD","partnerDiscounts":{"saberMasters":{"link":"https://www.swapi.tech/partner-discount/sabermasters-swapi","details":"Use this link to automatically get $10 off your purchase!"},"heartMath":{"link":"https://www.heartmath.com/ryanc","details":"Looking for some Jedi-like inner peace? Take 10% off your heart-brain coherence tools from the HeartMath Institute!"}}},"social":{"discord":"https://discord.gg/zWvA6GPeNG","reddit":"https://www.reddit.com/r/SwapiOfficial/","github":"https://github.com/semperry/swapi/blob/main/CONTRIBUTORS.md"}}
```

В ответ мы получили такой JSON:

```json
{
  "message": "ok",
  "total_records": 82,
  "total_pages": 9,
  "previous": null,
  "next": "https://swapi.tech/api/people?page=2&limit=10",
  "results": [
    {
      "uid": "1",
      "name": "Luke Skywalker",
      "url": "https://www.swapi.tech/api/people/1"
    },
    {
      "uid": "2",
      "name": "C-3PO",
      "url": "https://www.swapi.tech/api/people/2"
    },
    {
      "uid": "3",
      "name": "R2-D2",
      "url": "https://www.swapi.tech/api/people/3"
    },
    {
      "uid": "4",
      "name": "Darth Vader",
      "url": "https://www.swapi.tech/api/people/4"
    },
    {
      "uid": "5",
      "name": "Leia Organa",
      "url": "https://www.swapi.tech/api/people/5"
    },
    {
      "uid": "6",
      "name": "Owen Lars",
      "url": "https://www.swapi.tech/api/people/6"
    },
    {
      "uid": "7",
      "name": "Beru Whitesun lars",
      "url": "https://www.swapi.tech/api/people/7"
    },
    {
      "uid": "8",
      "name": "R5-D4",
      "url": "https://www.swapi.tech/api/people/8"
    },
    {
      "uid": "9",
      "name": "Biggs Darklighter",
      "url": "https://www.swapi.tech/api/people/9"
    },
    {
      "uid": "10",
      "name": "Obi-Wan Kenobi",
      "url": "https://www.swapi.tech/api/people/10"
    }
  ],
  "apiVersion": "1.0",
  "timestamp": "2025-09-12T16:40:29.902Z",
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

Видим, что у Дарт Вейдера **uid = 4**. Следовательно, формируем такой GET запрос: **curl https://swapi.tech/api/people/4**

```bash
serg@serg-pc:~$ curl https://swapi.tech/api/people/4
{"message":"ok","result":{"properties":{"created":"2025-09-12T09:37:19.660Z","edited":"2025-09-12T09:37:19.660Z","name":"Darth Vader","gender":"male","skin_color":"white","hair_color":"none","height":"202","eye_color":"yellow","mass":"136","homeworld":"https://www.swapi.tech/api/planets/1","birth_year":"41.9BBY","vehicles":[],"starships":["https://www.swapi.tech/api/starships/13"],"films":["https://www.swapi.tech/api/films/1","https://www.swapi.tech/api/films/2","https://www.swapi.tech/api/films/3","https://www.swapi.tech/api/films/6"],"url":"https://www.swapi.tech/api/people/4"},"_id":"5f63a36eee9fd7000499be45","description":"A person within the Star Wars universe","uid":"4","__v":4},"apiVersion":"1.0","timestamp":"2025-09-12T16:44:29.976Z","support":{"contact":"admin@swapi.tech","donate":"https://www.paypal.com/donate/?business=2HGAUVTWGR5T2&no_recurring=0&item_name=Support+Swapi+and+keep+the+galaxy%27s+data+free%21+Your+donation+fuels+open-source+innovation+and+helps+us+grow.+Thank+you%21+%F0%9F%9A%80&currency_code=USD","partnerDiscounts":{"saberMasters":{"link":"https://www.swapi.tech/partner-discount/sabermasters-swapi","details":"Use this link to automatically get $10 off your purchase!"},"heartMath":{"link":"https://www.heartmath.com/ryanc","details":"Looking for some Jedi-like inner peace? Take 10% off your heart-brain coherence tools from the HeartMath Institute!"}}},"social":{"discord":"https://discord.gg/zWvA6GPeNG","reddit":"https://www.reddit.com/r/SwapiOfficial/","github":"https://github.com/semperry/swapi/blob/main/CONTRIBUTORS.md"}}
```

В ответ получаем такой JSON:

```json
{
  "message": "ok",
  "result": {
    "properties": {
      "created": "2025-09-12T09:37:19.660Z",
      "edited": "2025-09-12T09:37:19.660Z",
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
  },
  "apiVersion": "1.0",
  "timestamp": "2025-09-12T16:44:29.976Z",
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

В данном ответе содержится информация о Дарте Вейдере:

#### Общие данные

- **Имя:** Darth Vader;

- **Пол:** male;

- **Цвет кожи:** white;

- **Цвет волос:** none;

- **Цвет глаз:** yellow;

- **Рост:** 202 см;

- **Масса:** 136 кг;

- **Год рождения:** 41.9BBY (до битвы при Явине);

- **Родной мир:** - делаем запрос **curl "https://www.swapi.tech/api/planets/1"** - ответ, что это планета **Tatooine**;

#### Связи

- **Звёздные корабли:**
  
  - Делаем запрос **curl https://www.swapi.tech/api/starships/13** и получаем ответ, что его личный истребитель называется - TIE Advanced x1;

- **Фильмы в которых был Дарт Вейдер:**
  
  - `https://www.swapi.tech/api/films/1` (по запросу это "Новая надежда")
  
  - `https://www.swapi.tech/api/films/2` (по запросу это "Империя наносит ответный удар")
  
  - `https://www.swapi.tech/api/films/3` (по запросу это "Возвращение джедая")
  
  - `https://www.swapi.tech/api/films/6` (по запросу это "Месть ситхов")

- **Транспорт / Vehicles:** пусто (он не использует наземный транспорт в фильмах).

Теперь создаём GET запрос на поиск всех звездолётов в базе сайта: **curl https://swapi.tech/api/starships**

```bash
serg@serg-pc:~$ curl https://swapi.tech/api/starships
{"message":"ok","total_records":36,"total_pages":4,"previous":null,"next":"https://swapi.tech/api/starships?page=2&limit=10","results":[{"uid":"2","name":"CR90 corvette","url":"https://www.swapi.tech/api/starships/2"},{"uid":"3","name":"Star Destroyer","url":"https://www.swapi.tech/api/starships/3"},{"uid":"5","name":"Sentinel-class landing craft","url":"https://www.swapi.tech/api/starships/5"},{"uid":"9","name":"Death Star","url":"https://www.swapi.tech/api/starships/9"},{"uid":"11","name":"Y-wing","url":"https://www.swapi.tech/api/starships/11"},{"uid":"10","name":"Millennium Falcon","url":"https://www.swapi.tech/api/starships/10"},{"uid":"13","name":"TIE Advanced x1","url":"https://www.swapi.tech/api/starships/13"},{"uid":"15","name":"Executor","url":"https://www.swapi.tech/api/starships/15"},{"uid":"12","name":"X-wing","url":"https://www.swapi.tech/api/starships/12"},{"uid":"17","name":"Rebel transport","url":"https://www.swapi.tech/api/starships/17"}],"apiVersion":"1.0","timestamp":"2025-09-12T16:52:55.047Z","support":{"contact":"admin@swapi.tech","donate":"https://www.paypal.com/donate/?business=2HGAUVTWGR5T2&no_recurring=0&item_name=Support+Swapi+and+keep+the+galaxy%27s+data+free%21+Your+donation+fuels+open-source+innovation+and+helps+us+grow.+Thank+you%21+%F0%9F%9A%80&currency_code=USD","partnerDiscounts":{"saberMasters":{"link":"https://www.swapi.tech/partner-discount/sabermasters-swapi","details":"Use this link to automatically get $10 off your purchase!"},"heartMath":{"link":"https://www.heartmath.com/ryanc","details":"Looking for some Jedi-like inner peace? Take 10% off your heart-brain coherence tools from the HeartMath Institute!"}}},"social":{"discord":"https://discord.gg/zWvA6GPeNG","reddit":"https://www.reddit.com/r/SwapiOfficial/","github":"https://github.com/semperry/swapi/blob/main/CONTRIBUTORS.md"}}
```

В ответ получаем такой JSON:

```json
{
  "message": "ok",
  "total_records": 36,
  "total_pages": 4,
  "previous": null,
  "next": "https://swapi.tech/api/starships?page=2&limit=10",
  "results": [
    {
      "uid": "2",
      "name": "CR90 corvette",
      "url": "https://www.swapi.tech/api/starships/2"
    },
    {
      "uid": "3",
      "name": "Star Destroyer",
      "url": "https://www.swapi.tech/api/starships/3"
    },
    {
      "uid": "5",
      "name": "Sentinel-class landing craft",
      "url": "https://www.swapi.tech/api/starships/5"
    },
    {
      "uid": "9",
      "name": "Death Star",
      "url": "https://www.swapi.tech/api/starships/9"
    },
    {
      "uid": "11",
      "name": "Y-wing",
      "url": "https://www.swapi.tech/api/starships/11"
    },
    {
      "uid": "10",
      "name": "Millennium Falcon",
      "url": "https://www.swapi.tech/api/starships/10"
    },
    {
      "uid": "13",
      "name": "TIE Advanced x1",
      "url": "https://www.swapi.tech/api/starships/13"
    },
    {
      "uid": "15",
      "name": "Executor",
      "url": "https://www.swapi.tech/api/starships/15"
    },
    {
      "uid": "12",
      "name": "X-wing",
      "url": "https://www.swapi.tech/api/starships/12"
    },
    {
      "uid": "17",
      "name": "Rebel transport",
      "url": "https://www.swapi.tech/api/starships/17"
    }
  ],
  "apiVersion": "1.0",
  "timestamp": "2025-09-12T16:52:55.047Z",
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

Видим, что у Звездв смерти **uid = 9**. Следовательно, Звезду смерти ищем при помощи GET запроса: **curl https://swapi.tech/api/starships/9**

```bash
serg@serg-pc:~$ curl https://swapi.tech/api/starships/9
{"message":"ok","result":{"properties":{"created":"2025-09-12T09:37:19.669Z","edited":"2025-09-12T09:37:19.669Z","consumables":"3 years","name":"Death Star","cargo_capacity":"1000000000000","passengers":"843,342","max_atmosphering_speed":"n/a","crew":"342,953","length":"120000","model":"DS-1 Orbital Battle Station","cost_in_credits":"1000000000000","manufacturer":"Imperial Department of Military Research, Sienar Fleet Systems","pilots":[],"MGLT":"10","starship_class":"Deep Space Mobile Battlestation","hyperdrive_rating":"4.0","films":["https://www.swapi.tech/api/films/1"],"url":"https://www.swapi.tech/api/starships/9"},"_id":"5f63a34fee9fd7000499be21","description":"A Starship","uid":"9","__v":2},"apiVersion":"1.0","timestamp":"2025-09-12T16:56:28.140Z","support":{"contact":"admin@swapi.tech","donate":"https://www.paypal.com/donate/?business=2HGAUVTWGR5T2&no_recurring=0&item_name=Support+Swapi+and+keep+the+galaxy%27s+data+free%21+Your+donation+fuels+open-source+innovation+and+helps+us+grow.+Thank+you%21+%F0%9F%9A%80&currency_code=USD","partnerDiscounts":{"saberMasters":{"link":"https://www.swapi.tech/partner-discount/sabermasters-swapi","details":"Use this link to automatically get $10 off your purchase!"},"heartMath":{"link":"https://www.heartmath.com/ryanc","details":"Looking for some Jedi-like inner peace? Take 10% off your heart-brain coherence tools from the HeartMath Institute!"}}},"social":{"discord":"https://discord.gg/zWvA6GPeNG","reddit":"https://www.reddit.com/r/SwapiOfficial/","github":"https://github.com/semperry/swapi/blob/main/CONTRIBUTORS.md"}}
```

В ответ мы получили такой JSON:

```json
{
  "message": "ok",
  "result": {
    "properties": {
      "created": "2025-09-12T09:37:19.669Z",
      "edited": "2025-09-12T09:37:19.669Z",
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
  },
  "apiVersion": "1.0",
  "timestamp": "2025-09-12T16:56:28.140Z",
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

#### Общие сведения

- **Название:** Death Star;

- **Модель:** DS-1 Orbital Battle Station;

- **Класс:** Deep Space Mobile Battlestation (глубококосмическая мобильная боевая станция);

- **Производитель:** Imperial Department of Military Research, Sienar Fleet Systems;

#### Размеры и вместимость

- **Длина (диаметр):** 120000 м (120 км);

- **Экипаж:** 342,953;

- **Пассажиры:** 843,342;

- **Грузоподъёмность:** 1,000,000,000,000 (1 триллион единиц);

- **Запасы провизии:** 3 years;

#### Технические характеристики

- **Стоимость:** 1,000,000,000,000 кредитов;

- **Максимальная скорость в атмосфере:** n/a (не рассчитана для атмосферы);

- **MGLT (скорость в космосе):** 10;

- **Гипердвигатель:** 4.0 (очень медленный по меркам SW);

#### Связи

- **Фильмы:** делаем запрос **curl https://www.swapi.tech/api/films/1** и получаем ответ, что звезда смерти появлялась в фильме "A New Hope" (Новая надежда);

- **Пилоты:** пусто (станция не имеет индивидуального пилота);
