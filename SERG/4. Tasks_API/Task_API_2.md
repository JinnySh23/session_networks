# Задачи по API

## **Задание**:

Используя сайт открытого API Рика и Морти ((https://rickandmortyapi.com/)https://rickandmortyapi.com/), (https://rickandmortyapi.com/) создать GET-запросы на получение информации по 11 и 22 эпизодам (в одном запросе) и Пост-Апокалиптической Земле

## Решение

Создадим GET-запрос, который сразу получает информацию о двух эпизодах: 11 и 22: **curl "https://rickandmortyapi.com/api/episode/11,22"**

```bash
serg@serg-pc:~$ curl "https://rickandmortyapi.com/api/episode/11,22"
[{"id":11,"name":"Ricksy Business","air_date":"April 14, 2014","episode":"S01E11","characters":["https://rickandmortyapi.com/api/character/1","https://rickandmortyapi.com/api/character/2","https://rickandmortyapi.com/api/character/3","https://rickandmortyapi.com/api/character/4","https://rickandmortyapi.com/api/character/5","https://rickandmortyapi.com/api/character/7","https://rickandmortyapi.com/api/character/35","https://rickandmortyapi.com/api/character/47","https://rickandmortyapi.com/api/character/58","https://rickandmortyapi.com/api/character/88","https://rickandmortyapi.com/api/character/180","https://rickandmortyapi.com/api/character/181","https://rickandmortyapi.com/api/character/210","https://rickandmortyapi.com/api/character/216","https://rickandmortyapi.com/api/character/251","https://rickandmortyapi.com/api/character/282","https://rickandmortyapi.com/api/character/295","https://rickandmortyapi.com/api/character/308","https://rickandmortyapi.com/api/character/326","https://rickandmortyapi.com/api/character/327","https://rickandmortyapi.com/api/character/331","https://rickandmortyapi.com/api/character/333","https://rickandmortyapi.com/api/character/344","https://rickandmortyapi.com/api/character/362","https://rickandmortyapi.com/api/character/389","https://rickandmortyapi.com/api/character/395","https://rickandmortyapi.com/api/character/405","https://rickandmortyapi.com/api/character/423","https://rickandmortyapi.com/api/character/435","https://rickandmortyapi.com/api/character/436"],"url":"https://rickandmortyapi.com/api/episode/11","created":"2017-11-10T12:56:34.850Z"},{"id":22,"name":"The Rickshank Rickdemption","air_date":"April 1, 2017","episode":"S03E01","characters":["https://rickandmortyapi.com/api/character/1","https://rickandmortyapi.com/api/character/2","https://rickandmortyapi.com/api/character/3","https://rickandmortyapi.com/api/character/4","https://rickandmortyapi.com/api/character/5","https://rickandmortyapi.com/api/character/21","https://rickandmortyapi.com/api/character/22","https://rickandmortyapi.com/api/character/38","https://rickandmortyapi.com/api/character/42","https://rickandmortyapi.com/api/character/47","https://rickandmortyapi.com/api/character/48","https://rickandmortyapi.com/api/character/57","https://rickandmortyapi.com/api/character/69","https://rickandmortyapi.com/api/character/71","https://rickandmortyapi.com/api/character/86","https://rickandmortyapi.com/api/character/94","https://rickandmortyapi.com/api/character/95","https://rickandmortyapi.com/api/character/103","https://rickandmortyapi.com/api/character/150","https://rickandmortyapi.com/api/character/152","https://rickandmortyapi.com/api/character/175","https://rickandmortyapi.com/api/character/200","https://rickandmortyapi.com/api/character/215","https://rickandmortyapi.com/api/character/231","https://rickandmortyapi.com/api/character/240","https://rickandmortyapi.com/api/character/274","https://rickandmortyapi.com/api/character/285","https://rickandmortyapi.com/api/character/286","https://rickandmortyapi.com/api/character/294","https://rickandmortyapi.com/api/character/295","https://rickandmortyapi.com/api/character/330","https://rickandmortyapi.com/api/character/338","https://rickandmortyapi.com/api/character/344","https://rickandmortyapi.com/api/character/378","https://rickandmortyapi.com/api/character/380","https://rickandmortyapi.com/api/character/385","https://rickandmortyapi.com/api/character/389","https://rickandmortyapi.com/api/character/461","https://rickandmortyapi.com/api/character/462","https://rickandmortyapi.com/api/character/463","https://rickandmortyapi.com/api/character/464","https://rickandmortyapi.com/api/character/465","https://rickandmortyapi.com/api/character/466","https://rickandmortyapi.com/api/character/592"],"url":"https://rickandmortyapi.com/api/episode/22","created":"2017-11-10T12:56:35.983Z"}]
```

Обратим внимание, что в ответ мы получили массив из 2-х объектов, поскольку мы запросили информацию, не об одном эпизоде, а о двух:

```json
[
  {
    "id": 11,
    "name": "Ricksy Business",
    "air_date": "April 14, 2014",
    "episode": "S01E11",
    "characters": [
      "https://rickandmortyapi.com/api/character/1",
      "https://rickandmortyapi.com/api/character/2",
      "https://rickandmortyapi.com/api/character/3",
      "https://rickandmortyapi.com/api/character/4",
      "https://rickandmortyapi.com/api/character/5",
      "https://rickandmortyapi.com/api/character/7",
      "https://rickandmortyapi.com/api/character/35",
      "https://rickandmortyapi.com/api/character/47",
      "https://rickandmortyapi.com/api/character/58",
      "https://rickandmortyapi.com/api/character/88",
      "https://rickandmortyapi.com/api/character/180",
      "https://rickandmortyapi.com/api/character/181",
      "https://rickandmortyapi.com/api/character/210",
      "https://rickandmortyapi.com/api/character/216",
      "https://rickandmortyapi.com/api/character/251",
      "https://rickandmortyapi.com/api/character/282",
      "https://rickandmortyapi.com/api/character/295",
      "https://rickandmortyapi.com/api/character/308",
      "https://rickandmortyapi.com/api/character/326",
      "https://rickandmortyapi.com/api/character/327",
      "https://rickandmortyapi.com/api/character/331",
      "https://rickandmortyapi.com/api/character/333",
      "https://rickandmortyapi.com/api/character/344",
      "https://rickandmortyapi.com/api/character/362",
      "https://rickandmortyapi.com/api/character/389",
      "https://rickandmortyapi.com/api/character/395",
      "https://rickandmortyapi.com/api/character/405",
      "https://rickandmortyapi.com/api/character/423",
      "https://rickandmortyapi.com/api/character/435",
      "https://rickandmortyapi.com/api/character/436"
    ],
    "url": "https://rickandmortyapi.com/api/episode/11",
    "created": "2017-11-10T12:56:34.850Z"
  },
  {
    "id": 22,
    "name": "The Rickshank Rickdemption",
    "air_date": "April 1, 2017",
    "episode": "S03E01",
    "characters": [
      "https://rickandmortyapi.com/api/character/1",
      "https://rickandmortyapi.com/api/character/2",
      "https://rickandmortyapi.com/api/character/3",
      "https://rickandmortyapi.com/api/character/4",
      "https://rickandmortyapi.com/api/character/5",
      "https://rickandmortyapi.com/api/character/21",
      "https://rickandmortyapi.com/api/character/22",
      "https://rickandmortyapi.com/api/character/38",
      "https://rickandmortyapi.com/api/character/42",
      "https://rickandmortyapi.com/api/character/47",
      "https://rickandmortyapi.com/api/character/48",
      "https://rickandmortyapi.com/api/character/57",
      "https://rickandmortyapi.com/api/character/69",
      "https://rickandmortyapi.com/api/character/71",
      "https://rickandmortyapi.com/api/character/86",
      "https://rickandmortyapi.com/api/character/94",
      "https://rickandmortyapi.com/api/character/95",
      "https://rickandmortyapi.com/api/character/103",
      "https://rickandmortyapi.com/api/character/150",
      "https://rickandmortyapi.com/api/character/152",
      "https://rickandmortyapi.com/api/character/175",
      "https://rickandmortyapi.com/api/character/200",
      "https://rickandmortyapi.com/api/character/215",
      "https://rickandmortyapi.com/api/character/231",
      "https://rickandmortyapi.com/api/character/240",
      "https://rickandmortyapi.com/api/character/274",
      "https://rickandmortyapi.com/api/character/285",
      "https://rickandmortyapi.com/api/character/286",
      "https://rickandmortyapi.com/api/character/294",
      "https://rickandmortyapi.com/api/character/295",
      "https://rickandmortyapi.com/api/character/330",
      "https://rickandmortyapi.com/api/character/338",
      "https://rickandmortyapi.com/api/character/344",
      "https://rickandmortyapi.com/api/character/378",
      "https://rickandmortyapi.com/api/character/380",
      "https://rickandmortyapi.com/api/character/385",
      "https://rickandmortyapi.com/api/character/389",
      "https://rickandmortyapi.com/api/character/461",
      "https://rickandmortyapi.com/api/character/462",
      "https://rickandmortyapi.com/api/character/463",
      "https://rickandmortyapi.com/api/character/464",
      "https://rickandmortyapi.com/api/character/465",
      "https://rickandmortyapi.com/api/character/466",
      "https://rickandmortyapi.com/api/character/592"
    ],
    "url": "https://rickandmortyapi.com/api/episode/22",
    "created": "2017-11-10T12:56:35.983Z"
  }
]
```

Рассмотрим наш результат:

#### Эпизод 11

- **ID:** 11;

- **Название:** Ricksy Business;

- **Дата выхода:** April 14, 2014;

- **Сезон и серия:** S01E11 (1 сезон, 11 серия);

- **Персонажи:** массив ссылок на персонажей;

- **Ссылка на сам эпизод в API:** https://rickandmortyapi.com/api/episode/11

- **Дата добавления в базу данных:** 2017-11-10T12:56:34.850Z;

#### Эпизод 22

- **ID:** 22;

- **Название:** The Rickshank Rickdemption;

- **Дата выхода:** April 1, 2017;

- **Сезон и серия:** S03E01 (3 сезон, 1 серия);

- **Персонажи:** массив ссылок на персонажей;

- **Ссылка на сам эпизод в API:** https://rickandmortyapi.com/api/episode/22

- **Дата добавления в базу данных:** 2017-11-10T12:56:35.983Z;

Далее сформируем GET запрос, который получит информацию о Пост-Апокалиптической Земле, использовав GET-параметр "<u>name</u>" (%20 - символ пробела): **curl "https://rickandmortyapi.com/api/location/?name=Post-Apocalyptic%20Earth"**

```bash
serg@serg-pc:~$ curl "https://rickandmortyapi.com/api/location/?name=Post-Apocalyptic%20Earth"
{"info":{"count":1,"pages":1,"next":null,"prev":null},"results":[{"id":8,"name":"Post-Apocalyptic Earth","type":"Planet","dimension":"Post-Apocalyptic Dimension","residents":["https://rickandmortyapi.com/api/character/25","https://rickandmortyapi.com/api/character/52","https://rickandmortyapi.com/api/character/68","https://rickandmortyapi.com/api/character/110","https://rickandmortyapi.com/api/character/111","https://rickandmortyapi.com/api/character/140","https://rickandmortyapi.com/api/character/156","https://rickandmortyapi.com/api/character/228","https://rickandmortyapi.com/api/character/323","https://rickandmortyapi.com/api/character/342"],"url":"https://rickandmortyapi.com/api/location/8","created":"2017-11-10T13:09:22.551Z"}]}
```

Получаем такой JSON в ответе:

```json
{
  "info": {
    "count": 1,
    "pages": 1,
    "next": null,
    "prev": null
  },
  "results": [
    {
      "id": 8,
      "name": "Post-Apocalyptic Earth",
      "type": "Planet",
      "dimension": "Post-Apocalyptic Dimension",
      "residents": [
        "https://rickandmortyapi.com/api/character/25",
        "https://rickandmortyapi.com/api/character/52",
        "https://rickandmortyapi.com/api/character/68",
        "https://rickandmortyapi.com/api/character/110",
        "https://rickandmortyapi.com/api/character/111",
        "https://rickandmortyapi.com/api/character/140",
        "https://rickandmortyapi.com/api/character/156",
        "https://rickandmortyapi.com/api/character/228",
        "https://rickandmortyapi.com/api/character/323",
        "https://rickandmortyapi.com/api/character/342"
      ],
      "url": "https://rickandmortyapi.com/api/location/8",
      "created": "2017-11-10T13:09:22.551Z"
    }
  ]
}
```

Какую основную информацию о локации мы получили?

#### Основные сведения

- **ID:** 8;

- **Название:** Post-Apocalyptic Earth;

- **Тип:** Planet (планета);

- **Измерение:** Post-Apocalyptic Dimension;

#### Жители

В поле **residents** перечислены ссылки на персонажей, связанных с этой локацией.

#### Служебные данные

- **URL:** https://rickandmortyapi.com/api/location/8

- **Дата создания в базе данных:** 2017-11-10T13:09:22.551Z
