# RouterSim

Минимальный пример динамической маршрутизации между ≥6 узлами с возможностью:

- задавать метрики линков и их состояние (up/down);
- автоматически пересчитывать таблицы маршрутизации (алгоритм Дейкстры);
- отправлять «пакет» от узла A к узлу B с детальным логом пересылки на каждом хопе;
- демонстрировать альтернативные маршруты при изменении метрик/отказах.

## Структура проекта

```
router_sim/
├── main.py                 # Сценарий запуска/демо
├── network/
│   ├── link.py             # Класс Link — двунаправленная связь между двумя роутерами
│   ├── packet.py           # Класс Packet — упрощённый сетевой пакет (src,dst,payload,ttl)
│   ├── router.py           # Класс Router — интерфейсы, таблица маршрутизации, форвардинг
│   └── topology.py         # Класс Topology — сборка топологии, отправка пакетов, операции
└── README.md
```

## Как запустить

1. Убедитесь, что установлен Python 3.9+.

2. Перейдите в директорию проекта:
   
   ```bash
   cd router_sim
   ```

3. Запустите демонстрационный сценарий:
   
   ```bash
   python main.py
   ```

Вы увидите:

- снимки таблиц маршрутизации на всех узлах;
- лог доставки пакета A→F по кратчайшему пути;
- изменение метрики на канале B–E (до 50), перерасчёт таблиц и повторную отправку A→F по **другому** маршруту;
- отказ канала C–F (down), перерасчёт и отправку A→G (по A–D–G и т.д.).

## Как это работает (кратко про классы)

### `network.Link`

- Соединяет два роутера (двунаправленно).
- Имеет `metric` (стоимость) и флаг `up` (состояние линии).
- Позволяет менять метрику и состояние: `set_metric()`, `set_state()`.

### `network.Router`

- Хранит список интерфейсов (имя, IP, связанный `Link`).

- Метод `compute_routes()` запускает Дейкстру по графу «роутер—линк—роутер» и строит `routing_table`:
  
  ```py
  {destination_name: Route(next_hop, cost, path=[...])}
  ```

- Метод `forward(packet, all_routers, log)` реализует пересылку: ищет маршрут, уменьшает TTL, логирует переход и передаёт пакет соседу.

### `network.Topology`

- Содержит словарь роутеров и список линков.
- `Topology.sample()` строит пример с узлами **A..G** и несколькими альтернативными путями.
- `send(src, dst, payload)` — отправка пакета с пошаговым логом.
- `set_link_metric(a,b,val)` и `set_link_state(a,b,up)` — динамические изменения с автоматическим пересчётом маршрутов.
- `routing_tables_snapshot()` — удобный дамп таблиц для печати/проверок.

### `network.Packet`

- Упрощённая модель пакета (источник/получатель — имена роутеров), полезная нагрузка и TTL.

# Пример работы

```bash
=== Initial routing tables ===

Routing table at A:
DEST  NEXTHOP COST   PATH
A     None    0.00   A
B     B       1.00   A-B
C     B       2.00   A-B-C
D     D       3.00   A-D
E     B       3.00   A-B-E
F     F       2.00   A-F
G     D       4.00   A-D-G

Routing table at B:
DEST  NEXTHOP COST   PATH
A     A       1.00   B-A
B     None    0.00   B
C     C       1.00   B-C
D     E       3.00   B-E-D
E     E       2.00   B-E
F     A       3.00   B-A-F
G     E       4.00   B-E-D-G

Routing table at C:
DEST  NEXTHOP COST   PATH
A     B       2.00   C-B-A
B     B       1.00   C-B
C     None    0.00   C
D     B       4.00   C-B-E-D
E     B       3.00   C-B-E
F     F       2.00   C-F
G     B       5.00   C-B-E-D-G

Routing table at D:
DEST  NEXTHOP COST   PATH
A     A       3.00   D-A
B     E       3.00   D-E-B
C     E       4.00   D-E-F-C
D     None    0.00   D
E     E       1.00   D-E
F     E       2.00   D-E-F
G     G       1.00   D-G

Routing table at E:
DEST  NEXTHOP COST   PATH
A     F       3.00   E-F-A
B     B       2.00   E-B
C     F       3.00   E-F-C
D     D       1.00   E-D
E     None    0.00   E
F     F       1.00   E-F
G     D       2.00   E-D-G

Routing table at F:
DEST  NEXTHOP COST   PATH
A     A       2.00   F-A
B     E       3.00   F-E-B
C     C       2.00   F-C
D     E       2.00   F-E-D
E     E       1.00   F-E
F     None    0.00   F
G     E       3.00   F-E-D-G

Routing table at G:
DEST  NEXTHOP COST   PATH
A     D       4.00   G-D-A
B     D       4.00   G-D-E-B
C     D       5.00   G-D-E-F-C
D     D       1.00   G-D
E     D       2.00   G-D-E
F     D       3.00   G-D-E-F
G     None    0.00   G

=== Send A -> F (initial) ===
[A] Received packet (ttl=32) dst=F
[A] FORWARD -> F via cost=2.00 path=A-F
[F] Received packet (ttl=31) dst=F
[F] DELIVERED payload='hello F from A'
RESULT: Delivery success

=== Increase cost on B-E to 50 (simulate congestion) ===

Routing table at A:
DEST  NEXTHOP COST   PATH
A     None    0.00   A
B     B       1.00   A-B
C     B       2.00   A-B-C
D     D       3.00   A-D
E     F       3.00   A-F-E
F     F       2.00   A-F
G     D       4.00   A-D-G

Routing table at B:
DEST  NEXTHOP COST   PATH
A     A       1.00   B-A
B     None    0.00   B
C     C       1.00   B-C
D     A       4.00   B-A-D
E     A       4.00   B-A-F-E
F     A       3.00   B-A-F
G     A       5.00   B-A-D-G

Routing table at C:
DEST  NEXTHOP COST   PATH
A     B       2.00   C-B-A
B     B       1.00   C-B
C     None    0.00   C
D     F       4.00   C-F-E-D
E     F       3.00   C-F-E
F     F       2.00   C-F
G     F       5.00   C-F-E-D-G

Routing table at D:
DEST  NEXTHOP COST   PATH
A     A       3.00   D-A
B     A       4.00   D-A-B
C     E       4.00   D-E-F-C
D     None    0.00   D
E     E       1.00   D-E
F     E       2.00   D-E-F
G     G       1.00   D-G

Routing table at E:
DEST  NEXTHOP COST   PATH
A     F       3.00   E-F-A
B     F       4.00   E-F-A-B
C     F       3.00   E-F-C
D     D       1.00   E-D
E     None    0.00   E
F     F       1.00   E-F
G     D       2.00   E-D-G

Routing table at F:
DEST  NEXTHOP COST   PATH
A     A       2.00   F-A
B     A       3.00   F-A-B
C     C       2.00   F-C
D     E       2.00   F-E-D
E     E       1.00   F-E
F     None    0.00   F
G     E       3.00   F-E-D-G

Routing table at G:
DEST  NEXTHOP COST   PATH
A     D       4.00   G-D-A
B     D       5.00   G-D-A-B
C     D       5.00   G-D-E-F-C
D     D       1.00   G-D
E     D       2.00   G-D-E
F     D       3.00   G-D-E-F
G     None    0.00   G

=== Send A -> F after metric change (should reroute) ===
[A] Received packet (ttl=32) dst=F
[A] FORWARD -> F via cost=2.00 path=A-F
[F] Received packet (ttl=31) dst=F
[F] DELIVERED payload='reroute test'
RESULT: Delivery success

=== Bring down link C-F (failure) ===

Routing table at A:
DEST  NEXTHOP COST   PATH
A     None    0.00   A
B     B       1.00   A-B
C     B       2.00   A-B-C
D     D       3.00   A-D
E     F       3.00   A-F-E
F     F       2.00   A-F
G     D       4.00   A-D-G

Routing table at B:
DEST  NEXTHOP COST   PATH
A     A       1.00   B-A
B     None    0.00   B
C     C       1.00   B-C
D     A       4.00   B-A-D
E     A       4.00   B-A-F-E
F     A       3.00   B-A-F
G     A       5.00   B-A-D-G

Routing table at C:
DEST  NEXTHOP COST   PATH
A     B       2.00   C-B-A
B     B       1.00   C-B
C     None    0.00   C
D     D       5.00   C-D
E     B       5.00   C-B-A-F-E
F     B       4.00   C-B-A-F
G     D       6.00   C-D-G

Routing table at D:
DEST  NEXTHOP COST   PATH
A     A       3.00   D-A
B     A       4.00   D-A-B
C     C       5.00   D-C
D     None    0.00   D
E     E       1.00   D-E
F     E       2.00   D-E-F
G     G       1.00   D-G

Routing table at E:
DEST  NEXTHOP COST   PATH
A     F       3.00   E-F-A
B     F       4.00   E-F-A-B
C     F       5.00   E-F-A-B-C
D     D       1.00   E-D
E     None    0.00   E
F     F       1.00   E-F
G     D       2.00   E-D-G

Routing table at F:
DEST  NEXTHOP COST   PATH
A     A       2.00   F-A
B     A       3.00   F-A-B
C     A       4.00   F-A-B-C
D     E       2.00   F-E-D
E     E       1.00   F-E
F     None    0.00   F
G     E       3.00   F-E-D-G

Routing table at G:
DEST  NEXTHOP COST   PATH
A     D       4.00   G-D-A
B     D       5.00   G-D-A-B
C     D       6.00   G-D-C
D     D       1.00   G-D
E     D       2.00   G-D-E
F     D       3.00   G-D-E-F
G     None    0.00   G

=== Send A -> G after failure (still should work via A-D-G) ===
[A] Received packet (ttl=32) dst=G
[A] FORWARD -> D via cost=4.00 path=A-D-G
[D] Received packet (ttl=31) dst=G
[D] FORWARD -> G via cost=1.00 path=D-G
[G] Received packet (ttl=30) dst=G
[G] DELIVERED payload='to G despite failure'
RESULT: Delivery success
```
