# STP Protocol Simulation

## Описание проекта

Реализация алгоритма Spanning Tree Protocol (STP) на Python. Данная программа моделирует работу протокола STP на канальном уровне (уровень 2 модели OSI), который предотвращает образование петель в сетях с избыточными соединениями.

### Основные возможности

- **Реализация полного цикла STP**: Обнаружение корневого моста, выбор корневых портов, блокировка избыточных соединений;

- **Поддержка всех состояний портов**: BLOCKING, LISTENING, LEARNING, FORWARDING, DISABLED;

- **Обмен BPDU сообщениями**: Имитация протокольных сообщений между коммутаторами;

- **Обработка изменений топологии**: Автоматическое перестроение дерева при изменениях сети;

- **Визуализация состояний**: Подробный вывод информации о работе протокола;

## Структура проекта

```bash
stp-simulation/
├── stp_classes.py      # Основные классы STP (порты, коммутаторы, сообщения)
├── main.py             # Главная программа и симуляция сети
└── README.md           # Этот файл
```

## Требования

- Python 3.6 или выше;

- Операционная система: Windows, Linux, macOS;

- Дополнительные библиотеки не требуются (используются только стандартные модули Python);

## Установка и запуск

#### Основная демонстрация

```bash
python stp_simulation.py
```

#### Запуск с дополнительными опциями

```bash
# В файле stp_simulation.py можно раскомментировать строку:
# demo_network_changes()
# для демонстрации обработки изменений сети
```

## Использование

### Базовая конфигурация сети

Программа автоматически создает тестовую сеть из 3 коммутаторов:

- **Switch 100** (Bridge ID: 100) - станет корневым мостом (наименьший ID)

- **Switch 200** (Bridge ID: 200)

- **Switch 300** (Bridge ID: 300)

Топология соединений (образует петлю):

```bash
Switch 100 ─── Switch 200
    │               │
    └── Switch 300 ─┘
```

### Настройка собственной сети

Для создания собственной конфигурации сети измените функцию `main()` в `main.py`:

```python
def main():
    simulation = STPSimulation()
    
    # Создание коммутаторов
    switch1 = simulation.create_switch(100, "00:AA:BB:CC:DD:01")
    switch2 = simulation.create_switch(200, "00:AA:BB:CC:DD:02")
    
    # Соединение коммутаторов
    simulation.connect_switches(100, 1, 200, 1)
    
    simulation.start_simulation()
    time.sleep(30)
    simulation.stop_simulation()
```

### Состояния портов

- **BLOCKING** - порт заблокирован (не передает данные);

- **LISTENING** - порт слушает BPDU сообщения;

- **LEARNING** - порт изучает MAC-адреса;

- **FORWARDING** - порт передает данные;

- **DISABLED** - порт отключен;

### Параметры таймеров

- **Hello Time**: 2 секунды (частота отправки BPDU);

- **Max Age**: 20 секунд (время жизни информации);

- **Forward Delay**: 15 секунд (задержка перехода между состояниями);

## Устранение проблем

### Ошибка "ModuleNotFoundError"

Убедитесь, что все файлы находятся в одной папке:

- stp_classes.py

- main.py

### Программа завершается сразу после запуска

Увеличьте время работы в функции `main()`:

```python
time.sleep(60)  # вместо 30 секунд
```

### Не отображается информация о портах

Проверьте, что у коммутаторов созданы порты:

```python
switch.add_port(1, "00:AA:BB:CC:DD:01:01", cost=10)
```

### Пример работы

```bash
D:\ITMOStudies\Python_STP>python main.py
STP Protocol Simulation
========================================
Creating switches...

Connecting switches...
Connected Switch 100 Port 1 to Switch 200 Port 1
Connected Switch 100 Port 2 to Switch 300 Port 1
Connected Switch 200 Port 2 to Switch 300 Port 2
Starting STP Simulation...
Switch 100 STP started
Switch 200 STP started
Switch 300 STP started

Simulation running for 30 seconds...
Press Ctrl+C to stop early

==================================================
NETWORK STATUS
==================================================

=== Switch 100 Status ===
Root Bridge: 100
Is Root: True
Root Path Cost: 0
Root Port: None
Port States:
  Port 1: BLOCKING
  Port 2: BLOCKING
  Port 3: BLOCKING
  Port 4: BLOCKING

=== Switch 200 Status ===
Root Bridge: 200
Is Root: True
Root Path Cost: 0
Root Port: None
Port States:
  Port 1: BLOCKING
  Port 2: BLOCKING
  Port 3: BLOCKING
  Port 4: BLOCKING

=== Switch 300 Status ===
Root Bridge: 300
Is Root: True
Root Path Cost: 0
Root Port: None
Port States:
  Port 1: BLOCKING
  Port 2: BLOCKING
  Port 3: BLOCKING
  Port 4: BLOCKING
==================================================
```


