# Система сетевого мониторинга

## Система состоит из следующих блоков:

- Определение принадлежности IP-адресов к автономным системам через WHOIS/RADB;

- Парсинг логов HTTP-сервера и обогащение данных информацией об AS;



## Определение принадлежности IP-адресов к автономным системам через WHOIS/RADB

**Цель:** Создать модуль, который по любому IP-адресу определяет номер автономной системы (ASN) и информацию о провайдере.

#### Реализация

Для начала установим виртуальное окружение Python в нужном нам каталоге, если его нет, при помощи команды:

```bash
python3 -m venv venv
```

Далее активируем его:

```bash
source venv/bin/activate
```

В каталоге "1. Determining_whether_IP_addresses_belong_to_autonomous_systems" ставим зависимости Python из файла [requirements.txt](./1. Determining_whether_IP_addresses_belong_to_autonomous_systems/requirements.txt) при помощи команды:

```bash
pip install -r requirements.txt
```

В этом же каталоге создаём скрипт [asn_lookup.py](./1. Determining_whether_IP_addresses_belong_to_autonomous_systems/asn_lookup.py):

```python
#!/usr/bin/env python3
"""
Модуль для определения автономной системы по IP-адресу
"""

import ipaddress
from ipwhois import IPWhois
import requests
import json
import sys
from typing import Dict, Optional, Tuple

class ASNLookup:
    def __init__(self):
        self.cache = {}  # Простой кеш для повторяющихся запросов
    
    def get_asn_info(self, ip_str: str) -> Optional[Dict]:
        """
        Получает информацию об ASN для указанного IP-адреса
        
        Args:
            ip_str: IP-адрес в строковом формате
            
        Returns:
            Словарь с информацией об ASN или None в случае ошибки
        """
        try:
            # Проверяем кеш
            if ip_str in self.cache:
                return self.cache[ip_str]
            
            # Валидация IP-адреса
            ipaddress.ip_address(ip_str)
            
            # Используем ipwhois для получения информации
            obj = IPWhois(ip_str)
            results = obj.lookup_rdap(depth=1)
            
            # Извлекаем нужную информацию
            asn_info = {
                'ip': ip_str,
                'asn': results.get('asn'),
                'asn_description': results.get('asn_description'),
                'network_name': results.get('network', {}).get('name'),
                'network_range': results.get('network', {}).get('cidr'),
                'country': results.get('asn_country_code'),
                'raw_data': results  # Полные данные для отладки
            }
            
            # Сохраняем в кеш
            self.cache[ip_str] = asn_info
            return asn_info
            
        except ValueError as e:
            print(f"Ошибка: Неверный IP-адрес {ip_str}: {e}")
            return None
        except Exception as e:
            print(f"Ошибка при запросе информации для {ip_str}: {e}")
            return None
    
    def get_asn_info_radb(self, ip_str: str) -> Optional[Dict]:
        """
        Альтернативный метод через RADB (whois.radb.net)
        """
        try:
            url = f"https://whois.radb.net/api/whois?q={ip_str}"
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                # Парсим ответ RADB (упрощенно)
                return {
                    'ip': ip_str,
                    'source': 'RADB',
                    'data': data
                }
            return None
            
        except Exception as e:
            print(f"Ошибка RADB для {ip_str}: {e}")
            return None

def main():
    """Тестирование модуля"""
    lookup = ASNLookup()
    
    # Тестовые IP-адреса
    test_ips = [
        '8.8.8.8',           # Google DNS
        '77.88.44.242',      # Yandex
        '87.240.132.72',     # VK
        '178.248.237.216',   # МТС
        'invalid_ip'         # Для теста ошибок
    ]
    
    print("Тестирование модуля определения ASN:")
    print("=" * 50)
    
    for ip in test_ips:
        print(f"\nIP: {ip}")
        result = lookup.get_asn_info(ip)
        
        if result:
            print(f"ASN: {result.get('asn', 'N/A')}")
            print(f"Описание: {result.get('asn_description', 'N/A')}")
            print(f"Сеть: {result.get('network_name', 'N/A')}")
            print(f"Диапазон: {result.get('network_range', 'N/A')}")
            print(f"Страна: {result.get('country', 'N/A')}")
        else:
            print("Не удалось получить информацию")

if __name__ == "__main__":
    main()
```

Далее тестируем скрипт, запустив командой:

```bash
python asn_lookup.py
```

В результате получаем:

```bash
(venv) evgeny@evgeny-sdl:~/tests$ python asn_lookup.py
Тестирование модуля определения ASN:
==================================================

IP: 8.8.8.8
ASN: 15169
Описание: GOOGLE, US
Сеть: GOGL
Диапазон: 8.8.8.0/24
Страна: US

IP: 77.88.44.242
ASN: 13238 208398
Описание: None
Сеть: YANDEX-77-88-44-0
Диапазон: 77.88.44.0/24
Страна: RU

IP: 87.240.132.72
ASN: 47541
Описание: VKONTAKTE-SPB-AS vk.com, RU
Сеть: VKONTAKTE-FRONT
Диапазон: 87.240.128.0/19
Страна: RU

IP: 178.248.237.216
ASN: 51115
Описание: HLL-AS, RU
Сеть: QRATOR-21804
Диапазон: 178.248.237.216/32
Страна: RU
```

## Парсинг логов HTTP-сервера и обогащение данных информацией об AS

**Цель:** Научиться читать логи Nginx/Apache, извлекать IP-адреса клиентов и обогащать их информацией об автономных системах.

#### Реализация

Установим дополнительные зависимости в виртуальной среде Python из файла [requirements.txt](./2. Parsing_HTTP_server_log/requirements.txt) при помощи команды:

```bash
pip install -r requirements.txt
```

Создаём скрипт Python - [log_parser.py](./2. Parsing_HTTP_server_logs/log_parser.py)

```python
#!/usr/bin/env python3
"""
Модуль для парсинга логов HTTP-сервера и обогащения IP-адресов информацией об AS
"""

import re
import gzip
from datetime import datetime
from pathlib import Path
from loguru import logger
import pandas as pd
from asn_lookup import ASNLookup  # Импортируем наш предыдущий модуль

class HTTPLogParser:
    def __init__(self):
        self.asn_lookup = ASNLookup()
        self.stats = {
            'total_lines': 0,
            'parsed_lines': 0,
            'unique_ips': set(),
            'errors': 0
        }
    
    def parse_nginx_line(self, line: str) -> dict:
        """
        Парсит одну строку лога Nginx в стандартном формате
        
        Стандартный формат Nginx:
        log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                       '$status $body_bytes_sent "$http_referer" '
                       '"$http_user_agent" "$http_x_forwarded_for"';
        """
        # Регулярное выражение для парсинга стандартного формата Nginx
        pattern = r'(\S+) - (\S+) \[([^\]]+)\] "(\S+) (\S+) (\S+)" (\d+) (\d+) "([^"]*)" "([^"]*)" "([^"]*)"'
        
        match = re.match(pattern, line)
        if not match:
            # Альтернативный паттерн
            alt_pattern = r'(\S+) - (\S+) \[([^\]]+)\] "([^"]*)" (\d+) (\d+) "([^"]*)" "([^"]*)"'
            match = re.match(alt_pattern, line)
            if not match:
                return None
        
        try:
            if len(match.groups()) >= 8:
                if len(match.groups()) == 11:
                    # Полный формат
                    remote_addr, remote_user, time_local, method, url, protocol, status, body_bytes_sent, referer, user_agent, x_forwarded_for = match.groups()
                else:
                    # Упрощенный формат
                    remote_addr, remote_user, time_local, request, status, body_bytes_sent, referer, user_agent = match.groups()
                    # Парсим request на method, url, protocol
                    request_parts = request.split()
                    method = request_parts[0] if len(request_parts) > 0 else ''
                    url = request_parts[1] if len(request_parts) > 1 else ''
                    protocol = request_parts[2] if len(request_proups) > 2 else ''
                    x_forwarded_for = ''
                
                # Парсим дату
                try:
                    # Преобразуем формат Nginx в datetime
                    dt = datetime.strptime(time_local.split()[0], '%d/%b/%Y:%H:%M:%S')
                    timestamp = dt.isoformat()
                except:
                    timestamp = time_local
                
                return {
                    'remote_addr': remote_addr,
                    'remote_user': remote_user,
                    'timestamp': timestamp,
                    'method': method,
                    'url': url,
                    'protocol': protocol,
                    'status': int(status),
                    'body_bytes_sent': int(body_bytes_sent),
                    'referer': referer,
                    'user_agent': user_agent,
                    'x_forwarded_for': x_forwarded_for
                }
        except Exception as e:
            logger.error(f"Ошибка парсинга строки: {e}")
            return None
        
        return None
    
    def read_log_file(self, file_path: str) -> list:
        """
        Читает log-файл (поддерживает обычные файлы и .gz)
        """
        logs = []
        
        try:
            file_path = Path(file_path)
            
            if file_path.suffix == '.gz':
                # Чтение gzip-файла
                with gzip.open(file_path, 'rt', encoding='utf-8') as f:
                    lines = f.readlines()
            else:
                # Чтение обычного файла
                with open(file_path, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
            
            for line_num, line in enumerate(lines, 1):
                self.stats['total_lines'] += 1
                line = line.strip()
                
                if not line or line.startswith('#'):
                    continue
                
                parsed = self.parse_nginx_line(line)
                if parsed:
                    logs.append(parsed)
                    self.stats['unique_ips'].add(parsed['remote_addr'])
                    self.stats['parsed_lines'] += 1
                else:
                    self.stats['errors'] += 1
                    if self.stats['errors'] <= 5:  # Логируем только первые 5 ошибок
                        logger.warning(f"Не удалось распарсить строку {line_num}: {line[:100]}...")
            
        except Exception as e:
            logger.error(f"Ошибка чтения файла {file_path}: {e}")
        
        return logs
    
    def enrich_with_asn(self, logs: list) -> list:
        """
        Обогащает логи информацией об автономных системах
        """
        enriched_logs = []
        
        for log_entry in logs:
            ip = log_entry['remote_addr']
            
            # Получаем информацию об ASN
            asn_info = self.asn_lookup.get_asn_info(ip)
            
            enriched_entry = log_entry.copy()
            if asn_info:
                enriched_entry.update({
                    'asn': asn_info.get('asn'),
                    'asn_description': asn_info.get('asn_description'),
                    'network_name': asn_info.get('network_name'),
                    'country': asn_info.get('country')
                })
            else:
                enriched_entry.update({
                    'asn': None,
                    'asn_description': None,
                    'network_name': None,
                    'country': None
                })
            
            enriched_logs.append(enriched_entry)
        
        return enriched_logs
    
    def analyze_logs(self, logs: list) -> dict:
        """
        Анализирует логи и выдает статистику
        """
        if not logs:
            return {}
        
        df = pd.DataFrame(logs)
        
        # Статистика по ASN
        asn_stats = df[df['asn'].notna()].groupby('asn').agg({
            'remote_addr': 'count',
            'asn_description': 'first',
            'country': 'first'
        }).rename(columns={'remote_addr': 'request_count'}).sort_values('request_count', ascending=False)
        
        # Статистика по странам
        country_stats = df[df['country'].notna()].groupby('country').size().sort_values(ascending=False)
        
        # Статистика по статусам
        status_stats = df.groupby('status').size().sort_values(ascending=False)
        
        return {
            'asn_stats': asn_stats.head(10).to_dict(),
            'country_stats': country_stats.head(10).to_dict(),
            'status_stats': status_stats.to_dict(),
            'total_requests': len(logs),
            'unique_ips': len(self.stats['unique_ips']),
            'time_range': {
                'start': min([log['timestamp'] for log in logs if log['timestamp']]),
                'end': max([log['timestamp'] for log in logs if log['timestamp']])
            } if any(log['timestamp'] for log in logs) else {}
        }

def main():
    """Тестирование парсера логов"""
    parser = HTTPLogParser()
    
    # Файл лога
    test_log_path = "access.log"
    
    print("Тестирование парсера HTTP-логов:")
    print("=" * 60)
    
    # Читаем и парсим логи
    logs = parser.read_log_file(test_log_path)
    print(f"Прочитано строк: {parser.stats['total_lines']}")
    print(f"Успешно распаршено: {parser.stats['parsed_lines']}")
    print(f"Уникальных IP-адресов: {len(parser.stats['unique_ips'])}")
    print(f"Ошибок парсинга: {parser.stats['errors']}")
    
    if logs:
        # Обогащаем данными об ASN
        enriched_logs = parser.enrich_with_asn(logs)
        
        print(f"\nОбогащено записей: {len(enriched_logs)}")
        
        # Показываем первые 3 обогащенные записи
        print("\nПервые 3 обогащенные записи:")
        for i, log in enumerate(enriched_logs[:3]):
            print(f"\nЗапись {i+1}:")
            print(f"  IP: {log['remote_addr']}")
            print(f"  ASN: {log.get('asn', 'N/A')}")
            print(f"  Описание AS: {log.get('asn_description', 'N/A')}")
            print(f"  Страна: {log.get('country', 'N/A')}")
            print(f"  URL: {log['method']} {log['url']}")
            print(f"  Статус: {log['status']}")
        
        # Анализируем логи
        analysis = parser.analyze_logs(enriched_logs)
        print(f"\nСтатистика анализа:")
        print(f"Всего запросов: {analysis['total_requests']}")
        print(f"Топ ASN по запросам: {analysis['asn_stats']}")
    
    # Удаляем тестовый файл
    Path(test_log_path).unlink(missing_ok=True)

if __name__ == "__main__":
    main()
```

Предоставляем скрипту в той же папке лог файл, пример - [access.log](./2. Parsing_HTTP_server_logs/access.log)

И запускаем скрипт:

```bash
python asn_lookup.py
```

И получаем вывод:

```bash
(venv) evgeny@evgeny-sdl:~/tests$ python log_parser.py
Тестирование парсера HTTP-логов:
============================================================
2025-09-15 15:44:33.681 | ERROR    | __main__:read_log_file:122 - Ошибка чтения файла access.log: [Errno 2] No such file or directory: 'access.log'
Прочитано строк: 0
Успешно распаршено: 0
Уникальных IP-адресов: 0
Ошибок парсинга: 0
(venv) alex@alex-work:~/tests$ python log_parser.py
Тестирование парсера HTTP-логов:
============================================================
Прочитано строк: 6
Успешно распаршено: 6
Уникальных IP-адресов: 6
Ошибок парсинга: 0
 
Обогащено записей: 6

Первые 3 обогащенные записи:

Запись 1:
  IP: 77.88.55.60
  ASN: 13238 208398
  Описание AS: None
  Страна: RU
  URL: GET /
  Статус: 200

Запись 2:
  IP: 87.240.134.10
  ASN: 47541
  Описание AS: VKONTAKTE-SPB-AS vk.com, RU
  Страна: RU
  URL: GET /feed2
  Статус: 200

Запись 3:
  IP: 95.167.123.45
  ASN: 12389
  Описание AS: ROSTELECOM-AS PJSC Rostelecom. Technical Team, RU
  Страна: RU
  URL: GET /
  Статус: 403

Статистика анализа:
Всего запросов: 6
Топ ASN по запросам: {'request_count': {'12389': 2, '13238 208398': 2, '47541': 2}, 'asn_description': {'12389': 'ROSTELECOM-AS PJSC Rostelecom. Technical Team, RU', '13238 208398': None, '47541': 'VKONTAKTE-SPB-AS vk.com, RU'}, 'country': {'12389': 'RU', '13238 208398': 'RU', '47541': 'RU'}}
```


