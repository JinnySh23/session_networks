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

if __name__ == "__main__":
    main()