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