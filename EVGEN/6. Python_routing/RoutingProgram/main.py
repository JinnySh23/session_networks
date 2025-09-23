import time
from network import create_test_network

def print_all_routing_tables(network):
    """Выводит таблицы маршрутизации всех маршрутизаторов"""
    for i in range(1, 7):
        router = network.get_router(f"R{i}")
        print(router.get_routing_table_str())

def demonstrate_network_operations():
    """Демонстрирует различные операции в сети"""
    print("=== Создание тестовой сети ===")
    network = create_test_network()
    
    print("\n=== Инициализация Link-State протокола ===")
    network.update_all_link_states()
    time.sleep(1)
    
    print("\n=== Таблицы маршрутизации после инициализации ===")
    print_all_routing_tables(network)
    
    print("\n=== Тест 1: Отправка пакета R1 -> R4 (короткий маршрут) ===")
    network.get_router("R1").send_packet("R4", "Hello from R1 to R4!")
    
    print("\n=== Тест 2: Имитация обрыва связи R3-R4 ===")
    network.simulate_link_failure("R3", "R4")
    time.sleep(1)
    
    print("\n=== Таблицы маршрутизации после обрыва ===")
    print_all_routing_tables(network)
    
    print("\n=== Тест 3: Отправка пакета R1 -> R4 (альтернативный маршрут) ===")
    network.get_router("R1").send_packet("R4", "Hello after link failure!")
    
    print("\n=== Тест 4: Отправка пакета R2 -> R6 ===")
    network.get_router("R2").send_packet("R6", "Hello from R2 to R6!")
    
    print("\n=== Тест 5: Восстановление связи R3-R4 ===")
    network.simulate_link_recovery("R3", "R4", "eth2", "eth1")
    time.sleep(1)
    
    print("\n=== Таблицы маршрутизации после восстановления ===")
    print_all_routing_tables(network)
    
    print("\n=== Тест 6: Отправка пакета R1 -> R4 (восстановленный маршрут) ===")
    network.get_router("R1").send_packet("R4", "Hello after link recovery!")

def interactive_mode():
    """Интерактивный режим для тестирования сети"""
    network = create_test_network()
    network.update_all_link_states()
    time.sleep(1)
    
    while True:
        print("\n" + "="*50)
        print("Интерактивный режим тестирования сети")
        print("1. Показать таблицы маршрутизации")
        print("2. Отправить пакет")
        print("3. Имитировать обрыв связи")
        print("4. Имитировать восстановление связи")
        print("5. Выход")
        
        choice = input("Выберите действие: ")
        
        if choice == "1":
            print_all_routing_tables(network)
        
        elif choice == "2":
            source = input("Отправитель (R1-R6): ").upper()
            destination = input("Получатель (R1-R6): ").upper()
            message = input("Сообщение: ")
            
            if source in network.routers and destination in network.routers:
                network.get_router(source).send_packet(destination, message)
            else:
                print("Ошибка: неверные имена маршрутизаторов")
        
        elif choice == "3":
            r1 = input("Первый маршрутизатор (R1-R6): ").upper()
            r2 = input("Второй маршрутизатор (R1-R6): ").upper()
            
            if r1 in network.routers and r2 in network.routers:
                network.simulate_link_failure(r1, r2)
                time.sleep(1)
            else:
                print("Ошибка: неверные имена маршрутизаторов")
        
        elif choice == "4":
            r1 = input("Первый маршрутизатор (R1-R6): ").upper()
            r2 = input("Второй маршрутизатор (R1-R6): ").upper()
            int1 = input(f"Интерфейс {r1}: ")
            int2 = input(f"Интерфейс {r2}: ")
            
            if r1 in network.routers and r2 in network.routers:
                network.simulate_link_recovery(r1, r2, int1, int2)
                time.sleep(1)
            else:
                print("Ошибка: неверные имена маршрутизаторов")
        
        elif choice == "5":
            break
        
        else:
            print("Неверный выбор")

if __name__ == "__main__":
    # Автоматическая демонстрация
    demonstrate_network_operations()