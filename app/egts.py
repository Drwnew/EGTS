import multiprocessing
import socket
from processing_package import package_data_processing
from threading import Thread

from work_db import (
    # connect_main_db,
    Packet_data,
    # create_check_connect,
    # create_th_save_data,
)

from logger_files.logger import Logging
from logger_files.type_text import Types_text
import time
import os
from datetime import datetime

queue_length = int(os.getenv("SOCKET_QUEUE_LENGTH", 1))
devices_count = int(os.getenv("SOCKET_DEVICE_COUNT", 100))
server_port = int(os.getenv("SOCKET_SERVER_PORT", 44444))


# Процедура получения и отправки пакетов.
def receive_data(data, connection, data_for_db, logging):
    try:
        print("Получены данные:", data)
        print("Пакет получен: {d} - {data}".format(d=datetime.now().time().strftime("%H:%M:%S"), data=data))
        logging.logging(fromm=1, to=2, type_text=Types_text.SENT_DATA.value, text=data)

        packet = package_data_processing(data, data_for_db, logging)
        connection.send(packet)
        print("Отправлен пакет на пакет: {d} - {packet}".format(d=datetime.now().time().strftime("%H:%M:%S"), packet=packet))
        logging.logging(fromm=2, to=1, type_text=Types_text.SENT_DATA.value, text=packet)

    except KeyboardInterrupt:
        pass


def process_work(connection, address):
    """
    Процедура работы процесса.
    """
    try:
        print("process_work")
        data_for_db = Packet_data()
        logging_file = Logging(address)
        logging_file.logging(fromm=1, to=2, type_text=Types_text.CONNECTED.value)
        while True:
            data = connection.recv(1024)
            if not data:
                break
            t = Thread(target=receive_data, args=(data, connection, data_for_db, logging_file))
            t.start()
        logging_file.logging(fromm=1, to=2, type_text=Types_text.DISCONNECTED.value)
        connection.close()

    except Exception as e:
        raise e


def server_work():
    """
    Процедура работы сервера
    """
    process_list = []

    def check_process_count():
        """
        Процедура проверки живых процессов.
        """
        while True:
            for pr in process_list:
                if not pr.is_alive():
                    process_list.remove(pr)
            time.sleep(3)

    # Создаем поток сохранения данных в серверную бд.
    # create_th_save_data()
    port = server_port
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(("", port))
    server_socket.listen(queue_length)
    print(f"Сервер запущен и слушает порт {port}")
    t = Thread(target=check_process_count)  # Создаем новый поток для проверки живих процессов.
    t.start()
    try:
        while True:
            if len(process_list) <= devices_count:
                connection, address = server_socket.accept()
                print("Установлено соединение с {}".format(address))
                process = multiprocessing.Process(target=process_work, args=(connection, address))
                process.start()
                process_list.append(process)
    except KeyboardInterrupt as e:
        pass

    Packet_data.db_connection.close()
    Packet_data.loc_db_connection.close()
    server_socket.close()


# Блок кода для тестов.
if __name__ == "__main__":
    # Раскомментить строку.
    server_work()
