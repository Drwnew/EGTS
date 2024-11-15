from enum import Enum


# Типы пакетов транспортного уровня.
class Sfrd_types(Enum):
    EGTS_PT_RESPONSE = 0  # подтверждение на пакет транспортного уровня
    EGTS_PT_APPDATA = 1  # пакет, содержащий данные протокола уровня поддержки услуг
    EGTS_PT_SIGNED_APPDATA = 2  # пакет, содержащий данные протокола уровня поддержки услуг с цифровой подписью
