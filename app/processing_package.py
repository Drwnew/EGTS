import copy

from work_byte_bit import param_byte, param_bit, hex_to_dec
from crc import crc8, crc16
from create_package import create_response_package

from lists.sfrd_types import Sfrd_types
from lists.processing_result_codes import Codes
from lists.types_services import Types_services

from processing_subrecords.processing_srd_AUTH import pr_EGTS_AUTH_SERVICE
from processing_subrecords.processing_srd_TELEDATA import pr_EGTS_TELEDATA_SERVICE

from logger_files.type_text import Types_text
import time


def get_package_data(packet):
    """
    Функция получения данных пакета
    """
    dict_data = {}

    while len(packet) > 0:
        try:
            packet, dict_data["PRV"] = param_byte(packet, 1, False)  # Protocol Version)
            packet, dict_data["SKID"] = param_byte(packet, 1, False)  # (Security Key ID)
            packet, dict_data["tmp_byte"] = param_byte(packet, 1, False)

            (
                dict_data["PRF"],  # PRF (Prefix)
                dict_data["RTE"],  # RTE (Route).
                # Битовое поле определяет необходимость дальнейшей маршрутизации данного пакета на удаленную телематическую платформу,
                # а также наличие опциональных параметров PRA, RCA, TTL, необходимых для маршрутизации данного пакета. Если поле имеет значение 1,
                # то необходима маршрутизация, и поля PRA, RCA, TTL присутствуют в пакете. Данное поле устанавливает диспетчер той телематической платформы,
                # на которой сгенерирован пакет, или АС, сгенерировавшая пакет для отправки на телематическую платформу, в случае установки в ней параметра
                # «HOME_DISPATCHER_ID», определяющего ее адрес, по которому данная АС зарегистрирована
                dict_data["ENA"],  # ENA (Encryption Algorithm) Битовое поле определяет код алгоритма, используемый для шифрования данных из поля SFRD. Если поле имеет значение 00, то данные в поле SFRD не шифруются.
                dict_data["CMP"],  # Битовое поле определяет, используется ли сжатие данных из поля SFRD. Если поле имеет значение 1, то данные в поле SFRD считаются сжатыми.
                dict_data["PR"],  # Битовое поле определяет приоритет маршрутизации данного пакета и может принимать следующие значения: 00 — наивысший; 01 — высокий; 10 — средний; 11 — низкий.
            ) = param_bit(dict_data["tmp_byte"], (2, 1, 2, 1, 2))

            packet, dict_data["HL"] = param_byte(packet, 1, False)  # Длина заголовка протокола транспортного уровня в байтах с учетом байта контрольной суммы (поля HCS)
            packet, dict_data["HE"] = param_byte(packet, 1, False)  # Определяет применяемый метод кодирования следующей за данным параметром части заголовка протокола транспортного уровня
            packet, dict_data["FDL"] = param_byte(packet, 2, True)  # Определяет размер в байтах поля данных SFRD, содержащего информацию протокола уровня поддержки услуг
            packet, dict_data["PID"] = param_byte(packet, 2, True)  # Содержит номер пакета протокола транспортного уровня,
            print(f"Packet id = {hex_to_dec(dict_data['PID'])}")
            packet, dict_data["PT"] = param_byte(packet, 1, False)  # Тип пакета протокола транспортного уровня. Поле РТ может принимать следующие значения: 0 — EGTS_PT_RESPONSE (подтверждение на протокол транспортного уровня); 1 — EGTS_PT_APPDATA (пакет, содержащий данные протокола уровня поддержки услуг); 2 — EGTS_PT_SIGNED_APPDATA (пакет, содержащий данные протокола уровня поддержки услуг с цифровой подписью)
            if int(dict_data["RTE"]) == 1:
                # необходима маршрутизация
                packet, dict_data["PRA"] = param_byte(packet, 2, True)
                packet, dict_data["RCA"] = param_byte(packet, 2, True)
                packet, dict_data["TTL"] = param_byte(packet, 1, False)
            packet, dict_data["HCS"] = param_byte(packet, 1, False)  # Контрольная сумма заголовка протокола транспортного уровня
            packet, dict_data["SFRD"] = param_byte(packet, hex_to_dec(dict_data["FDL"]), False)  # Структура данных, зависящая от типа пакета и содержащая информацию протокола уровня поддержки услуг
            packet, dict_data["SFRCS"] = param_byte(packet, 2, True)  # Контрольная сумма. Для подсчета контрольной суммы по данным из поля SFRD

            return dict_data

        except Exception as e:
            print(e)
            return None


def processing_EGTS_PT_RESPONSE(byte_string, data_for_db):
    """
    Функция обработки поля SFRD для подтверждения пакета Транспортного Уровня.
    """
    dict_data_sfrd = {}
    i = 0
    while len(byte_string) > 0:
        try:
            byte_string, dict_data_sfrd["RPID"] = param_byte(byte_string, 2, True)
            byte_string, dict_data_sfrd["PR"] = param_byte(byte_string, 1, False)
            dict_data_sfrd.update(processing_EGTS_PT_APPDATA(byte_string, data_for_db, dict_data_sfrd))
            return dict_data_sfrd
        except Exception as e:
            print(e)


def processing_EGTS_PT_APPDATA(byte_string, data_for_db, dict_data_sfrd=None):
    """
    Функция обработки поля SFRD для пакета содержащего данные ППУ.
    """
    if not dict_data_sfrd:
        dict_data_sfrd = {}
    dict_data_sfrd = {}
    dict_data = {}
    i = 0
    while len(byte_string) > 0:
        try:
            byte_string, dict_data["RL"] = param_byte(byte_string, 2, True)
            byte_string, dict_data["RN"] = param_byte(byte_string, 2, True)
            byte_string, dict_data["RFL"] = param_byte(byte_string, 1, False)
            (
                dict_data["SSOD"],
                dict_data["RSOD"],
                dict_data["GRP"],
                dict_data["RPP"],
                dict_data["TMFE"],
                dict_data["EVFE"],
                dict_data["OBFE"],
            ) = param_bit(dict_data["RFL"], (1, 1, 1, 2, 1, 1, 1))
            if int(dict_data["OBFE"]) == 1:
                byte_string, dict_data["OID"] = param_byte(byte_string, 4, True)
                data_for_db.set_oid(hex_to_dec(dict_data["OID"]))
            if int(dict_data["EVFE"]) == 1:
                byte_string, dict_data["EVID"] = param_byte(byte_string, 4, True)
                data_for_db.set_evid(hex_to_dec(dict_data["EVID"]))
                #По непонятным причинам TMFE всегда равен 0
            if int(dict_data["TMFE"]) == 1:
                byte_string, dict_data["TM"] = param_byte(byte_string, 4, True)
                # data_for_db.set_tm(hex_to_dec(dict_data["TM"]))
            byte_string, dict_data["SST"] = param_byte(byte_string, 1, False)
            byte_string, dict_data["RST"] = param_byte(byte_string, 1, False)
            byte_string, dict_data["RD"] = param_byte(byte_string, hex_to_dec(dict_data["RL"]), False)
            dict_srd = {}
            j = 0
            # Разложение данных записи на подзаписи.
            while len(dict_data["RD"]) > 0:
                dict_data["RD"], srt = param_byte(dict_data["RD"], 1, False)
                dict_data["RD"], srl = param_byte(dict_data["RD"], 2, True)
                dict_data["RD"], srd = param_byte(dict_data["RD"], hex_to_dec(srl), False)
                j += 1
                dict_srd["SRD={j}".format(j=j)] = {"SRT": srt, "SRL": srl, "SRD": srd}
            dict_data["RD"] = dict_srd
            i += 1
            dict_data_sfrd["RID={i}".format(i=i)] = dict_data
        except Exception as e:
            print(e)
            return None
    return dict_data_sfrd


def processing_EGTS_PT_SIGNED_APPDATA(byte_string, data_for_db):
    """
    Функция обработки поля SFRD для пакета содержащего данные ППУ с цифровой подписью.
    """
    dict_data_sfrd = {}
    byte_string, dict_data_sfrd["SIGL"] = param_byte(byte_string, 2, True)
    if hex_to_dec(dict_data_sfrd["SIGL"]) > 0:
        byte_string, dict_data_sfrd["SIGD"] = param_byte(byte_string, hex_to_dec(dict_data_sfrd["SIGL"]), False)
    else:
        dict_data_sfrd["SIGD"] = None
    dict_data_sfrd.update(processing_EGTS_PT_APPDATA(byte_string, data_for_db, dict_data_sfrd))
    return dict_data_sfrd


def processing_subrecord(rids, data_for_db):
    """
    Процедура обработки подзаписей
    """
    all_srds_srd = dict()
    for rid in rids:
        dict_rid = copy.deepcopy(rids[rid])
        srds = dict_rid["RD"]
        dec_rst = hex_to_dec(dict_rid["RST"])

        if dec_rst == Types_services.EGTS_AUTH_SERVICE.value:
            all_srds_srd = pr_EGTS_AUTH_SERVICE(srds, data_for_db)
            # print("pr_EGTS_AUTH_SERVICE")

        elif dec_rst == Types_services.EGTS_TELEDATA_SERVICE.value:
            all_srds_srd = pr_EGTS_TELEDATA_SERVICE(srds, data_for_db)
            # print("pr_EGTS_TELEDATA_SERVICE")
            # Сохранение данных в локальную бд.
            data_for_db.gts_data_save()
            # Очищаем список значений llsd.
            data_for_db.reset_llsd()
        elif dec_rst == Types_services.EGTS_COMMANDS_SERVICE.value:
            print("EGTS_COMMANDS_SERVICE")
        elif dec_rst == Types_services.EGTS_FIRMWARE_SERVICE.value:
            print("EGTS_FIRMWARE_SERVICE")
        elif dec_rst == Types_services.EGTS_ECALL_SERVICE.value:
            print("EGTS_ECALL_SERVICE")
        else:
            print("Неизвестный тип сервиса-получателя.")
    for rid in rids:
        for srd in all_srds_srd:
            rids[rid]["RD"][srd]["SRD"] = all_srds_srd[srd]["SRD"]
    return rids


def package_data_processing(packet, data_for_db, logging):
    """
    Функция обработки данных пакета
    """
    dict_data = get_package_data(packet)
    send_dict_data = dict_data.copy()
    # Поддерживаются ли версии PRV, PRF.
    if dict_data["PRV"] == b"\x01" and dict_data["PRF"] == "00":
        # Проверка длины заголовка.
        if hex_to_dec(dict_data["HL"]) in range(11, 17):
            data_checksum_crc8 = list(packet[: hex_to_dec(dict_data["HL"]) - 1])
            checksum_crc8 = crc8(data_checksum_crc8)
            # Проверка контрольной суммы заголовка.
            if checksum_crc8 == dict_data["HCS"]:
                # Необходимость дальнейшей маршрутизации.
                if dict_data["RTE"] == "0":
                    if hex_to_dec(dict_data["FDL"]) > 0:  # Есть ли информация уровня поддержки услуг.
                        data_checksum_crc16 = list(dict_data["SFRD"])
                        checksum_crc16 = crc16(data_checksum_crc16)
                        # Проверка контрольной суммы информация уровня поддержки услуг.
                        if checksum_crc16 == dict_data["SFRCS"]:
                            # Проверка кода алгоритма шифрования.
                            if dict_data["ENA"] == "00":
                                # Обрабатываем информацию уровня поддержки в зависимости от значения PT.
                                dec_pt = hex_to_dec(dict_data["PT"])
                                if dec_pt == Sfrd_types.EGTS_PT_RESPONSE.value:
                                    # print("EGTS_PT_RESPONSE")
                                    # эта часть кода не тестилась
                                    dict_data["SFRD"] = processing_EGTS_PT_RESPONSE(dict_data["SFRD"], data_for_db)
                                    dict_data["SFRD"] = processing_subrecord(dict_data["SFRD"], data_for_db)
                                    # неизвестно надо или нет, но кода я участвую в цепи пересылок пакета, то будто бы надо
                                    # я получу ответ от пересылки, и ответ направлю, кто мне скинул пакет
                                elif dec_pt == Sfrd_types.EGTS_PT_APPDATA.value:
                                    dict_data["SFRD"] = processing_EGTS_PT_APPDATA(dict_data["SFRD"], data_for_db)
                                    dict_data["SFRD"] = processing_subrecord(dict_data["SFRD"], data_for_db)
                                elif dec_pt == Sfrd_types.EGTS_PT_SIGNED_APPDATA.value:
                                    dict_data["SFRD"] = processing_EGTS_PT_SIGNED_APPDATA(dict_data["SFRD"], data_for_db)
                                    dict_data["SFRD"] = processing_subrecord(dict_data["SFRD"], data_for_db)
                                else:
                                    print("Неизвестный тип пакета.")

                                logging.logging(fromm=1, to=2, type_text=Types_text.PROCESSED_SUCCESSFULLY.value, text=dict_data)
                                return create_response_package(
                                    send_dict_data,
                                    Sfrd_types.EGTS_PT_RESPONSE.value,
                                    Codes.EGTS_PC_OK.value,
                                )
                            else:
                                return create_response_package(send_dict_data, Sfrd_types.EGTS_PT_RESPONSE.value, Codes.EGTS_PC_DECRYPT_ERROR.value)
                        else:
                            return create_response_package(send_dict_data, Sfrd_types.EGTS_PT_RESPONSE.value, Codes.EGTS_PC_DATACRC_ERROR.value)
                    else:
                        return create_response_package(send_dict_data, Sfrd_types.EGTS_PT_RESPONSE.value, Codes.EGTS_PC_OK.value)
                else:
                    # Пока не знаю, будет ли нужен этот блок кода.
                    print("Попали в блок пересылки пакета")
                    if hex_to_dec(dict_data["TTL"]) > 0:
                        dict_data["TTL"] = (hex_to_dec(dict_data["TTL"]) - 1).to_bytes(1, byteorder="big")
                        data_checksum_crc8 = list(packet[: hex_to_dec(dict_data["HL"]) - 2])
                        data_checksum_crc8.append(dict_data["TTL"])
                        dict_data["HCS"] = crc8(data_checksum_crc8)

                        # Создаем пакет для отправки на другую ТП.
                        create_response_package(send_dict_data, hex_to_dec(dict_data["PT"]), "хз что тут надо")
                    else:
                        return create_response_package(send_dict_data, Sfrd_types.EGTS_PT_RESPONSE.value, Codes.EGTS_PC_TTLEXPIRED.value)
            else:
                return create_response_package(send_dict_data, Sfrd_types.EGTS_PT_RESPONSE.value, Codes.EGTS_PC_HEADERCRC_ERROR.value)
        else:
            return create_response_package(send_dict_data, Sfrd_types.EGTS_PT_RESPONSE.value, Codes.EGTS_PC_INC_HEADERFORM.value)
    else:
        return create_response_package(send_dict_data, Sfrd_types.EGTS_PT_RESPONSE.value, Codes.EGTS_PC_UNS_PROTOCOL.value)
