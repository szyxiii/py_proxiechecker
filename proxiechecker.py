import requests
import multiprocessing
from enum import Enum
from collections import namedtuple


"""Кастомный тип данных Proxy для списка типов прокси"""
Proxy = namedtuple('Proxy', ['name', 'filename', 'protocols'])


class ProxyTypes(Enum):
    """Типы прокси"""

    #: HTTP
    #: Протоколы: http, https
    HTTP = Proxy('HTTP(S)', 'http(s).txt', ['http', 'https'])

    #: SOCKS4
    #: Протоколы: socks4
    SOCKS4 = Proxy('SOCKS4', 'socks4.txt', ['socks4'])

    #: SOCKS5
    #: Протоколы: socks4
    SOCKS5 = Proxy('SOCKS5', 'socks5.txt', ['socks4'])

    #: INVALID
    #: Невалид
    INVALID = Proxy('INVALID', 'invalid.txt', [])


class Checker:
    """
    Класс для проверки валидности proxy

    :param filename: путь к файлу для загрузки proxy
    :type filename: str

    :param timeout: таймаут проверки каждого proxy
    :type timeout: int

    :param processes: кол-во процессов для параллельной проверки прокси
    :type processes: int

    :param url: URL адрес для проверки proxy на нём
    :type url: str
    """
    HEADERS = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:69.0) Gecko/20100101 Firefox/69.0'
    }

    def __init__(self, filename, timeout=1, processes=50, url='https://google.com'):
        self.filename = filename
        self.timeout = timeout
        self.processes = processes
        self.url = url
        self.proxies = self._read_proxies()

    def _read_proxies(self):
        """Прочесть прокси из файла"""
        with open(self.filename) as file:
            return [line.strip() for line in file.readlines()]

    def _check_proxy(self, proxy, proxy_type=ProxyTypes.HTTP):
        """Проверить прокси на валидность соответствующим протоколом

        :param proxy: строка прокси ip:port
        :type proxy: str

        :param proxy_type: тип прокси для проверки на соответствие
        :type proxy_type: ProxyTypes

        :return: результат соответствия прокси заданному типу
        :rtype: bool
        """
        if proxy_type is ProxyTypes.INVALID:
            return False

        try:
            proxies = [f'{protocol}://{proxy}' for protocol in proxy_type.value.protocols]
            proxies = dict(zip(['http', 'https'], proxies if len(proxies) != 1 else proxies * 2))
            requests.get(self.url, headers=self.HEADERS, proxies=proxies, timeout=self.timeout)
            return True
        except Exception:
            return False

    def get_proxy_type(self, proxy):
        """Узнать тип proxy

        :param proxy: строка прокси ip:port
        :type proxy: str

        :return: тип прокси (ProxyTypes.INVALID, если некорректный)
        :rtype: ProxyTypes
        """
        for proxy_type in list(ProxyTypes):
            if self._check_proxy(proxy, proxy_type):
                print(f'Валидный прокси: {proxy} ({proxy_type.value.name})')
                return (proxy, proxy_type)

        print(f'Невалидный прокси: {proxy}')
        return (proxy, ProxyTypes.INVALID)

    def save_proxies(self, filename, proxies):
        """Сохранить прокси в файл

        :param filename: имя файла для сохранения
        :type filename: str

        :param proxies: список прокси для записи
        :type proxies: list, tuple
        """
        with open(filename, 'w') as file:
            file.write('\n'.join(proxies))

    def check(self):
        """Проверить все загруженные из файла прокси на валидность и записать содержимое в отдельные файлы"""
        proxies_dict = {ptype: [] for ptype in list(ProxyTypes)}

        print('[Параметры]')
        print(f'Файл: {self.filename}')
        print(f'Кол-во proxy: {len(self.proxies)}')
        print(f'Процессы: {self.processes}')
        print(f'Таймаут: {self.timeout}')
        print(f'URL: {self.url}')

        print('\n[Прогресс]')
        with multiprocessing.Pool(processes=self.processes) as process:
            proxies = process.map(self.get_proxy_type, self.proxies)

        for proxy, proxy_type in proxies:
            proxies_dict[proxy_type].append(proxy)

        print('\n[Результат]')
        for proxy_type, proxies in proxies_dict.items():
            try:
                self.save_proxies(proxy_type.value.filename, proxies)
                print(f'Прокси типа {proxy_type.value.name} ({len(proxies)} шт.) сохранены в файл {proxy_type.value.filename}')
            except Exception as ex:
                print(f'Ошибка при сохранении файла с прокси\n{ex}')


def main():
    checker = Checker('CHECKING.txt', processes=55)
    checker.check()


if __name__ == '__main__':
    main()
