Proxy Checker

Лёгкая утилита на Python для быстрой проверки скорости, живости (uptime) и exit-IP списка SOCKS5/HTTP прокси. Полезна перед закупкой пакета прокси или для регулярного мониторинга уже купленных.

Возможности


Параллельная проверка сотен прокси за секунды (многопоточность)
Поддержка socks5://, socks5h://, http://, https://
Отчёт: латency (ms), рабочий/нерабочий, exit IP, причина ошибки
Определение уровня анонимности (elite / anonymous / transparent)
Экспорт результатов в CSV и JSON — удобно для отчётов и статей
Работа как с одним прокси, так и со списком из файла


Установка

bashgit clone https://github.com/<your-username>/proxy-checker.git
cd proxy-checker
pip install -r requirements.txt

Использование

Проверить список прокси из файла:

bashpython proxy_checker.py --proxies proxies.txt

Проверить один прокси:

bashpython proxy_checker.py --proxy socks5://user:pass@1.2.3.4:1080

Настроить число потоков и таймаут:

bashpython proxy_checker.py --proxies proxies.txt --workers 50 --timeout 5

Проверить анонимность и сохранить отчёт в CSV/JSON:

bashpython proxy_checker.py --proxies proxies.txt --check-anonymity --export-csv report.csv --export-json report.json

Формат файла со списком — по одному прокси на строку, см. proxies.example.txt.



Пример вывода

======================================================================
Проверено прокси: 12  |  Живых: 9  |  Мёртвых: 3
======================================================================

✅ РАБОЧИЕ ПРОКСИ (отсортированы по скорости):

  socks5://1.2.3.4:1080                         182.3 ms   exit_ip=1.2.3.4
  socks5://5.6.7.8:1080                         241.7 ms   exit_ip=5.6.7.8
  ...

❌ НЕРАБОЧИЕ ПРОКСИ:

  socks5://9.9.9.9:1080                         Timeout при подключении

Средняя задержка: 205.4 ms   |   Uptime в этой проверке: 75.0%
