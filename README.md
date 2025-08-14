# NetNinjaScan
Сканер сети и уязвимостей

Возможности:
Быстрый аудит сети: вариант 1 (сканирование активных хостов) → вариант 6 (поиск веб-серверов)
Подробный анализ хоста: вариант 4 (стандартное сканирование портов) → вариант 8 (сканирование уязвимостей)
Полная оценка безопасности: варианты 1 → 2 → 5 → 8 → 10 (сформировать отчёт)

Установка:
# Clone the repository
git clone https://github.com/egorTriceps/NetNinjaScan.git
cd NetNinjaScan

# Run the installer script (automatically installs dependencies)
chmod +x install.sh
sudo ./install.sh

# Start NetScan Pro
sudo ./netscan.sh
