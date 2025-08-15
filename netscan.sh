#!/bin/bash

# Check if required commands are installed: nmap
REQUIRED_COMMANDS=("nmap")
OPTIONAL_COMMANDS=("figlet" "lolcat" "toilet" "nmcli" "iwlist" "iwconfig")

for cmd in "${REQUIRED_COMMANDS[@]}"; do
    if ! command -v "$cmd" &> /dev/null; then
        echo "Error: $cmd is not installed. Please install $cmd to run this script."
        exit 1
    fi
done

# Define colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Create results directory if it doesn't exist
RESULTS_DIR="results"
mkdir -p "$RESULTS_DIR"

WEB_RESULT="Web Pages"
mkdir -p "$WEB_RESULT"

LOG_FILE="$RESULTS_DIR/network_scan_$(date +'%Y%m%d_%H%M%S').log"

# Function to log output with timestamps
log() {
    echo -e "$(date +'%Y-%m-%d %H:%M:%S') $1" | tee -a "$LOG_FILE"
}

display_banner() {
    if command -v figlet &> /dev/null; then
        terminal_width=$(tput cols)
        banner=$(figlet "NetNinjaScan")
        while IFS= read -r line; do
            padding=$(( (terminal_width - ${#line}) / 2 ))
            printf "%*s%s\n" "$padding" "" "$line"
        done <<< "$banner" | { command -v lolcat &> /dev/null && lolcat || cat; }
    else
        echo -e "${CYAN}=========================================${NC}"
        echo -e "${GREEN}           NetNinjaScan v1.0            ${NC}"
        echo -e "${CYAN}=========================================${NC}"
    fi
}

get_host_ip() {
    hostname -I | awk '{print $1}'
}

get_default_gateway() {
    ip route | awk '/^default/ {print $3}'
}

calculate_network() {
    local host_ip=$1
    ip -o -f inet addr show | awk -v ip="$host_ip" '$0 ~ ip {print $4}'
}

scan_network() {
    local network=$1
    log "${BLUE}[*] Сканирование сети $network для живых хостов...${NC}"
    nmap -sn "$network" | tee -a "$LOG_FILE"
}

port_scan() {
    local target=$1
    local scan_type=$2

    case $scan_type in
        "quick")
            log "${BLUE}[*] Выполнение быстрого сканирования портов на $target...${NC}"
            nmap -T4 --top-ports 100 "$target" | tee -a "$LOG_FILE"
            ;;
        "full")
            log "${BLUE}[*] Выполнение полной проверки портов на $target...${NC}"
            sudo nmap -sS -sV -O -p- "$target" | tee -a "$LOG_FILE"
            ;;
        *)
            log "${BLUE}[*] Выполнение стандартного сканирования портов на $target...${NC}"
            sudo nmap -sS -sV -O "$target" | tee -a "$LOG_FILE"
            ;;
    esac
}

vulnerability_scan() {
    local target=$1
    log "${BLUE}[*] Сканирование $target на предмет уязвимостей...${NC}"
    sudo nmap -sV --script=vuln "$target" | tee -a "$LOG_FILE"
}

find_web_servers() {
    local network=$1
    log "${BLUE}[*] Поиск веб-серверов в сети...${NC}"
    nmap --open -p 80,443,8080,8443 "$network" | tee -a "$LOG_FILE"
}

find_databases() {
    local network=$1
    log "${BLUE}[*] Поиск серверов баз данных в сети...${NC}"
    nmap --open -p 1433,3306,5432,27017,6379,9200 "$network" | tee -a "$LOG_FILE"
}

find_wireless_connections() {
    log "${BLUE}[*] Поиск доступных беспроводных подключений...${NC}"
    if command -v nmcli &> /dev/null; then
        log "Использование nmcli для беспроводного сканирования."
        sudo nmcli dev wifi list | tee -a "$LOG_FILE"
    elif command -v iwlist &> /dev/null; then
        interface=$(iwconfig 2>/dev/null | grep 'ESSID' | awk '{print $1}')
        if [ -n "$interface" ]; then
            log "Использование iwlist в интерфейсе $interface"
            sudo iwlist "$interface" scan | grep -E 'ESSID|Signal|Quality|Channel' | tee -a "$LOG_FILE"
        else
            log "${RED}[!] Беспроводной интерфейс не найден. Убедитесь, что включен Wi-Fi.${NC}"
        fi
    else
        log "${RED}[!] Не найдено подходящего инструмента для поиска беспроводных сетей.${NC}"
    fi
}

network_device_discovery() {
    local network=$1
    log "${BLUE}[*] Выполнение обнаружения сетевого устройства на $network...${NC}"
    sudo nmap -sn -PR -PE -PA21,22,23,80,443,3389 "$network" | tee -a "$LOG_FILE"
}

generate_report() {
    local report_file="$WEB_RESULT/network_report_$(date +'%Y%m%d_%H%M%S').html"
    log "${BLUE}[*] Создание HTML-отчета на основе данных сканирования...${NC}"

    # Parse the log file to extract different sections
    local live_hosts=$(grep -A 20 "Сканирование сети.* на наличие активных узлов" "$LOG_FILE" | grep -E "Nmap scan report|Host is up" | sed 's/Nmap scan report for //')
    local port_scans=$(grep -A 50 "Выполнение .* сканирование портов на" "$LOG_FILE" | grep -E "PORT|open|filtered|closed" | grep -v "Not shown")
    local web_servers=$(grep -A 30 "Поиск веб-серверов" "$LOG_FILE" | grep -E "Nmap scan report|80/tcp|443/tcp|8080/tcp|8443/tcp")
    local db_servers=$(grep -A 30 "Поиск серверов баз данных" "$LOG_FILE" | grep -E "Nmap scan report|1433/tcp|3306/tcp|5432/tcp|27017/tcp|6379/tcp|9200/tcp")
    local vulnerabilities=$(grep -A 100 "Сканирование .* на наличие уязвимостей" "$LOG_FILE" | grep -E "VULNERABLE|CVE-|exploit")
    local wireless=$(grep -A 30 "Поиск доступных беспроводных подключений" "$LOG_FILE" | grep -E "ESSID|Signal|Quality|Channel|SSID")

    echo "<!DOCTYPE html>
<html lang=\"en\">
<head>
    <meta charset=\"UTF-8\">
    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">
    <title>Отчет о проверке сети</title>
    <style>
        :root {
            --primary-color: #2563eb;
            --secondary-color: #3b82f6;
            --accent-color: #60a5fa;
            --success-color: #10b981;
            --danger-color: #ef4444;
            --warning-color: #f59e0b;
            --info-color: #3b82f6;
            --dark-color: #1e3a8a;
            --light-color: #f3f4f6;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            margin: 0;
            padding: 0;
            background-color: #f9fafb;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }

        .header {
            background: linear-gradient(135deg, var(--primary-color), var(--dark-color));
            color: white;
            padding: 20px;
            border-radius: 10px 10px 0 0;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }

        .header h1 {
            margin: 0;
            font-size: 28px;
        }

        .header p {
            margin: 5px 0 0;
            opacity: 0.8;
        }

        .summary-box {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }

        .summary-item {
            background-color: white;
            border-radius: 8px;
            padding: 15px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.05);
        }

        .summary-item h3 {
            margin-top: 0;
            font-size: 16px;
            color: #6b7280;
            border-bottom: 1px solid #e5e7eb;
            padding-bottom: 8px;
        }

        .summary-item p {
            margin: 0;
            font-size: 18px;
            font-weight: 600;
        }

        .card {
            background-color: white;
            border-radius: 8px;
            overflow: hidden;
            margin-bottom: 20px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.05);
        }

        .card-header {
            padding: 15px 20px;
            background-color: var(--light-color);
            border-bottom: 1px solid #e5e7eb;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .card-header h2 {
            margin: 0;
            font-size: 18px;
            color: var(--dark-color);
        }

        .card-body {
            padding: 20px;
        }

        pre.code-block {
            background-color: #f8fafc;
            padding: 15px;
            border-radius: 6px;
            border: 1px solid #e5e7eb;
            overflow-x: auto;
            font-family: 'Courier New', Courier, monospace;
            font-size: 14px;
            white-space: pre-wrap;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 15px;
        }

        table th {
            background-color: var(--light-color);
            text-align: left;
            padding: 10px;
            font-weight: 600;
            border-bottom: 2px solid #e5e7eb;
        }

        table td {
            padding: 10px;
            border-bottom: 1px solid #e5e7eb;
        }

        table tr:nth-child(even) {
            background-color: #f8fafc;
        }

        .badge {
            display: inline-block;
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: 600;
            color: white;
        }

        .badge-success {
            background-color: var(--success-color);
        }

        .badge-danger {
            background-color: var(--danger-color);
        }

        .badge-warning {
            background-color: var(--warning-color);
        }

        .badge-info {
            background-color: var(--info-color);
        }

        .footer {
            text-align: center;
            margin-top: 30px;
            padding: 20px;
            color: #6b7280;
            font-size: 14px;
        }

        .expandable {
            cursor: pointer;
        }

        .expandable-content {
            display: none;
        }

        .expandable.active .expandable-content {
            display: block;
        }

        /* Responsive adjustments */
        @media (max-width: 768px) {
            .summary-box {
                grid-template-columns: 1fr;
            }
        }
    </style>
    <script>
        document.addEventListener('DOMContentLoaded', function() {
            // Toggle expandable sections
            document.querySelectorAll('.expandable-header').forEach(header => {
                header.addEventListener('click', function() {
                    this.parentElement.classList.toggle('active');
                });
            });

            // Filter table data
            document.querySelectorAll('.filter-input').forEach(input => {
                input.addEventListener('keyup', function() {
                    const value = this.value.toLowerCase();
                    const table = this.closest('.card').querySelector('table');

                    table.querySelectorAll('tbody tr').forEach(row => {
                        const text = row.textContent.toLowerCase();
                        row.style.display = text.includes(value) ? '' : 'none';
                    });
                });
            });
        });
    </script>
</head>
<body>
    <div class=\"container\">
        <div class=\"header\">
            <h1>Отчет о проверке сети</h1>
            <p>Generated on $(date +'%Y-%m-%d %H:%M:%S')</p>
        </div>

        <div class=\"summary-box\">
            <div class=\"summary-item\">
                <h3>Host IP</h3>
                <p>$host_ip</p>
            </div>
            <div class=\"summary-item\">
                <h3>Network</h3>
                <p>$network</p>
            </div>
            <div class=\"summary-item\">
                <h3>Default Gateway</h3>
                <p>$gateway</p>
            </div>
        </div>

        <!-- Раздел активных узлов -->
        <div class=\"card\">
            <div class=\"card-header\">
                <h2>Live Hosts</h2>
                <input type=\"text\" class=\"filter-input\" placeholder=\"Фильтровать хосты...\">
            </div>
            <div class=\"card-body\">
                <pre class=\"code-block\">$live_hosts</pre>
            </div>
        </div>

        <!-- Раздел сканирования портов -->
        <div class=\"card\">
            <div class=\"card-header\">
                <h2>Port Scan Results</h2>
                <input type=\"text\" class=\"filter-input\" placeholder=\"Фильтровать порты...\">
            </div>
            <div class=\"card-body\">
                <pre class=\"code-block\">$port_scans</pre>
            </div>
        </div>

        <!-- Раздел веб-серверов -->
        <div class=\"card\">
            <div class=\"card-header\">
                <h2>Web Servers</h2>
                <input type=\"text\" class=\"filter-input\" placeholder=\"Фильтровать веб сервисы...\">
            </div>
            <div class=\"card-body\">
                <pre class=\"code-block\">$web_servers</pre>
            </div>
        </div>

        <!-- Раздел Серверы баз данных -->
        <div class=\"card\">
            <div class=\"card-header\">
                <h2>Database Servers</h2>
                <input type=\"text\" class=\"filter-input\" placeholder=\"Фильтровать сервисы БД...\">
            </div>
            <div class=\"card-body\">
                <pre class=\"code-block\">$db_servers</pre>
            </div>
        </div>

        <!-- Раздел уязвимостей -->
        <div class=\"card\">
            <div class=\"card-header\">
                <h2>Vulnerabilities</h2>
                <input type=\"text\" class=\"filter-input\" placeholder=\"Фильтровать уязвимости...\">
            </div>
            <div class=\"card-body\">
                <pre class=\"code-block\">$vulnerabilities</pre>
            </div>
        </div>

        <!-- Раздел беспроводных подключений -->
        <div class=\"card\">
            <div class=\"card-header\">
                <h2>Wireless Connections</h2>
                <input type=\"text\" class=\"filter-input\" placeholder=\"Фильтровать беспроводные сети...\">
            </div>
            <div class=\"card-body\">
                <pre class=\"code-block\">$wireless</pre>
            </div>
        </div>

        <!-- Полный раздел журнала (Log) -->
        <div class=\"card expandable\">
            <div class=\"card-header expandable-header\">
                <h2>Full Scan Log</h2>
                <span>Click to expand/collapse</span>
            </div>
            <div class=\"card-body expandable-content\">
                <pre class=\"code-block\">$(cat "$LOG_FILE")</pre>
            </div>
        </div>

        <div class=\"footer\">
            <p>Generated by NetNinjaScan v1.0</p>
        </div>
    </div>
</body>
</html>" > "$report_file"

    log "${GREEN}[+] Созданный улучшенный визуальный отчет: $report_file${NC}"

    # Try to open the report in the default browser if supported
    if command -v xdg-open &> /dev/null; then
        xdg-open "$report_file" &> /dev/null &
    elif command -v open &> /dev/null; then
        open "$report_file" &> /dev/null &
    else
        log "${YELLOW}[!] Отчет создан, но не удалось открыть автоматически. Пожалуйста, откройте вручную: $report_file${NC}"
    fi
}

clear_screen() {
    clear
    display_banner

    host_ip=$(get_host_ip)
    gateway=$(get_default_gateway)
    network=$(calculate_network "$host_ip")

    log "${GREEN}IP-адрес хоста: ${NC}$host_ip"
    log "${GREEN}Шлюз по умолчанию: ${NC}$gateway"
    log "${GREEN}Сеть: ${NC}$network"
    log "${GREEN}Результаты сканирования будут сохранены в: ${NC}$RESULTS_DIR"
}


show_menu() {
    echo -e "\n${YELLOW}Выберите нужный вариант:${NC}"
    echo -e "${CYAN}=== Обнаружение сети ===${NC}"
    echo -e "1. Поиск активных узлов в сети"
    echo -e "2. Выполните детальное обнаружение сетевого устройства"

    echo -e "\n${CYAN}=== Сканирование портов ===${NC}"
    echo -e "3. Выполните быструю проверку портов на определенном хосте"
    echo -e "4. Выполните стандартную проверку портов на определенном хосте"
    echo -e "5. Выполните полное сканирование портов на определенном хосте"

    echo -e "\n${CYAN}=== Обнаружение служб ===${NC}"
    echo -e "6. Поиск веб-серверов в сети"
    echo -e "7. Поиск серверов баз данных в сети"
    echo -e "8. Поиск уязвимостей на определенном хосте"

    echo -e "\n${CYAN}=== Беспроводной ===${NC}"
    echo -e "9. Поиск доступных беспроводных подключений"

    echo -e "\n${CYAN}=== Дополнения ===${NC}"
    echo -e "10. Создание HTML-отчета на основе данных сканирования"
    echo -e "11. Очистите экран"
    echo -e "12. Выход"

    echo -en "${GREEN}Введите свой выбор [1-12]: ${NC}"
}

# Main script execution
clear_screen


while true; do
    show_menu
    read -r choice
    case $choice in
        1)
            scan_network "$network"
            ;;
        2)
            network_device_discovery "$network"
            ;;
        3)
            echo -en "${GREEN}Введите IP-адрес целевого хоста для быстрого сканирования портов: ${NC}"
            read -r target
            port_scan "$target" "quick"
            ;;
        4)
            echo -en "${GREEN}Введите IP-адрес целевого хоста для стандартной проверки портов: ${NC}"
            read -r target
            port_scan "$target" "standard"
            ;;
        5)
            echo -en "${GREEN}Введите IP-адрес целевого хоста для полной проверки портов: ${NC}"
            read -r target
            port_scan "$target" "full"
            ;;
        6)
            find_web_servers "$network"
            ;;
        7)
            find_databases "$network"
            ;;
        8)
            echo -en "${GREEN}Введите IP-адрес целевого хоста для проверки на уязвимости: ${NC}"
            read -r target
            vulnerability_scan "$target"
            ;;
        9)
            find_wireless_connections
            ;;
        10)
            generate_report
            ;;
        11)
            clear_screen
            ;;
        12)
            log "${YELLOW}Увидимся. Хорошего дня!${NC}"
            exit 0
            ;;
        *)
            echo -e "${RED}Неверный вариант. Пожалуйста, выберите от 1 до 12.${NC}"
            ;;
    esac
done
