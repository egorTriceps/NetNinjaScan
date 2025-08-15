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
    log "${BLUE}[*] Scanning network $network for live hosts...${NC}"
    nmap -sn "$network" | tee -a "$LOG_FILE"
}

port_scan() {
    local target=$1
    local scan_type=$2

    case $scan_type in
        "quick")
            log "${BLUE}[*] Performing quick port scan on $target...${NC}"
            nmap -T4 --top-ports 100 "$target" | tee -a "$LOG_FILE"
            ;;
        "full")
            log "${BLUE}[*] Performing full port scan on $target...${NC}"
            sudo nmap -sS -sV -O -p- "$target" | tee -a "$LOG_FILE"
            ;;
        *)
            log "${BLUE}[*] Performing standard port scan on $target...${NC}"
            sudo nmap -sS -sV -O "$target" | tee -a "$LOG_FILE"
            ;;
    esac
}

# Конфигурация API
NVD_API_KEY="cac68a66-ff81-4ca9-89f1-ffef20a42cbc"
VULNERS_API_KEY="85O32CP843SA2W7780SXPI3SCV9NZOO5CVJZ6I8GIMYE2IIAY8EXMAYTHTE7I6UV"
MITRE_API_URL="https://cveawg.mitre.org/api/cve/"

# Функция для получения информации об уязвимости из NVD
get_nvd_vulnerability_info() {
    local cve_id=$1
    local api_url="https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=$cve_id"
    
    if [ -n "$NVD_API_KEY" ]; then
        response=$(curl -s -H "apiKey: $NVD_API_KEY" "$api_url")
    else
        response=$(curl -s "$api_url")
    fi
    
    if [ -z "$response" ]; then
        echo "NVD: Не удалось получить информацию для $cve_id"
        return
    fi
    
    description=$(echo "$response" | jq -r '.vulnerabilities[0].cve.descriptions[0].value')
    published=$(echo "$response" | jq -r '.vulnerabilities[0].cve.published')
    severity=$(echo "$response" | jq -r '.vulnerabilities[0].cve.metrics.cvssMetricV31[0].cvssData.baseSeverity // "N/A"')
    score=$(echo "$response" | jq -r '.vulnerabilities[0].cve.metrics.cvssMetricV31[0].cvssData.baseScore // "N/A"')
    
    echo -e "=== NVD ===\nОписание: $description\nОпубликовано: $published\nУровень опасности: $severity\nCVSS: $score"
}

# Функция для получения информации об уязвимости из Vulners
get_vulners_vulnerability_info() {
    local cve_id=$1
    local api_url="https://vulners.com/api/v3/search/id/"
    
    if [ -z "$VULNERS_API_KEY" ]; then
        echo "Vulners: Требуется API ключ"
        return
    fi
    
    response=$(curl -s -X POST "$api_url" \
        -H "Content-Type: application/json" \
        -H "X-Vulners-Api-Key: $VULNERS_API_KEY" \
        -d "{\"id\": \"$cve_id\"}")
    
    if [ -z "$response" ]; then
        echo "Vulners: Не удалось получить информацию для $cve_id"
        return
    fi
    
    description=$(echo "$response" | jq -r '.data.documents[].description')
    published=$(echo "$response" | jq -r '.data.documents[].published')
    severity=$(echo "$response" | jq -r '.data.documents[].cvss.severity // "N/A"')
    score=$(echo "$response" | jq -r '.data.documents[].cvss.score // "N/A"')
    exploit_count=$(echo "$response" | jq -r '.data.documents[].exploitCount // 0')
    
    echo -e "=== Vulners ===\nОписание: $description\nОпубликовано: $published\nУровень опасности: $severity\nCVSS: $score\nЭксплойты: $exploit_count"
}

# Функция для получения информации об уязвимости из MITRE
get_mitre_vulnerability_info() {
    local cve_id=$1
    local api_url="${MITRE_API_URL}${cve_id}"
    
    response=$(curl -s "$api_url")
    
    if [ -z "$response" ]; then
        echo "MITRE: Не удалось получить информацию для $cve_id"
        return
    fi
    
    description=$(echo "$response" | jq -r '.containers.cna.descriptions[0].value')
    published=$(echo "$response" | jq -r '.cveMetadata.datePublished')
    severity=$(echo "$response" | jq -r '.containers.cna.metrics[].cvssV3_1.baseSeverity // "N/A"')
    score=$(echo "$response" | jq -r '.containers.cna.metrics[].cvssV3_1.baseScore // "N/A"')
    
    echo -e "=== MITRE ===\nОписание: $description\nОпубликовано: $published\nУровень опасности: $severity\nCVSS: $score"
}

# Модифицированная функция сканирования уязвимостей
vulnerability_scan() {
    local target=$1
    log "${BLUE}[*] Scanning $target for vulnerabilities...${NC}"
    
    # Выполняем сканирование
    scan_results=$(sudo nmap -sV --script=vuln "$target")
    echo "$scan_results" | tee -a "$LOG_FILE"
    
    # Извлекаем CVE ID из результатов
    cve_list=$(echo "$scan_results" | grep -Eo 'CVE-[0-9]{4}-[0-9]+' | sort | uniq)
    
    if [ -z "$cve_list" ]; then
        log "${YELLOW}[!] CVE не обнаружены${NC}"
        return
    fi
    
    log "${GREEN}[+] Обнаружены CVE:${NC}"
    echo "$cve_list"
    
    # Получаем информацию об уязвимостях
    for cve in $cve_list; do
        log "${CYAN}[*] Получение информации для $cve${NC}"
        get_nvd_vulnerability_info "$cve"
        get_vulners_vulnerability_info "$cve"
        get_mitre_vulnerability_info "$cve"
        echo "----------------------------------------"
    done | tee -a "$LOG_FILE"
}

web_vulnerability_scan() {
    local target=$1
    log "${BLUE}[*] Scanning $target for web vulnerabilities...${NC}"
    sudo nmap -sV --script=http-vuln*,http-enum,http-sql-injection "$target" | tee -a "$LOG_FILE"
}

os_vulnerability_scan() {
    local target=$1
    log "${BLUE}[*] Scanning $target for OS vulnerabilities...${NC}"
    sudo nmap -sV --script=vulners,exploit "$target" | tee -a "$LOG_FILE"
}

find_web_servers() {
    local network=$1
    log "${BLUE}[*] Scanning for web servers on the network...${NC}"
    nmap --open -p 80,443,8080,8443 "$network" | tee -a "$LOG_FILE"
}

find_databases() {
    local network=$1
    log "${BLUE}[*] Scanning for database servers on the network...${NC}"
    nmap --open -p 1433,3306,5432,27017,6379,9200 "$network" | tee -a "$LOG_FILE"
}

find_wireless_connections() {
    log "${BLUE}[*] Scanning for available wireless connections...${NC}"
    if command -v nmcli &> /dev/null; then
        log "Using nmcli for wireless scan."
        sudo nmcli dev wifi list | tee -a "$LOG_FILE"
    elif command -v iwlist &> /dev/null; then
        interface=$(iwconfig 2>/dev/null | grep 'ESSID' | awk '{print $1}')
        if [ -n "$interface" ]; then
            log "Using iwlist on interface $interface"
            sudo iwlist "$interface" scan | grep -E 'ESSID|Signal|Quality|Channel' | tee -a "$LOG_FILE"
        else
            log "${RED}[!] No wireless interface found. Ensure WiFi is enabled.${NC}"
        fi
    else
        log "${RED}[!] No suitable tool found to scan for wireless networks.${NC}"
    fi
}

network_device_discovery() {
    local network=$1
    log "${BLUE}[*] Performing network device discovery on $network...${NC}"
    sudo nmap -sn -PR -PE -PA21,22,23,80,443,3389 "$network" | tee -a "$LOG_FILE"
}

generate_report() {
    local report_file="$WEB_RESULT/network_report_$(date +'%Y%m%d_%H%M%S').html"
    log "${BLUE}[*] Generating HTML report from scan data...${NC}"

    # Parse the log file to extract different sections
    local live_hosts=$(grep -A 20 "Scanning network .* for live hosts" "$LOG_FILE" | grep -E "Nmap scan report|Host is up" | sed 's/Nmap scan report for //')
    local port_scans=$(grep -A 50 "Performing .* port scan on" "$LOG_FILE" | grep -E "PORT|open|filtered|closed" | grep -v "Not shown")
    local web_servers=$(grep -A 30 "Scanning for web servers" "$LOG_FILE" | grep -E "Nmap scan report|80/tcp|443/tcp|8080/tcp|8443/tcp")
    local db_servers=$(grep -A 30 "Scanning for database servers" "$LOG_FILE" | grep -E "Nmap scan report|1433/tcp|3306/tcp|5432/tcp|27017/tcp|6379/tcp|9200/tcp")
    local vulnerabilities=$(grep -A 100 "Scanning .* for vulnerabilities" "$LOG_FILE" | grep -E "VULNERABLE|CVE-|exploit")
    local wireless=$(grep -A 30 "Scanning for available wireless connections" "$LOG_FILE" | grep -E "ESSID|Signal|Quality|Channel|SSID")

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
                <h3>IP-адрес хоста</h3>
                <p>$host_ip</p>
            </div>
            <div class=\"summary-item\">
                <h3>Сеть</h3>
                <p>$network</p>
            </div>
            <div class=\"summary-item\">
                <h3>Шлюз по умолчанию</h3>
                <p>$gateway</p>
            </div>
        </div>

        <!-- Раздел активных узлов -->
        <div class=\"card\">
            <div class=\"card-header\">
                <h2>Активные узлы</h2>
                <input type=\"text\" class=\"filter-input\" placeholder=\"Фильтровать хосты...\">
            </div>
            <div class=\"card-body\">
                <pre class=\"code-block\">$live_hosts</pre>
            </div>
        </div>

        <!-- Раздел сканирования портов -->
        <div class=\"card\">
            <div class=\"card-header\">
                <h2>Результаты сканирования портов</h2>
                <input type=\"text\" class=\"filter-input\" placeholder=\"Фильтровать порты...\">
            </div>
            <div class=\"card-body\">
                <pre class=\"code-block\">$port_scans</pre>
            </div>
        </div>

        <!-- Раздел веб-серверов -->
        <div class=\"card\">
            <div class=\"card-header\">
                <h2>Веб-серверы</h2>
                <input type=\"text\" class=\"filter-input\" placeholder=\"Фильтровать веб сервисы...\">
            </div>
            <div class=\"card-body\">
                <pre class=\"code-block\">$web_servers</pre>
            </div>
        </div>

        <!-- Раздел Серверы баз данных -->
        <div class=\"card\">
            <div class=\"card-header\">
                <h2>Серверы баз данных</h2>
                <input type=\"text\" class=\"filter-input\" placeholder=\"Фильтровать сервисы БД...\">
            </div>
            <div class=\"card-body\">
                <pre class=\"code-block\">$db_servers</pre>
            </div>
        </div>

        <!-- Раздел уязвимостей -->
        <div class=\"card\">
            <div class=\"card-header\">
                <h2>Уязвимости</h2>
                <input type=\"text\" class=\"filter-input\" placeholder=\"Фильтровать уязвимости...\">
            </div>
            <div class=\"card-body\">
                <pre class=\"code-block\">$vulnerabilities</pre>
            </div>
        </div>

        <!-- Раздел беспроводных подключений -->
        <div class=\"card\">
            <div class=\"card-header\">
                <h2>Беспроводные соединения</h2>
                <input type=\"text\" class=\"filter-input\" placeholder=\"Фильтровать беспроводные сети...\">
            </div>
            <div class=\"card-body\">
                <pre class=\"code-block\">$wireless</pre>
            </div>
        </div>

        <!-- Полный раздел журнала (Log) -->
        <div class=\"card expandable\">
            <div class=\"card-header expandable-header\">
                <h2>Полный журнал сканирования</h2>
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
    echo -e "2. Детальное обнаружение сетевых устройств"

    echo -e "\n${CYAN}=== Сканирование портов ===${NC}"
    echo -e "3. Быстрое сканирование портов"
    echo -e "4. Стандартное сканирование портов"
    echo -e "5. Полное сканирование портов"

    echo -e "\n${CYAN}=== Обнаружение сервисов ===${NC}"
    echo -e "6. Поиск веб-серверов"
    echo -e "7. Поиск серверов баз данных"
    echo -e "8. Сканирование общих уязвимостей"
    echo -e "9. Сканирование веб-уязвимостей"
    echo -e "10. Сканирование уязвимостей ОС"

    echo -e "\n${CYAN}=== Беспроводные сети ===${NC}"
    echo -e "11. Поиск беспроводных подключений"

    echo -e "\n${CYAN}=== Управление уязвимостями ===${NC}"
    echo -e "12. Настройка API ключей"
    
    echo -e "\n${CYAN}=== Отчеты ===${NC}"
    echo -e "13. Генерация HTML отчета"
    
    echo -e "\n${CYAN}=== Система ===${NC}"
    echo -e "14. Очистка экрана"
    echo -e "15. Выход"

    echo -en "${GREEN}Введите ваш выбор [1-15]: ${NC}"
}

# Main script execution
clear_screen

configure_api_keys() {
    echo -e "\n${YELLOW}=== Настройка API ключей ===${NC}"
    
    if [ -z "$NVD_API_KEY" ]; then
        echo -n "Введите NVD API ключ (или нажмите Enter чтобы пропустить): "
        read -r key
        if [ -n "$key" ]; then
            NVD_API_KEY=$key
            echo "NVD API ключ сохранен"
        fi
    else
        echo "Текущий NVD API ключ: ${NVD_API_KEY:0:4}****${NVD_API_KEY: -4}"
        echo -n "Хотите изменить? [y/N]: "
        read -r change
        if [[ "$change" =~ ^[Yy]$ ]]; then
            echo -n "Введите новый NVD API ключ: "
            read -r new_key
            NVD_API_KEY=$new_key
            echo "NVD API ключ обновлен"
        fi
    fi
    
    if [ -z "$VULNERS_API_KEY" ]; then
        echo -n "Введите Vulners API ключ (или нажмите Enter чтобы пропустить): "
        read -r key
        if [ -n "$key" ]; then
            VULNERS_API_KEY=$key
            echo "Vulners API ключ сохранен"
        fi
    else
        echo "Текущий Vulners API ключ: ${VULNERS_API_KEY:0:4}****${VULNERS_API_KEY: -4}"
        echo -n "Хотите изменить? [y/N]: "
        read -r change
        if [[ "$change" =~ ^[Yy]$ ]]; then
            echo -n "Введите новый Vulners API ключ: "
            read -r new_key
            VULNERS_API_KEY=$new_key
            echo "Vulners API ключ обновлен"
        fi
    fi
}

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
            echo -en "${GREEN}Введите целевой IP для быстрого сканирования: ${NC}"
            read -r target
            port_scan "$target" "quick"
            ;;
        4)
            echo -en "${GREEN}Введите целевой IP для стандартного сканирования: ${NC}"
            read -r target
            port_scan "$target" "standard"
            ;;
        5)
            echo -en "${GREEN}Введите целевой IP для полного сканирования: ${NC}"
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
            echo -en "${GREEN}Введите целевой IP для сканирования уязвимостей: ${NC}"
            read -r target
            vulnerability_scan "$target"
            ;;
        9)
            echo -en "${GREEN}Введите целевой IP для сканирования веб-уязвимостей: ${NC}"
            read -r target
            web_vulnerability_scan "$target"
            ;;
        10)
            echo -en "${GREEN}Введите целевой IP для сканирования уязвимостей ОС: ${NC}"
            read -r target
            os_vulnerability_scan "$target"
            ;;
        11)
            find_wireless_connections
            ;;
        12)
            configure_api_keys
            ;;
        13)
            generate_report
            ;;
        14)
            clear_screen
            ;;
        15)
            log "${YELLOW}Увидимся. Хорошего дня!${NC}"
            exit 0
            ;;
        *)
            echo -e "${RED}Неверный вариант. Пожалуйста, выберите от 1 до 15.${NC}"
            ;;
    esac
done
       
