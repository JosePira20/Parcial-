import os
import re
from collections import defaultdict

# Ruta base para los archivos de log
BASE_DIR = "C:/Users/jose/Pictures/SotM34/Parcial-Estructura-de-datos-2/SotM34"

# Función para leer los archivos de log
def read_logs(file_paths):
    logs = []
    for file_path in file_paths:
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                logs.extend(file.readlines())
                print(f"Leyendo archivo: {file_path}")
        except FileNotFoundError:
            print(f"Error: El archivo {file_path} no se encuentra.")
        except Exception as e:
            print(f"Error al leer el archivo {file_path}: {e}")
    return logs

# Función para extraer intentos fallidos de login en los logs de Apache
def extract_failed_logins(logs):
    failed_attempts = defaultdict(int)
    for log in logs:
        if "Failed password" in log:
            match = re.search(r"(\d+\.\d+\.\d+\.\d+)", log)
            if match:
                ip = match.group(1)
                failed_attempts[ip] += 1
    return failed_attempts

# Función para identificar accesos inusuales a Apache
def analyze_apache_access_logs(logs):
    suspicious_ips = defaultdict(int)
    for log in logs:
        if "GET" in log or "POST" in log:
            match = re.search(r"(\d+\.\d+\.\d+\.\d+)", log)
            if match:
                ip = match.group(1)
                suspicious_ips[ip] += 1
    return suspicious_ips

# Función para analizar registros de firewall (iptables)
def analyze_firewall_logs(logs):
    blocked_ips = defaultdict(int)
    for log in logs:
        if "DROP" in log or "BLOCK" in log:
            match = re.search(r"(\d+\.\d+\.\d+\.\d+)", log)
            if match:
                ip = match.group(1)
                blocked_ips[ip] += 1
    return blocked_ips

# Función para analizar alertas del IDS Snort
def analyze_snort_logs(logs):
    snort_alerts = defaultdict(int)
    for log in logs:
        if "ALERT" in log:
            match = re.search(r"(\d+\.\d+\.\d+\.\d+)", log)
            if match:
                ip = match.group(1)
                snort_alerts[ip] += 1
    return snort_alerts

# Función principal para ejecutar el análisis
def main():
    apache_files = [
        os.path.join(BASE_DIR, 'http', 'error_log'),
        os.path.join(BASE_DIR, 'http', 'access_log'),
        os.path.join(BASE_DIR, 'http', 'ssl_error_log')
    ]
    firewall_file = [os.path.join(BASE_DIR, 'iptables', 'iptablesyslog')]
    snort_file = [os.path.join(BASE_DIR, 'snort', 'snortsyslog')]

    apache_logs = read_logs(apache_files)
    firewall_logs = read_logs(firewall_file)
    snort_logs = read_logs(snort_file)

    # Intentos fallidos de login
    failed_logins = extract_failed_logins(apache_logs)
    print("\nIntentos fallidos de login:")
    if failed_logins:
        for ip, count in failed_logins.items():
            print(f"IP {ip}: {count} intentos fallidos")
    else:
        print("No se encontraron intentos fallidos de login.")

    # Accesos inusuales a Apache
    suspicious_access = analyze_apache_access_logs(apache_logs)
    print("\nAccesos inusuales a Apache:")
    if suspicious_access:
        for ip, count in suspicious_access.items():
            print(f"IP {ip}: {count} accesos")
    else:
        print("No se encontraron accesos inusuales en Apache.")

    # Bloqueos de firewall
    blocked_ips = analyze_firewall_logs(firewall_logs)
    print("\nBloqueos de firewall:")
    if blocked_ips:
        for ip, count in blocked_ips.items():
            print(f"IP {ip}: {count} bloqueos")
    else:
        print("No se encontraron bloqueos en el firewall.")

    # Alertas de Snort
    snort_alerts = analyze_snort_logs(snort_logs)
    print("\nAlertas de Snort:")
    if snort_alerts:
        for ip, count in snort_alerts.items():
            print(f"IP {ip}: {count} alertas")
    else:
        print("No se encontraron alertas en Snort.")

if __name__ == "__main__":
    main()
