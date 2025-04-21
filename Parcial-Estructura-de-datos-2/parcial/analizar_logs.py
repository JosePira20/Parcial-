import re
from collections import Counter
import matplotlib.pyplot as plt

# ------------------------- ANALIZAR ACCESS LOG -------------------------
# Ruta del archivo de logs de acceso
archivo_log = r'C:\Users\jose\Pictures\SotM34\Parcial-Estructura-de-datos-2\SotM34\http\access_log.1'

# Listado de IPs sospechosas en el archivo de acceso
ips_acceso = []

# Leer el archivo de logs
with open(archivo_log, 'r', encoding='utf-8', errors='ignore') as f:
    for linea in f:
        # Buscar las IPs en las primeras posiciones de cada línea
        match = re.match(r'^(\d+\.\d+\.\d+\.\d+)', linea)
        if match:
            ip = match.group(1)
            ips_acceso.append(ip)

# Contamos las IPs y mostramos las más frecuentes
contador_ips_acceso = Counter(ips_acceso)
print("Top 10 IPs más frecuentes en el archivo de acceso:")
for ip, cantidad in contador_ips_acceso.most_common(10):
    print(f"{ip}: {cantidad} veces")

# ------------------------- ANALIZAR SYSLOG -------------------------
# Ruta del archivo de logs de syslog
archivo_logs = r'C:\Users\jose\Pictures\SotM34\Parcial-Estructura-de-datos-2\sotM34\syslog\messages.1'

# Expresión regular para encontrar intentos fallidos de acceso
patron_fallo = re.compile(r'authentication failure.*rhost=(\d+\.\d+\.\d+\.\d+)')

# Contador para IPs sospechosas en el syslog
ips_sospechosas = Counter()

try:
    with open(archivo_logs, 'r', encoding='utf-8', errors='ignore') as f:
        # Imprimir las primeras 10 líneas para diagnóstico
        print("\nPrimeras 10 líneas del archivo syslog para diagnóstico:")
        for i, linea in enumerate(f):
            if i < 10:
                print(linea.strip())

        f.seek(0)  # Volver al principio para hacer el análisis completo

        # Buscar IPs sospechosas
        for linea in f:
            match = patron_fallo.search(linea)
            if match:
                ip = match.group(1)  # Obtener la IP del fallo de autenticación
                ips_sospechosas[ip] += 1

    # Mostrar las IPs más sospechosas
    print("\nTop 10 IPs con intentos fallidos de acceso:")
    for ip, count in ips_sospechosas.most_common(10):
        print(f"{ip}: {count} veces")

    # Opcional: Graficar los intentos fallidos por hora (si tienes las fechas)

except FileNotFoundError:
    print("No se encontró el archivo. Verifica la ruta.")
