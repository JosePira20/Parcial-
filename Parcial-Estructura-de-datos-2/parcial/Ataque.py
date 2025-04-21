import os
import re
import json
import requests
import time

# Ruta a la carpeta con archivos .log
carpeta_logs = r"C:\Users\306\repositorio\SotM34\http"

if not os.path.exists(carpeta_logs):
    print("La carpeta no existe:", carpeta_logs)
    exit()

# Expresión regular robusta para logs tipo Apache
regex_log = re.compile(
    r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3}) - - \['
    r'(?P<fecha>\d{2}/\w{3}/\d{4}):'
    r'(?P<hora>\d{2}:\d{2}:\d{2}) [^\]]+\] '
    r'"(?:GET|POST|PUT|DELETE|HEAD|OPTIONS) '
    r'(?P<ruta>\S+) [^"]+" '
    r'(?P<codigo>\d{3})'
)

# Función para obtener país desde IP
def get_country(ip):
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        data = response.json()
        return data.get("country", "Desconocido")
    except:
        return "Error"

resultados = []
ips_cache = {}

# Procesar cada archivo .log
for archivo in os.listdir(carpeta_logs):
    if archivo.endswith(".log"):
        print(f"Procesando: {archivo}")
        ruta_archivo = os.path.join(carpeta_logs, archivo)
        with open(ruta_archivo, "r", encoding="utf-8", errors="ignore") as f:
            for linea in f:
                match = regex_log.search(linea)
                if match:
                    ip = match.group("ip")
                    fecha = match.group("fecha")
                    hora = match.group("hora")
                    ruta = match.group("ruta")
                    codigo = match.group("codigo")

                    if ip in ips_cache:
                        pais = ips_cache[ip]
                    else:
                        pais = get_country(ip)
                        ips_cache[ip] = pais
                        time.sleep(1)

                    resultados.append({
                        "archivo": archivo,
                        "ip": ip,
                        "fecha": fecha,
                        "hora": hora,
                        "ruta": ruta,
                        "codigo": codigo,
                        "pais": pais
                    })

# Guardar resultados
with open("resultados.json", "w", encoding="utf-8") as salida:
    json.dump(resultados, salida, indent=2, ensure_ascii=False)

print(f"\n✅ Proceso terminado. Se encontraron {len(resultados)} registros. Guardados en 'resultados.json'")
