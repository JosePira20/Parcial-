import re
linea = '24.196.254.170 - - [06/Mar/2005:05:28:52 -0500] "GET / HTTP/1.1" 403 2898 "-" "Mozilla/4.0 (compatible; MSIE 5.5; Windows 98)"'

regex_log = r'(?P<ip>\d+\.\d+\.\d+\.\d+)\s+-\s+-\s+(?P<fecha>\d{2}/[A-Za-z]{3}/\d{4}):(?P<hora>\d{2}:\d{2}:\d{2})\s[^]+]\s+"[^"]+"\s+(?P<codigo>\d{3})'

match = re.search(regex_log, linea)
if match:
    print("Coincidencia encontrada:")
    print("IP:", match.group("ip"))
    print("Fecha:", match.group("fecha"))
    print("Hora:", match.group("hora"))
    print("Código:", match.group("codigo"))
else:
    print("No se encontró coincidencia.")