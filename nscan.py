import nmap
import sys


def nmap_A_scan(network_prefix):
    nm = nmap.PortScanner()
    scan_raw_result = nm.scan(hosts=network_prefix, arguments='-v -n -A')
    for host, result in scan_raw_result['scan'].items():
        if result['status']['state'] == 'up':
            print('#' * 17 + 'Host:' + host + '#' * 17)
            print('-' * 20 + 'Sistema operativo adivinar' + '-' * 20)
            for os in result['osmatch']:
                print('El sistema operativo es:' + os['name'] + ' ' * 3 + 'La precisión es:' + os['accuracy'])
            idno = 1
            try:
                for port in result['tcp']:
                    try:
                        print('-' * 17 + 'Detalles del servidor TCP' + '[' + str(idno) + ']' + '-' * 17)
                        idno += 1
                        print('Número de puerto TCP:' + str(port))
                        try:
                            print('Estado:' + result['tcp'][port]['state'])
                        except:
                            pass
                        try:
                            print(Porque: + result['tcp'][port]['reason'])
                        except:
                            pass
                        try:
                            print('Información adicional:' + result['tcp'][port]['extrainfo'])
                        except:
                            pass
                        try:
                            print('Nombre:' + result['tcp'][port]['name'])
                        except:
                            pass
                        try:
                            print('Versión:' + result['tcp'][port]['version'])
                        except:
                            pass
                        try:
                            print('Producto:' + result['tcp'][port]['product'])
                        except:
                            pass
                        try:
                            print('CPE：' + result['tcp'][port]['cpe'])
                        except:
                            pass
                        try:
                            print('Guión:' + result['tcp'][port]['script'])
                        except:
                            pass
                    except:
                        pass
            except:
                pass

            idno = 1
            try:
                for port in result['udp']:
                    try:
                        print('-' * 17 + 'Detalles del servidor UDP' + '[' + str(idno) + ']' + '-' * 17)
                        idno += 1
                        print('Número de puerto UDP:' + str(port))
                        try:
                            print('Estado:' + result['udp'][port]['state'])
                        except:
                            pass
                        try:
                            print(Porque: + result['udp'][port]['reason'])
                        except:
                            pass
                        try:
                            print('Información adicional:' + result['udp'][port]['extrainfo'])
                        except:
                            pass
                        try:
                            print('Nombre:' + result['udp'][port]['name'])
                        except:
                            pass
                        try:
                            print('Versión:' + result['udp'][port]['version'])
                        except:
                            pass
                        try:
                            print('Producto:' + result['udp'][port]['product'])
                        except:
                            pass
                        try:
                            print('CPE：' + result['udp'][port]['cpe'])
                        except:
                            pass
                        try:
                            print('Guión:' + result['udp'][port]['script'])
                        except:
                            pass
                    except:
                        pass
            except:
                pass


if __name__ == '__main__':
    nmap_A_scan('www.rspt.org.cn')