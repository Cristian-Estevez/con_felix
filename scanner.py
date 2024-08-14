import socket
import threading
from queue import Queue, Empty

from utils.logger import Logger

num_threads = 100
queue = Queue()
open_ports = []
shutdown_event = threading.Event()  # Evento de terminación
logger = Logger("SCANNER LOG")
nmap_allowed_host = '45.33.32.156'

# Diccionario de puertos comunes y sus servicios
common_ports = {
    20: 'FTP (File Transfer Protocol)',
    21: 'FTP (File Transfer Protocol)',
    22: 'SSH (Secure Shell)',
    23: 'Telnet',
    25: 'SMTP (Simple Mail Transfer Protocol)',
    53: 'DNS (Domain Name System)',
    80: 'HTTP (HyperText Transfer Protocol)',
    110: 'POP3 (Post Office Protocol v3)',
    143: 'IMAP (Internet Message Access Protocol)',
    443: 'HTTPS (HTTP Secure)',
    3306: 'MySQL',
    3389: 'RDP (Remote Desktop Protocol)',
    5900: 'VNC (Virtual Network Computing)',
    8080: 'HTTP-alt (HTTP Alternate)',
}

def set_num_threads(port_range):
    # Nos aseguramos de no iniciar threads que no se van a utilizar. 
    # 1 thread por puerto en caso de que los puertos sean menos de 100

    global num_threads
    if (len(port_range) < 100):
        num_threads = len(port_range)

def port_scan(host, port):
    """Función que escanea un puerto en un host dado."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        result = sock.connect_ex((host, port))
        if result == 0:
            service = common_ports.get(port, 'Unknown Service')
            open_ports.append((port, service))
            print(get_banner(sock))
            #logger.log_info(f"Puerto {port} está abierto - {service}")
        else:
            #logger.log_debug(f"Puerto {port} está cerrado")
            sock.close()
    except socket.timeout:
        logger.log_warning(f"Timeout escaneando el puerto {port}")
    except socket.error as e:
        logger.log_error(f"Error de socket escaneando el puerto {port}: {e}")
    except Exception as e:
        logger.log_critical(f"Error inesperado escaneando el puerto {port}: {e}")
    finally:
        sock.close()

def get_banner(sock):
    """Intentar obtener un banner del servicio en el puerto."""
    # Hay que pulirlo pero anda
    try:
        sock.send('Anything \r\n'.encode())
        banner = sock.recv(1024).decode()
        return str(banner)
    except socket.timeout:
        logger.log_error("Got timeout trying to get banner.")
        return
    except socket.error as e:
        logger.log_error(f"Error al obtener el banner: {e}")
        return
    except Exception as e:
        logger.log_critical(f"Error inesperado al obtener el banner: {e}")
        return

def threader(host):
    """Función que asigna queue a los hilos."""
    while not shutdown_event.is_set():
        try:
            worker = queue.get(timeout=1)  # Timeout para verificar la señal de terminación
            if worker is None:
                break
            #logger.log_debug(f"Hilo {threading.current_thread().name} escaneando puerto {worker}")
            port_scan(host, worker)
            queue.task_done()
        except Empty:
            continue
        except Exception as e:
            logger.log_critical(f"Excepción en el hilo {threading.current_thread().name}: {e}", exc_info=True)
            break

def start_scanner(host, port_range):
    """Función principal para iniciar el escaneo de puertos."""
    for _ in range(num_threads):
        t = threading.Thread(target=threader, args=(host,))
        t.daemon = True
        t.start()
        logger.log_debug(f"Hilo {t.name} iniciado")

    for port in port_range:
        queue.put(port)
        logger.log_debug(f"Puerto {port} añadido a la cola")

    queue.join()
    shutdown_event.set()  # Señal para terminar los hilos

if __name__ == "__main__":
    # Hay que validar el input de los usuarios, que sean: 
    #   IP válida, 
    #   Puertos valor numérico en rango de 0 a 655...
    #   puerto inicial menor a puerto final
    #
    #   debería buclear en un while ...
    #


    target_host = input("Ingrese la dirección IP o Host(enter para escanear la ip autorizada por nmap): ")
    if (target_host == ''):
        target_host = nmap_allowed_host

    start_port = int(input("Ingrese el puerto inicial: "))
    end_port = int(input("Ingrese el puerto final: "))
    port_range = range(start_port, end_port + 1)
    set_num_threads(port_range)

    logger.log_info("""
                    
        =============================
                Iniciando scan
        =============================
                    
    """)

    start_scanner(target_host, port_range)

    print("Puertos abiertos:")
    for port, service in open_ports:
        print(f"Puerto {port} está abierto - {service}")

    logger.log_info("""
                    
        =============================
                Scan Finalizado
        =============================
                    
    """)

