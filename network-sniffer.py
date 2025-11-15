import os
os.environ['SDL_VIDEO_WINDOW_POS'] = '100,100'
import random
import pgzrun
import pygame
from scapy.all import sniff, IP, TCP
import socket
import threading
import time

pygame.mixer.music.load("song.ogg")  # Eric Matyas
pygame.mixer.music.play(-1)

my_ip = socket.gethostbyname(socket.gethostname())
level = -2
message = ""
target = ""   # Initialisierung, sonst Fehler
running=True
seen_packets = set()
sniffer_started=False

def resolve_dns(ip):
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except socket.herror:
        return ip

def packet_callback(packet):
    global message, seen_packets
    if IP in packet and TCP in packet:
        if packet[TCP].sport in [80, 443] or packet[TCP].dport in [80, 443]:
            if packet[IP].src == my_ip or packet[IP].dst == my_ip:
                return
            ip_src = resolve_dns(packet[IP].src)
            ip_dst = resolve_dns(packet[IP].dst)
            line = f"[WEB] {ip_src}:{packet[TCP].sport} -> {ip_dst}:{packet[TCP].dport}\n"
            
            # Nur anzeigen, wenn neu
            if line not in seen_packets:
                seen_packets.add(line)
                message += line
                print(line)

def draw():
    global level, message
    screen.clear()
    if level == -2:
        screen.blit("disclaimer",(0,0))
    elif level == -1:
        screen.blit("title",(0,0))
    elif level == 0:
        screen.blit("intro",(0,0))
    elif level == 1:
        screen.blit("back",(0,0))
        screen.draw.text(message, center=(400, 180), fontsize=24, color=(255, 255, 0))

def on_key_down(key, unicode=None):
    global level
    if key == keys.ESCAPE:
        pygame.quit()
  
def update():
    global level,running,buttons,sniffer_started
    if (level == 0 or level == -2) and keyboard.RETURN:
        level += 1
        running = True
    elif level == -1 and keyboard.space:
        level = 0
    if level == 1 and keyboard.space:
        level = 0
    if level == 1:
        if running:
            if not sniffer_started:
                threading.Thread(target=start_sniffer, daemon=True).start()
                #sniffer_started=True
            for event in pygame.event.get():
                if event.type == pygame.QUIT:
                    running = False
        
def start_sniffer():
    sniff(prn=packet_callback, filter="tcp port 80 or tcp port 443", count=1)

def on_quit():
#    print("Fenster wird geschlossen...")
    pygame.quit()
    raise SystemExit

pgzrun.go()
