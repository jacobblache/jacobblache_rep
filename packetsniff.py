#!/usr/bin/env python3
import os as _os
import sys as _sys
import socket as _socket
import time as _time
from struct import Struct as _Struct
from ipaddress import IPv4Address as _IPv4Address
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText_fast_time = _time.time
_write_err = _sys.stdout.write
tcp_header_unpack = _Struct('!2H2LB').unpack_from
udp_header_unpack = _Struct('!4H').unpack_fromdef send_alert(src_ip, dst_ip, INTERACTION_THRESHOLD, count):
    subject = f"Interaction count exceeded ({INTERACTION_THRESHOLD} times)"
    body = f"The interaction between {src_ip} and {dst_ip} has exceeded the set interaction count of {INTERACTION_THRESHOLD}.\nDetails:\n- Source IP: {src_ip}\n- Destination IP: {dst_ip}\n- Count: {count}"
    try:
        msg = MIMEMultipart()
        msg["From"] = FROM_EMAIL
        msg["To"] = TO_EMAIL
        msg["Subject"] = subject
        msg.attach(MIMEText(body, 'plain'))
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as smtp:
            smtp.starttls()
            smtp.login(FROM_EMAIL, SMTP_PASSWORD)
            smtp.send_message(msg)
        print("Email alert sent.")
    except Exception as e:
        print(f"Failed to send email alert. Error: {str(e)}")class RawPacket:
    interaction_count = {}    def __init__(self, data):
        self.timestamp = _fast_time()
        self.protocol = 0
        self._name = self.__class__.__name__
        self._dlen = len(data)
        self.dst_mac = data[:6].hex()
        self.src_mac = data[6:12].hex()
        self._data = data[14:]    def __str__(self):
        return '\n'.join([
            f'{"="*32}',
            f'{" "*8}PACKET',
            f'{"="*32}',
            f'{" "*8}ETHERNET',
            f'{"-"*32}',
            f'src mac: {self.src_mac}',
            f'dst mac: {self.dst_mac}',
            f'{"-"*32}',
            f'{" "*8}IP',
            f'{"-"*32}',
            f'header length: {self.header_len}',
            f'protocol: {self.protocol}',
            f'src ip: {self.src_ip}',
            f'dst ip: {self.dst_ip}',
            f'{"-"*32}',
            f'{" "*8}PROTOCOL',
            f'{"-"*32}',
            f'src port: {self.src_port}',
            f'dst port: {self.dst_port}',
            f'{"-"*32}',
            f'{" "*8}PAYLOAD',
            f'{"-"*32}',
            f'{self.payload}'
        ])    def parse(self):
        self._ip()
        if self.protocol == 6:
            self._tcp()
        elif self.protocol == 17:
            self._udp()
        else:
            _write_err('non tcp/udp packet!\n')
        self._update_interaction_count()    def _ip(self):
        data = self._data
        self.src_ip = _IPv4Address(data[12:16])
        self.dst_ip = _IPv4Address(data[16:20])
        self.header_len = (data[0] & 15) * 4
        self.protocol = data[9]
        self.ip_header = data[:self.header_len]
        self._data = data[self.header_len:]    def _tcp(self):
        data = self._data
        tcp_header = tcp_header_unpack(data)
        self.src_port = tcp_header[0]
        self.dst_port = tcp_header[1]
        self.seq_number = tcp_header[2]
        self.ack_number = tcp_header[3]
        header_len = (tcp_header[4] >> 4 & 15) * 4
        self.proto_header = data[:header_len]
        self.payload = data[header_len:]    def _udp(self):
        data = self._data
        udp_header = udp_header_unpack(data)
        self.src_port = udp_header[0]
        self.dst_port = udp_header[1]
        self.udp_len = udp_header[2]
        self.udp_chk = udp_header[3]
        self.proto_header = data[:8]
        self.payload = data[8:]    def _update_interaction_count(self):
        ip_pair = (self.src_ip, self.dst_ip)
        if ip_pair in self.interaction_count:
            self.interaction_count[ip_pair] += 1
            if self.interaction_count[ip_pair] > INTERACTION_THRESHOLD:
                send_alert(self.src_ip, self.dst_ip, INTERACTION_THRESHOLD, self.interaction_count[ip_pair])
        else:
            self.interaction_count[ip_pair] = 1def parse(data):
    try:
        packet = RawPacket(data)
        packet.parse()
        print(packet)
    except Exception as e:
        _write_err(f'Error parsing packet: {e}\n')def listen_forever(intf):
    sock = _socket.socket(_socket.AF_PACKET, _socket.SOCK_RAW)
    try:
        sock.bind((intf, 3))
    except OSError:
        _sys.exit(f'cannot bind interface: {intf}! exiting...')
    else:
        _write_err(f'now listening on {intf}!\n')
    while True:
        try:
            data = sock.recv(2048)
        except OSError:
            pass
        else:
            parse(data)if __name__ == '__main__':
    FROM_EMAIL = input("Please type your email in the *****@***.*** format: ")
    SMTP_PASSWORD = input("Please type your email's password: ")
    TO_EMAIL = input("Please type an email in the *****@***.*** format in case of alerts: ")
    INTERACTION_THRESHOLD = int(input("Please type a number of interactions you would want to be alerted for: "))
    SMTP_SERVER = "smtp.gmail.com"
    SMTP_PORT = 587
    if _os.geteuid():
        _sys.exit('listener must be run as root! exiting...')
    listen_forever('enp0s3')
