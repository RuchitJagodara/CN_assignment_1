from scapy.all import rdpcap, PcapNgReader, Raw
from collections import defaultdict

def analyze_pcapng(file_path):
    protocols = defaultdict(int)
    packets = PcapNgReader(file_path)

    for pkt in packets:
        if pkt.haslayer(Raw):
            payload = pkt[Raw].load
            if b'HTTP' in payload:
                protocols['HTTP'] += 1
            elif b'SMTP' in payload:
                protocols['SMTP'] += 1
            elif b'FTP' in payload:
                protocols['FTP'] += 1
            elif b'SSH' in payload:
                protocols['SSH'] += 1
            elif b'DNS' in payload:
                protocols['DNS'] += 1
            elif b'IMAP' in payload:
                protocols['IMAP'] += 1
            elif b'POP3' in payload:
                protocols['POP3'] += 1
            elif b'SNMP' in payload:
                protocols['SNMP'] += 1
            elif b'LDAP' in payload:
                protocols['LDAP'] += 1
            elif b'RTP' in payload:
                protocols['RTP'] += 1
            elif b'HTTPS' in payload:
                protocols['HTTPS'] += 1
            elif b'HTTP2' in payload:
                protocols['HTTP2'] += 1
            elif b'BGP' in payload:
                protocols['BGP'] += 1
            elif b'RIP' in payload:
                protocols['RIP'] += 1
            elif b'OSPF' in payload:
                protocols['OSPF'] += 1
            elif b'RDP' in payload:
                protocols['RDP'] += 1
            elif b'TELNET' in payload:
                protocols['TELNET'] += 1
            elif b'LDAP' in payload:
                protocols['LDAP'] += 1
            elif b'XMPP' in payload:
                protocols['XMPP'] += 1
            elif b'MQTT' in payload:
                protocols['MQTT'] += 1
            elif b'CoAP' in payload:
                protocols['CoAP'] += 1

    return protocols

if __name__ == "__main__":
    file_path = 'question3.pcapng'
    protocols = analyze_pcapng(file_path)
    
    print("Application Layer Protocols:")
    for protocol, count in protocols.items():
        print(f"{protocol}: {count}")