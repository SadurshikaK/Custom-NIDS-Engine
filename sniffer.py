import socket
import struct
import time

# --- SYSTEM MEMORY FOR THREAT DETECTION ---
scan_tracker = {}
SCAN_THRESHOLD = 5 # Alert if more than 5 unique ports are touched in 10 seconds

def check_for_port_scan(src_ip, dest_port):
    current_time = time.time()
    
    # 1. If this IP is new, add it to our tracker memory
    if src_ip not in scan_tracker:
        scan_tracker[src_ip] = {'ports': set(), 'first_seen': current_time}
        
    # 2. Add the port they are knocking on
    scan_tracker[src_ip]['ports'].add(dest_port)
    
    # 3. Calculate the behavior metrics
    unique_ports_hit = len(scan_tracker[src_ip]['ports'])
    time_elapsed = current_time - scan_tracker[src_ip]['first_seen']
    
    # 4. The Detection Engine Logic
    if unique_ports_hit > SCAN_THRESHOLD and time_elapsed < 10:
        print(f"\n[!!!] CRITICAL SECURITY ALERT [!!!]")
        print(f"    -> Port Scan Detected from IP : {src_ip}")
        print(f"    -> Behavior : Probed {unique_ports_hit} unique ports in {time_elapsed:.2f} seconds.\n")
        
        # Reset the tracker for this IP so the alarm doesn't spam continuously
        scan_tracker[src_ip] = {'ports': set(), 'first_seen': current_time}

# --- PACKET UNPACKING LOGIC ---
def get_mac_addr(bytes_addr):
    return ':'.join(map('{:02x}'.format, bytes_addr)).upper()

def unpack_ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

def format_ipv4(addr):
    return '.'.join(map(str, addr))

def unpack_ipv4_packet(data):
    version_header_length = data[0]
    
    # FIXED: Extracting the version using bitwise right-shift
    version = version_header_length >> 4
    
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, format_ipv4(src), format_ipv4(target), data[header_length:]

def unpack_icmp(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

def unpack_tcp(data):
    src_port, dest_port, sequence, acknowledgment, offset_reserved_flags = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    return src_port, dest_port, sequence, acknowledgment, data[offset:]

# --- MAIN ENGINE ---
def main():
    try:
        conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    except PermissionError:
        print("Error: You must run this script as root (use sudo).")
        return

    print("Intrusion Detection System Active. Listening for threats...\n")
    
    while True:
        raw_data, addr = conn.recvfrom(65536)
        dest_mac, src_mac, eth_proto, payload = unpack_ethernet_frame(raw_data)
        
        if eth_proto == 8: # IPv4
            version, header_length, ttl, ip_proto, src, target, ip_payload = unpack_ipv4_packet(payload)
            
            if ip_proto == 1: # ICMP
                icmp_type, code, checksum, data = unpack_icmp(ip_payload)
                print(f"[+] ICMP Traffic | Source: {src} -> Dest: {target}")
            
            elif ip_proto == 6: # TCP
                src_port, dest_port, sequence, acknowledgment, data = unpack_tcp(ip_payload)
                print(f"[+] TCP Traffic  | Source: {src}:{src_port} -> Dest: {target}:{dest_port}")
                
                # Feed the traffic data into our Threat Detection Engine
                check_for_port_scan(src, dest_port)

if __name__ == '__main__':
    main()