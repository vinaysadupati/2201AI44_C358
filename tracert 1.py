import time
from scapy.all import *

def format_output(ttl, hop_ip, rtt_list, packet_loss):
    if hop_ip:
        avg_rtt = round(sum(rtt_list) / len(rtt_list), 2)
        formatted_output = f" {ttl:<3} {hop_ip:<16} {avg_rtt:>8} ms {packet_loss:>10}% packet loss"
    else:
        formatted_output = f" {ttl:<3} *  Request timed out."
    return formatted_output

def scapy_tracert(dest_ip, max_ttl=30, timeout=2, packet_size=64, pings_per_hop=3, delay_between_pings=1, save_to_file=None):
    output_lines = []
    output_lines.append(f"Tracing route to {dest_ip} over a maximum of {max_ttl} hops:\n")
    
    for ttl in range(1, max_ttl + 1):
        rtt_list = []
        packet_loss = 0
        
        for _ in range(pings_per_hop):
            pkt = IP(dst=dest_ip, ttl=ttl)/ICMP()/(b'X' * packet_size)
            start_time = time.time()
            try:
                reply = sr1(pkt, verbose=0, timeout=timeout)
            except Exception as e:
                output_lines.append(f"Error sending packet: {e}\n")
                return
            
            rtt = (time.time() - start_time) * 1000  # RTT in milliseconds
            
            if reply:
                rtt_list.append(round(rtt, 2))
                if reply.src == dest_ip:
                    break
            else:
                packet_loss += 1
                rtt_list.append(None)
            
            time.sleep(delay_between_pings)
        
        if len(rtt_list) > 0 and None not in rtt_list:
            output_lines.append(format_output(ttl, reply.src, rtt_list, packet_loss/pings_per_hop * 100) + '\n')
        elif reply:
            output_lines.append(format_output(ttl, reply.src, rtt_list, packet_loss/pings_per_hop * 100) + '\n')
        else:
            output_lines.append(format_output(ttl, None, [], 100) + '\n')
        
        if reply and reply.src == dest_ip:
            output_lines.append("Trace complete.\n")
            break
    else:
        output_lines.append("Trace incomplete.\n")
    
    output_str = ''.join(output_lines)
    print(output_str)
    
    if save_to_file:
        try:
            with open(save_to_file, 'w') as f:
                f.write(output_str)
        except IOError as e:
            print(f"Error saving to file: {e}")
    
    return output_str

if __name__ == "__main__":
    # Get user input
    dest_ip = input("Enter the destination IP or hostname: ")
    max_ttl = int(input("Enter the maximum TTL (default 30): ") or "30")
    timeout = int(input("Enter the timeout in seconds (default 2): ") or "2")
    packet_size = int(input("Enter the packet size in bytes (default 64): ") or "64")
    pings_per_hop = int(input("Enter the number of pings per hop (default 3): ") or "3")
    delay_between_pings = int(input("Enter the delay between pings in seconds (default 1): ") or "1")
    save_to_file = input("Enter the filename to save the output (leave blank if not saving): ")

    # Run tracert
    scapy_tracert(dest_ip, max_ttl=max_ttl, timeout=timeout, packet_size=packet_size, pings_per_hop=pings_per_hop, delay_between_pings=delay_between_pings, save_to_file=save_to_file)
