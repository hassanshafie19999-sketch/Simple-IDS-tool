
from scapy.all import *

def packet_callback(packet):
    """
    دالة رد الاتصال التي يتم استدعاؤها لكل حزمة يتم التقاطها.
    تقوم بتحليل الحزمة وتطبيق قواعد الكشف.
    """
    # التحقق مما إذا كانت الحزمة تحتوي على طبقة IP
    if packet.haslayer(IP):
        print(f"[+] Packet: {packet.summary()}")

        # قاعدة الكشف 1: الكشف عن حزم ICMP (ping) غير المصرح بها
        # يمكن أن يشير العدد الكبير من حزم ICMP إلى هجوم ICMP flood
        if packet.haslayer(ICMP):
            print("[!] Potential ICMP flood detected!")

        # قاعدة الكشف 2: الكشف عن محاولات فحص المنافذ (Port Scan)
        # يتم الكشف عن حزم TCP التي تحتوي على علامات معينة (SYN, FIN, RST)
        # والتي تستهدف منافذ شائعة.
        if packet.haslayer(TCP) and (packet.flags == 'S' or packet.flags == 'F' or packet.flags == 'R'):
            # قائمة بالمنافذ الشائعة التي قد تكون هدفًا للفحص
            common_ports = [21, 22, 23, 80, 443, 3389, 8080]
            if packet.dport in common_ports:
                print(f"[!] Port scan attempt detected on port {packet.dport} from {packet.src}!")


print("[*] Starting simple IDS... Press Ctrl+C to stop.")
# بدء عملية شم الشبكة (sniffing)
# prn=packet_callback: تحدد الدالة التي سيتم استدعاؤها لكل حزمة.
# store=0: تمنع Scapy من تخزين الحزم في الذاكرة، مما يوفر الموارد.
sniff(prn=packet_callback, store=0)


