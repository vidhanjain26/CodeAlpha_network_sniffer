import threading
from tkinter import *
from tkinter.scrolledtext import ScrolledText
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
from datetime import datetime

sniffing = False

def packet_callback(packet):
    if not sniffing:
        return

    output = "\n" + "="*70 + "\n"
    output += f"Time: {datetime.now()}\n"

    if IP in packet:
        ip_layer = packet[IP]
        output += f"Source IP      : {ip_layer.src}\n"
        output += f"Destination IP : {ip_layer.dst}\n"

        if TCP in packet:
            output += "Protocol       : TCP\n"
            output += f"Source Port    : {packet[TCP].sport}\n"
            output += f"Destination Port: {packet[TCP].dport}\n"
            if Raw in packet:
                output += f"Payload        : {bytes(packet[Raw])[:50]}\n"

        elif UDP in packet:
            output += "Protocol       : UDP\n"
            output += f"Source Port    : {packet[UDP].sport}\n"
            output += f"Destination Port: {packet[UDP].dport}\n"
            if Raw in packet:
                output += f"Payload        : {bytes(packet[Raw])[:50]}\n"

        elif ICMP in packet:
            output += "Protocol       : ICMP\n"

        else:
            output += "Protocol       : Other\n"

    else:
        output += "Non-IP Packet Captured\n"

    text_area.insert(END, output)
    text_area.see(END)

def start_sniffing():
    global sniffing
    sniffing = True
    status_label.config(text="Status: Sniffing...", fg="green")
    threading.Thread(target=lambda: sniff(prn=packet_callback, store=False)).start()

def stop_sniffing():
    global sniffing
    sniffing = False
    status_label.config(text="Status: Stopped", fg="red")

# GUI Window
root = Tk()
root.title("Basic Network Sniffer - Internship Project")
root.geometry("900x550")

Label(root, text="Network Packet Sniffer", font=("Arial", 18, "bold")).pack(pady=10)

frame = Frame(root)
frame.pack()

start_btn = Button(frame, text="Start Sniffing", bg="green", fg="white", width=15, command=start_sniffing)
start_btn.grid(row=0, column=0, padx=10)

stop_btn = Button(frame, text="Stop Sniffing", bg="red", fg="white", width=15, command=stop_sniffing)
stop_btn.grid(row=0, column=1, padx=10)

status_label = Label(root, text="Status: Stopped", font=("Arial", 12), fg="red")
status_label.pack(pady=5)

text_area = ScrolledText(root, width=110, height=25, font=("Consolas", 10))
text_area.pack(padx=10, pady=10)

root.mainloop()
