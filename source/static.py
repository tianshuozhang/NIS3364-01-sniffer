from scapy.all import *
from tkinter import *
from tkinter.ttk import *
from scapy.layers.inet import IP
from scapy.all import defragment
import tkinter as tk
def statics(packets,flag):
    if packets is None:
        tk.messagebox.showinfo(title='Notion', message="pelease capture packets before choose this function")
        return
    root = Tk()
    if flag == 1:
        root.title('Ethernet Statics')
    elif flag==2:
        root.title('IP Statics')
    else:
        root.title("IP reassembly")
    root.geometry('800x400')  # 这里的乘号不是 * ，而是小写英文字母 x
    frame0 = tk.Frame(root, bd=5, relief='sunken')
    frame0.place(x=10, y=0, width=780, height=390,)
    scrollbar = Scrollbar(frame0)
    scrollbar.pack(side=RIGHT, fill=Y)
    if flag==3:
        columns = ['No', 'IPversion',  'Id', 'proto', 'Len', 'dst', 'src',
                    'Info','data']
    else:
        columns = ['AddressA', 'AddressB', 'Packets', 'Bytes', 'PacketA->B', 'PacketB->A', 'BytesA->B',
                'BytesB->A']
    table = Treeview(
        master=frame0,  # 父容器
        height=18,  # 表格显示的行数,height行
        columns=columns,  # 显示的列
        show='headings',  # 隐藏首列
        yscrollcommand=scrollbar.set
    )
    scrollbar['command'] = table.yview
    if flag==3:
        root.geometry('950x400')
        column_widths = [30,60,130, 50, 30, 92, 92, 270,160]
        column_anchors = [S, S, S, S, S, S, S, S,S]
        frame0.place(x=10, y=0, width=930, height=390,)
    else:
        column_widths = [135, 135, 60, 60, 92, 92, 92,90]
        column_anchors = [S, S, S, S, S, S, S,S]

    for i in range(len(columns)):
        column = columns[i]
        width = column_widths[i]
        anchor = column_anchors[i]
        table.heading(column=column, text=column)
        table.column(column, width=width, minwidth=width,anchor=anchor)
    table.place(relx=0, rely=0)
    packets_dic = {}
    if flag == 1:  # 以太网会话
        for packet in packets:
            addressa = packet.src
            addressb = packet.dst
            packet_number = 1
            packet_bytes = len(packet)
            if addressa + '-' + addressb not in packets_dic.keys():
                packets_dic[addressa + '-' + addressb] = [packet_number, packet_bytes]
            else:
                packets_dic[addressa + '-' + addressb][0] += packet_number
                packets_dic[addressa + '-' + addressb][1] += packet_bytes
        show_list = []
        key_del = []
        for key, value in packets_dic.items():
            if key in key_del:
                continue
            split = key.find('-')
            addressa=key[0:split]
            addressb=key[split+1:]
            if addressb+'-'+addressa in packets_dic.keys():
                packets_number=value[0]+packets_dic[addressb+'-'+addressa][0]
                packets_bytes=value[1]+packets_dic[addressb+'-'+addressa][1]
                packetA2B = value[0]
                packetB2A = packets_dic[addressb + '-' + addressa][0]
                bytesA2B = value[1]
                bytesB2A = packets_dic[addressb + '-' + addressa][1]
                show_list.append([addressa, addressb, packets_number, packets_bytes, packetA2B, packetB2A, bytesA2B,bytesB2A])
                key_del.append(key)
                key_del.append(addressb + '-' + addressa)
            else:
                packets_number = value[0]
                packets_bytes = value[1]
                packetA2B = packets_number
                packetB2A = 0
                bytesA2B = packets_bytes
                bytesB2A = 0
                show_list.append(
                    [addressa, addressb, packets_number, packets_bytes, packetA2B, packetB2A, bytesA2B,
                        bytesB2A])
                key_del.append(key)

        for i in show_list:
            table.insert('', END, values=i)
    elif flag==2:#IP统计
        for packet in packets:
            if IP in packet and 'ttl' in packet[IP].fields:
                src = packet[IP].src
                dst = packet[IP].dst
            # 继续处理数据包
            else:
                continue
            addressa = src
            addressb = dst

            packet_number = 1
            packet_bytes = len(packet)
            if addressa + '-' + addressb not in packets_dic.keys():
                packets_dic[addressa + '-' + addressb] = [packet_number, packet_bytes]
            else:
                packets_dic[addressa + '-' + addressb][0] += packet_number
                packets_dic[addressa + '-' + addressb][1] += packet_bytes
        show_list = []
        key_del = []
        for key, value in packets_dic.items():
            if key in key_del:
                continue
            split = key.find('-')
            addressa = key[0:split]
            addressb = key[split + 1:]
            if addressb + '-' + addressa in packets_dic.keys():
                packets_number = value[0] + packets_dic[addressb + '-' + addressa][0]
                packets_bytes = value[1] + packets_dic[addressb + '-' + addressa][1]
                packetA2B = value[0]
                packetB2A = packets_dic[addressb + '-' + addressa][0]
                bytesA2B = value[1]
                bytesB2A = packets_dic[addressb + '-' + addressa][1]
                show_list.append(
                    [addressa, addressb, packets_number, packets_bytes, packetA2B, packetB2A, bytesA2B,
                        bytesB2A])
                key_del.append(key)
                key_del.append(addressb + '-' + addressa)
            else:
                packets_number = value[0]
                packets_bytes = value[1]
                packetA2B = packets_number
                packetB2A = 0
                bytesA2B = packets_bytes
                bytesB2A = 0
                show_list.append(
                    [addressa, addressb, packets_number, packets_bytes, packetA2B, packetB2A, bytesA2B,
                        bytesB2A])
                key_del.append(key)
        for i in show_list:
            table.insert('', END, values=i)
    else:#报文重组
        repackets=[]
        fragments =[]
        for packet in packets:
            if IP in packet and 'ttl' in packet[IP].fields:
                if int(packet[IP].flags) == 1:  # 分片数据包
                    fragment_offset = packet[IP].frag
                    if fragment_offset == 0:  # 第一个分片
                        fragments.append(packet[IP])
                    else:
                        fragments.append(packet[IP])
                elif int(packet[IP].flags) == 0:
                    repackets.append(defragment(fragments))
                    fragments =[]
                elif int(packet[IP].flags) == 2:
                    repackets.append(packet[IP])
        for key,value in enumerate(repackets):
            layer = None
            counter = 0
            while True:
                var = value.getlayer(counter)
                if var is None:
                    break
                if not isinstance(var, (Padding, Raw)):
                    layer = var
                counter += 1
            if layer.name[0:3] == "DNS":
                protocol = "DNS"
            else:
                protocol = layer.name
            try:
                data=value[Raw].load
            except Exception as e:
                data=''
            table.insert('', END, values=[key+1,"IPv{}".format(value.version),value.id,protocol,value.len,value.dst,value.src,value.summary(),data])

    mainloop()
