from tkinter.font import Font
from scapy.all import *
from tkinter import *
from tkinter.ttk import *
from scapy.layers.inet import IP
from queue import Queue
from scapy.arch.common import compile_filter
from tkinter import filedialog
import tkinter as tk
from static import statics
class PacketAnalyzer:
    def __init__(self):
        self.packets = None
        self.packet = None
        self.sniffer = None
        self.packet_handling = None
        self.packetqueue = Queue()
        self.root = Tk()
        self.root.title('Packet Analyzer')
        self.root.geometry('1000x600')
        self.create_widgets()

    def create_widgets(self):
        self.create_menu()
        self.choose_NIC()

    def choose_NIC(self):
        ifaces_list = []
        for face in get_working_ifaces():
            ifaces_list.append(face.name)
        self.frame=tk.Frame(self.root, bd=5, relief='sunken')
        self.frame.place(x=10, y=40, width=980, height=580, )
        self.listbox = tk.Listbox(self.frame)
        self.listbox.pack(fill='both', expand=True)
        self.listbox.bind("<<ListboxSelect>>", self.onlistboxselect)
        # 将列表元素添加到Listbox中
        for item in ifaces_list:
            self.listbox.insert(tk.END, item)
        self.label1 = Label(self.root, text="Choose NIC:", font=("微软雅黑", 10), )
        self.label1.place(relx=0.48, rely=0.01)
        font_obj = Font(family='Arial', size=12)
        self.listbox.config(font=font_obj)
    def onlistboxselect(self,e):
        selected_index = self.listbox.curselection()
        if selected_index:
            index = selected_index[0]
            # 获取所选行的文本内容
            self.frame.destroy()
            self.listbox.destroy()
            self.interface(index)
            self.create_table()


    def create_menu(self):
        menu_bar = Menu(self.root)
        self.root.config(menu=menu_bar)

        file_menu = Menu(menu_bar, tearoff=0)
        file_menu.add_command(label="Introduction", command=self.introduction)
        file_menu.add_separator()
        file_menu.add_command(label="Save", command=self.save)
        file_menu.add_separator()
        file_menu.add_command(label="Open", command=self.openfile)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        menu_bar.add_cascade(label="File", menu=file_menu)

        analyze_menu = Menu(menu_bar, tearoff=0)
        analyze_menu.add_command(label="IP reassemble",command=lambda: statics(self.packets,3))
        file_menu.add_separator()

        menu_bar.add_cascade(label="reassemble", menu=analyze_menu)

        statistics_menu=Menu(menu_bar,tearoff=0)
        statistics_menu.add_command(label="Ethernet Statistics", command=lambda: statics(self.packets,1))
        statistics_menu.add_command(label="IP Statistics",command=lambda: statics(self.packets,2))
        menu_bar.add_cascade(label="Statistics",menu=statistics_menu)

        self.root.config(menu=menu_bar)
    def interface(self,index):
        ifaces_list = []
        for face in get_working_ifaces():
            ifaces_list.append(face.name)
        print(ifaces_list)
        face_frame = tk.Frame(self.root, bd=5, relief='sunken')
        face_frame.place(x=10, y=0, width=980, height=80, )
        self.comb = Combobox(face_frame, values=ifaces_list)
        self.comb.place(relx=0.1, rely=0.2, relwidth=0.7)
        self.comb.current(index)
        self.label1 = Label(face_frame, text="Choose NIC:", font=("微软雅黑", 10), )
        self.label1.place(relx=0.01, rely=0.2)

        Dy_String = tk.StringVar()

        self.entry1 = tk.Entry(face_frame,
                               textvariable=Dy_String)  # ,validate ="focus",validatecommand=self.check_filter)
        self.entry1.bind("<FocusOut>", self.checkfilter)
        self.entry1.place(relx=0.1, rely=0.6, relwidth=0.7)
        self.label1 = Label(face_frame, text="filter:", font=("微软雅黑", 10), )
        self.label1.place(relx=0.01, rely=0.6)

        self.Button = tk.Button(face_frame, text="Start", command=self.getpacket)
        self.Button.place(relx=0.85, rely=0.55, relwidth=0.05)

        tree_frame = tk.Frame(self.root, bd=5, relief='sunken')
        tree_frame.place(x=10, y=250, width=980, height=280, )
        self.tree_layer = Treeview(tree_frame, height=14, columns=('qy'), show='tree')
        self.tree_layer.column('#0', width=980, stretch=False)
        # self.tree_layer.place(relx=0.0, rely=0.0)
        self.tree_layer.pack(anchor=W, ipadx=100, side=LEFT, expand=True, fill=BOTH)

        scrollbar = Scrollbar(tree_frame,orient=VERTICAL)
        scrollbar.pack(side=RIGHT, fill=BOTH)

        self.tree_layer['yscrollcommand'] = scrollbar.set

        scrollbar['command'] = self.tree_layer.yview


    def checkfilter(self,e):
        filter_s=self.entry1.get().strip()
        if filter_s=='':
            self.entry1.configure(bg="white")
            return
        try:
            compile_filter(filter_exp=filter_s)
            self.entry1.configure(bg="green")
        except:
            self.entry1.configure(bg="red")
            return
    def getpacket(self):
        #
        if self.sniffer:
            self.sniffer.stop()
            self.sniffer = None
            self.Button.configure(bg="red")
            self.Button.configure(text="Strat")
            self.count=0
            return
        iface=self.chooseiface()
        filter_exp=self.entry1.get().strip()
        print(filter_exp)
        if iface is None:
            tk.messagebox.showinfo(title='Notion', message='Please select the NIC first')
            return
        self.sniffer = AsyncSniffer(
            iface=iface,
            prn=self.packetanalyse,
            filter=filter_exp,
        )
        #每次抓包都清空表格
        x=self.table.get_children()
        for item in x:
            self.table.delete(item)
        x=self.tree_layer.get_children()
        for item in x:
            self.tree_layer.delete(item)
        self.count=0
        self.packets=[]#清空缓存的数据包
        now_time = datetime.now().strftime( "%Y%m%d%H%M%S" )
        self.filename1 = "./pcaps/{0}.pcap".format(now_time)
        self.filename2 = "./txts/{0}.txt".format(now_time)
        self.sniffer.start()
        self.Button.configure(bg="green")
        self.Button.configure(text="Stop")
        print('开始抓包')

    def packetanalyse(self, packet):
        self.packetqueue.put(packet)
        self.packets.append(packet)  # 将数据包添加到列表保存
        self.count += 1
        for i in range(5):
            T1 = threading.Thread(name='t1', target=self.handlepacket, daemon=True)
            T1.start()
    def handlepacket(self):
        lock=threading.Lock()
        with lock:
            packet=self.packetqueue.get()
            time_show=datetime.fromtimestamp(int(packet.time)).strftime('%Y-%m-%d %H:%M:%S')
            if IP in packet:
                src = packet[IP].src
                dst = packet[IP].dst
            else:
                src = packet.src
                dst = packet.dst
            layer = None
            counter = 0
            while True:
                var = packet.getlayer(counter)
                if var is None:
                    break
                if not isinstance(var, (Padding, Raw)):
                    layer=var
                counter += 1
            if layer.name[0:3]=="DNS":
                protocol="DNS"
            else:
                protocol = layer.name
            length = f"{len(packet)}"
            try:
                info = str(packet.summary())
            except:
                info = "error"
            show_info=[self.count,time_show,src,dst,protocol,length,info]
            print(info)
            items=self.table.insert('', END, values=show_info)
            self.table.see(items)
    def chooseiface(self):
        iface_index=self.comb.current()
        if iface_index==-1:#没选择网卡
            return None
        iface=get_working_ifaces()[iface_index]
        print(iface)
        return iface

    def create_table(self):
        self.table_frame = tk.Frame(self.root,bd=5,relief='sunken')
        self.table_frame.place(x=10, y=85, width=980, height=160,)
        scrollbar = Scrollbar(self.table_frame,orient=VERTICAL)
        scrollbar.pack(side=RIGHT, fill=Y)
        columns=['No', 'Time', 'Source', 'Destination', 'Protocol', 'Length','Info']
        self.table = Treeview(
            master=self.table_frame,
            height=8,
            columns=columns,
            show='headings',
            yscrollcommand=scrollbar.set
        )
        scrollbar['command']=self.table.yview
        self.table.bind("<<TreeviewSelect>>", self.onSelectpacket)
        column_widths = [60, 150, 160, 160, 110, 80, 210]

        column_anchors = [S, S, S,S, S, S, S]

        for i in range(len(columns)):
            column = columns[i]
            width = column_widths[i]

            anchor = column_anchors[i]
            self.table.heading(column=column, text=column)
            self.table.column(column, width=width,anchor=anchor)

        self.table.pack()

    def onSelectpacket(self, e):
        itm = self.table.set(self.table.focus())
        print(itm)
        try:
            packet = self.packets[eval(itm['No']) - 1]
        except Exception as e:
            return
        self.packet_handling = packet
        x = self.tree_layer.get_children()
        for item in x:
            self.tree_layer.delete(item)
        layer_name = []
        counter = 0
        Ethernet_layer = packet.getlayer(0)
        if Ethernet_layer.name == 'Ethernet':
            pass
        while True:
            layer = packet.getlayer(counter)
            if layer is None:
                break
            layer_name.append(layer)
            counter += 1
        parent_chile = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
        for index, layer in enumerate(layer_name):
            parent_chile[index] = self.tree_layer.insert("", index, text=layer.name)
            print(layer.name)
            for name, value in layer.fields.items():
                self.tree_layer.insert(parent_chile[index], END, text=f"{name}: {value}")
            childtree = self.tree_layer.insert(parent_chile[index], END, text="Raw data tree")
            self.tree_layer.insert(childtree,END,text=hexdump(layer, dump=True))
            print(hexdump(layer,dump=True))
        t=self.tree_layer.insert("", index+1, text="Raw data")
        self.tree_layer.insert(parent=t,index=index+1,text=hexdump(Ethernet_layer, dump=True))
    
    def introduction(self):
        tk.messagebox.showinfo(title='prompt', message='packet capture program')

    def save(self):
        os.makedirs(os.path.dirname(self.filename1), exist_ok=True)
        os.makedirs(os.path.dirname(self.filename2), exist_ok=True)
        o_open_file = PcapWriter(self.filename1, append=True)
        for packet in self.packets:
            o_open_file.write(packet)
        with open(self.filename2, "w+") as file:
            file.write('No\tTime\tSource\tDestination\tProtocol\tLength\tinfo\n')
            for row_id in self.table.get_children():
                values = self.table.item(row_id)['values']
                line = "\t".join(str(element) for element in values)
                file.write(line+'\n')

    def openfile(self):
        t = threading.Thread(name='t', target=self.openthread, daemon=True)
        # t.start()
        self.openthread()
    def openthread(self):
        root = tk.Tk()
        root.withdraw()
        # 选择文件
        file_path = filedialog.askopenfilename(initialdir=os.getcwd())
        print(file_path)
        if file_path[-4:]==".txt":
            # 使用特定的工具打开文件
            tool_path = "notepad.exe"  # 替换为你要使用的工具的路径
            subprocess.call([tool_path, file_path])
        if file_path[-5:]==".pcap":
            x=self.table.get_children()
            for item in x:
                self.table.delete(item)
            x=self.tree_layer.get_children()
            for item in x:
                self.tree_layer.delete(item)
            self.count=0
            self.packets=[]#清空缓存的数据包
            self.packetqueue = Queue()
            cap=rdpcap(file_path)
            for packet in cap:
                self.packetqueue.put(packet)
                self.packets.append(packet)  # 将数据包添加到列表保存
                self.count += 1
                time_show=datetime.fromtimestamp(int(packet.time)).strftime('%Y-%m-%d %H:%M:%S')
                if IP in packet:
                    src = packet[IP].src
                    dst = packet[IP].dst
                else:
                    src = packet.src
                    dst = packet.dst
                layer = None
                counter = 0
                while True:
                    var = packet.getlayer(counter)
                    if var is None:
                        break
                    if not isinstance(var, (Padding, Raw)):
                        layer=var
                    counter += 1
                if layer.name[0:3]=="DNS":
                    protocol="DNS"
                else:
                    protocol = layer.name
                length = f"{len(packet)}"
                try:
                    info = str(packet.summary())
                except:
                    info = "error"
                show_info=[self.count,time_show,src,dst,protocol,length,info]
                print(info)
                items=self.table.insert('', END, values=show_info)
                self.table.see(items)
if __name__ == '__main__':
    analyzer = PacketAnalyzer()
    mainloop()