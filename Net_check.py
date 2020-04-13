#!/usr/bin/python3
# -*- coding: UTF-8 -*-

from tkinter import *
import tkinter.messagebox as messagebox
import sys
import socket
import time
import signal
from timeit import default_timer as timer
import socket
import struct
import select
import threading
from scapy.all import *
import ctypes
from urllib import parse
import pycurl,os
from io import BytesIO

class Application(Frame):
    
    def __init__(self, master=None):
        Frame.__init__(self, master)
        self.pack()
        self.createWidgets()
        #######
        self.passed = 0
        self.failed = 0
        self.host = "http://www.baidu.com"
        self.port = 80
        self.maxCount = 10000
        self.TmaxCount = 30
        self.count = 0

    def createWidgets(self):

        fm1 = Frame(self.master)
        # 该容器放在左边排列
        fm1.pack(side=TOP, padx=10,fill=BOTH, expand=YES)
        v = StringVar(fm1, value='https://www.baidu.com/s?wd=%E6%84%9F%E5%86%92')
        self.nameInput = Entry(fm1, textvariable=v)
        self.nameInput.pack(side=LEFT,fill=X,expand=YES)


        # fm2 = Frame(self.master)
        # # 该容器放在左边排列，就会挨着fm1
        # fm2.pack(side=LEFT, fill=BOTH,padx=10, expand=YES)
        # self.portInput = Entry(self)
        # self.portInput.pack()
        self.alertButton = Button(fm1, text='Ping', command=lambda:self.thread_it(self.tcpping))
        self.alertButton.pack(side=LEFT,fill=X,expand=YES)
        self.alertButton = Button(fm1, text='Tracert', command=lambda:self.thread_it(self.Tracert))
        self.alertButton.pack(side=LEFT,fill=X,expand=YES)
        self.alertButton = Button(fm1, text='curl', command=lambda:self.thread_it(self.ct))
        self.alertButton.pack(side=LEFT,fill=X,expand=YES)

        fm3 = Frame(self.master)
        # 该容器放在左边排列，就会挨着fm1
        fm3.pack(side=TOP, padx=10,fill=BOTH, expand=YES)

        self.alertText = Text(fm3, height=20,width=50)
        self.alertText.pack(side=LEFT,fill=BOTH,expand=YES)

        self.alertText2 = Text(fm3, height=20,width=30)
        self.alertText2.pack(side=LEFT,fill=BOTH,expand=YES)

        fm4 = Frame(self.master)
        # 该容器放在左边排列，就会挨着fm1
        fm4.pack(side=TOP, padx=10,fill=BOTH, expand=YES)

        self.alertText3 = Text(fm4, height=20,width=80)
        self.alertText3.pack(side=BOTTOM,fill=BOTH,expand=YES)
    # 打包进线程（耗时的操作）
    @staticmethod
    def thread_it(func, *args):
        t = threading.Thread(target=func, args=args) 
        t.setDaemon(True)   # 守护--就算主界面关闭，线程也会留守后台运行（不对!）
        t.start()           # 启动
        # t.join()          # 阻塞--会卡死界面
    def pinglog(self,content):
        file = os.path.abspath('.')+r'/ping_log.txt'
        with open(file, 'a+') as f:
            f.write(content+"\r\n")
    def tracertlog(self,content):
        file = os.path.abspath('.')+r'/tracert_log.txt'
        with open(file, 'a+') as f:
            f.write(content+"\r\n")
    def curllog(self,content):
        file = os.path.abspath('.')+r'/curl_log.txt'
        with open(file, 'a+') as f:
            f.write(content+"\r\n")
    ################################################
    def getResults(self):
        """ Summarize Results """
        lRate = 0
        if self.failed != 0:
            lRate = self.failed / (self.count) * 100
            lRate = "%.2f" % lRate
        # print("\nTCP Ping Results: Connections (Total/Pass/Fail): [{:}/{:}/{:}] (Failed: {:}%)".format((self.count), self.passed, self.failed, str(lRate)))
        self.pinglog("\nTCP Ping Results: Connections (Total/Pass/Fail): [{:}/{:}/{:}] (Failed: {:}%)".format((self.count), self.passed, self.failed, str(lRate)));
    def signal_handler(self,signal, frame):
        """ Catch Ctrl-C and Exit """
        self.getResults()
        sys.exit(0)

    def tcpping(self):
        self.pinglog("\n-----------------"+self.host+"-----------------\n")
        self.host = self.nameInput.get() or 'baidu.com'

        parseResult = parse.urlparse(self.host)
        Host = parseResult.netloc
        Port = 443 if (parseResult.scheme =="https") else 80

        # Register SIGINT Handler
        # Loop while less than max count or until Ctrl-C caught
        while self.count < self.maxCount:
            # Increment Counter
            self.count += 1
            success = False
            # New Socket
            s = socket.socket(
            socket.AF_INET, socket.SOCK_STREAM)
            # 1sec Timeout
            s.settimeout(1)
            # Start a timer
            s_start = timer()
            # Try to Connect
            try:
                s.connect((Host, int(Port)))
                s.shutdown(socket.SHUT_RD)
                success = True
            # Connection Timed Out
            except socket.timeout:
                self.alertText.insert('insert', "Connection timed out!\n")
                self.alertText.update()
                self.alertText.see(END)
                self.pinglog("Connection timed out!\n")
                # print("Connection timed out!")
                self.failed += 1
            except OSError as e:
                # print("OS Error:", e)
                self.alertText.insert('insert', "OS Error:"+e.message+"\n")
                self.alertText.update()
                self.alertText.see(END)
                self.pinglog("OS Error:"+e.message+"\n")
                self.failed += 1

            # Stop Timer
            s_stop = timer()
            s_runtime = "%.2f" % (1000 * (s_stop - s_start))

            if success:
                self.alertText.insert('insert', "Connected to %s[%s]: tcp_seq=%s time=%s ms \n" % (Host, Port, (self.count-1), s_runtime))
                self.alertText.update()
                self.alertText.see(END)
                self.pinglog("Connected to %s[%s]: tcp_seq=%s time=%s ms" % (Host, Port, (self.count-1), s_runtime))
                # print("Connected to %s[%s]: tcp_seq=%s time=%s ms" % (self.host, self.port, (self.count-1), s_runtime))
                self.passed += 1

            # Sleep for 1sec
            if self.count < self.maxCount:
                time.sleep(1)

        # Output Results if maxCount reached
        self.getResults()
    ################################################
    def Tracert_one(self,dst,dport,ttl_no):#发一个Traceroute包，参数需要目的地址，目的端口，TTL。
        send_time = time.time()#记录发送时间
        Tracert_one_reply = sr1(IP(dst=dst, ttl=ttl_no)/UDP(dport=dport)/b'traceroute!!!', timeout = 1, verbose=False)
        try:
            if Tracert_one_reply.getlayer(ICMP).type == 11 and Tracert_one_reply.getlayer(ICMP).code == 0:
                #如果收到TTL超时
                hop_ip = Tracert_one_reply.getlayer(IP).src
                received_time = time.time()
                time_to_passed = (received_time - send_time) * 1000
                return 1, hop_ip, time_to_passed #返回1表示并未抵达目的地
            elif Tracert_one_reply.getlayer(ICMP).type == 3 and Tracert_one_reply.getlayer(ICMP).code == 3:
                #如果收到端口不可达
                hop_ip = Tracert_one_reply.getlayer(IP).src
                received_time = time.time()
                time_to_passed = (received_time - send_time) * 1000
                return 2, hop_ip, time_to_passed #返回2表示抵达目的地
        except Exception as e:
            if re.match('.*NoneType.*',str(e)):
                return None #测试失败返回None


    # Tracert(ip, int(hops))
    def Tracert(self):
        self.tracertlog("\n-----------------"+self.host+"-----------------\n")

        self.host = self.nameInput.get() or 'baidu.com'
        parseResult = parse.urlparse(self.host)
        Host = parseResult.netloc
        Port = 443 if (parseResult.scheme =="https") else 80
        for i in range(20):
            dport = 33434 #Traceroute的目的端口从33434开始计算
            hop = 0
            while hop < self.TmaxCount:
                dport = dport + hop
                hop += 1
                Result = self.Tracert_one(Host,dport,hop)
                if Result == None:#如果测试失败就打印‘*’
                    self.alertText2.insert('insert', str(Host)+ ': ' +str(hop) +' *'+"\n")
                    self.alertText2.update()
                    self.alertText2.see(END)
                    self.tracertlog(str(Host)+ ': ' +str(hop) +' *'+"\n")
                    # print(str(hop) + ' *',flush=True)
                elif Result[0] == 1:#如果未抵达目的，就打印这一跳和消耗的时间
                    time_to_pass_result = '%4.2f' % Result[2]
                    self.alertText2.insert('insert', str(Host)+ ': ' +str(hop) + ' ' + str(Result[1]) + ' ' + time_to_pass_result + 'ms'+"\n")
                    self.alertText2.update()
                    self.alertText2.see(END)
                    self.tracertlog(str(Host)+ ': ' +str(hop) + ' ' + str(Result[1]) + ' ' + time_to_pass_result + 'ms')
                    # print(str(hop) + ' ' + str(Result[1]) + ' ' + time_to_pass_result + 'ms')
                elif Result[0] == 2:#如果抵达目的，就打印这一跳和消耗的时间，并且跳出循环！
                    time_to_pass_result = '%4.2f' % Result[2]
                    self.alertText2.insert(str(Host)+ ': ' +str(hop) + ' ' + str(Result[1]) + ' ' + time_to_pass_result + 'ms'+"\n")
                    self.alertText2.update()
                    self.alertText2.see(END)
                    self.tracertlog(str(Host)+ ': ' +str(hop) + ' ' + str(Result[1]) + ' ' + time_to_pass_result + 'ms')
                    # print(str(hop) + ' ' + str(Result[1]) + ' ' + time_to_pass_result + 'ms')
                    continue
                # time.sleep(1)
            self.alertText2.insert('insert', "-----------------"+str(i+1)+"-----------------\n")
            self.alertText2.update()
            self.alertText2.see(END)
            self.tracertlog("-----------------"+str(i+1)+"-----------------\n")

    def curl_time(self):
        input_url = self.host
        # t = idctest()
        #gzip_test = file("gzip_test.txt", 'w')
        buffer = BytesIO() 
        c = pycurl.Curl()
        c.setopt(pycurl.WRITEDATA,buffer)
        c.setopt(pycurl.ENCODING, 'gzip')
        c.setopt(pycurl.URL,input_url)
        c.setopt(pycurl.MAXREDIRS, 5)
        c.setopt(pycurl.FOLLOWLOCATION, 1)
        c.setopt(pycurl.SSL_VERIFYPEER,0)
        c.perform()
    
        http_code = c.getinfo(pycurl.HTTP_CODE)
        http_size_download = c.getinfo(pycurl.SIZE_DOWNLOAD)
        http_header_size = c.getinfo(pycurl.HEADER_SIZE)
        http_speed_downlaod = c.getinfo(pycurl.SPEED_DOWNLOAD)

        total_time = c.getinfo(pycurl.TOTAL_TIME)  
        #传输结束所消耗的总时间  
        dns_time = c.getinfo(pycurl.NAMELOOKUP_TIME)  
        #从发起请求到DNS解析完成所消耗的时间  
        connect_time = c.getinfo(pycurl.CONNECT_TIME)  
        #从发起请求到建立连接所消耗的时间  
        redirect_time = c.getinfo(pycurl.REDIRECT_TIME)  
        #从发起请求到重定向所消耗的时间  
        ssl_time = c.getinfo(pycurl.APPCONNECT_TIME)      
        #从发起请求到SSL建立握手时间  
        pretrans_time = c.getinfo(pycurl.PRETRANSFER_TIME)  
        #从发起请求到准备传输所消耗的时间  
        starttrans_time = c.getinfo(pycurl.STARTTRANSFER_TIME)     
        #从发起请求到接收第一个字节的时间  
  
        print('发起请求到DNS解析时间 : %.3f ms' %(dns_time*1000))
        print('发起请求到TCP连接完成时间: %.3f ms' %(connect_time*1000))
        print('发起请求到跳转完成时间: %.3f ms' %(redirect_time*1000))  
        print('发起请求到SSL建立完成时间 : %.3f ms' %(ssl_time*1000))  
        print('发起请求到客户端发送请求时间： %.3f ms' %(pretrans_time*1000))  
        print('发起请求到客户端接受首包时间: %.3f ms' %(starttrans_time*1000))  
        # print('总时间为: %.3f ms' %(total_time*1000))  
        # print('')
  
        transfer_time = total_time - starttrans_time  
        #传输时间  
        serverreq_time = starttrans_time - pretrans_time  
        #服务器响应时间，包括网络传输时间  
        if ssl_time == 0 :  
            if redirect_time == 0 :  
                clientper_time = pretrans_time - connect_time  
                #客户端准备发送数据时间  
                redirect_time = 0  
            else :  
                clientper_time = pretrans_time - redirect_time  
                redirect_time = redirect_time - connect_time  
            ssl_time = 0  
        else :  
            clientper_time = pretrans_time - ssl_time  
            
            if redirect_time == 0 :  
                ssl_time = ssl_time - connect_time  
                redirect_time = 0  
            else :  
                ssl_time = ssl_time - connect_time
                redirect_time = redirect_time - connect_time  
        
        connect_time = connect_time - dns_time  
        
        # print('发起请求到DNS解析时间 : %.3f ms' %(dns_time*1000))
        self.alertText3.insert('insert',"\r\n"+'发起请求到DNS解析时间 : %.3f ms' %(dns_time*1000))
        self.alertText3.insert('insert',"\r\n"+'TCP连接消耗时间 : %.3f ms' %(connect_time*1000))  
        self.alertText3.insert('insert',"\r\n"+'跳转消耗时间: %.3f ms' %(redirect_time*1000))  
        self.alertText3.insert('insert',"\r\n"+'SSL握手消耗时间 : %.3f ms' %(ssl_time*1000))  
        self.alertText3.insert('insert',"\r\n"+'客户端发送请求准备时间: %.3f ms' %(clientper_time*1000))  
        self.alertText3.insert('insert',"\r\n"+'服务器处理时间: %.3f ms' %(serverreq_time*1000))  
        self.alertText3.insert('insert',"\r\n"+'数据传输时间: %.3f ms' %(transfer_time*1000)) 
        self.alertText3.insert('insert',"\r\n"+'HTTP响应状态： %d' %http_code)
        self.alertText3.insert('insert',"\r\n"+"下载数据包大小： %d bytes/s" %http_size_download)
        self.alertText3.insert('insert',"\r\n"+"HTTP头大小： %d bytes/s" %http_header_size)
        self.alertText3.insert('insert',"\r\n"+"平均下载速度： %d k/s" %(http_speed_downlaod/1024))
        self.alertText3.insert('insert',"\r\n"+'总时间为: %.3f ms' %(total_time*1000))
        
        self.alertText3.update()
        self.alertText3.see(END)
        self.curllog('\n发起请求到DNS解析时间 : %.3f ms' %(dns_time*1000))
        self.curllog('\nTCP连接消耗时间 : %.3f ms' %(connect_time*1000))
        self.curllog('\n跳转消耗时间: %.3f ms' %(redirect_time*1000))
        self.curllog('\nSSL握手消耗时间 : %.3f ms' %(ssl_time*1000))
        self.curllog('\n客户端发送请求准备时间: %.3f ms' %(clientper_time*1000)) 
        self.curllog('\n服务器处理时间: %.3f ms' %(serverreq_time*1000))  
        self.curllog('\n数据传输时间: %.3f ms' %(transfer_time*1000)) 
        self.curllog('\nHTTP响应状态： %d' %http_code)
        self.curllog("\n下载数据包大小： %d bytes/s" %http_size_download)
        self.curllog("\nHTTP头大小： %d bytes/s" %http_header_size)
        self.curllog("\n平均下载速度： %d k/s" %(http_speed_downlaod/1024))
        self.curllog('\n总时间为: %.3f ms' %(total_time*1000))

    def ct(self):
        for x in range(100):
            self.alertText3.insert('insert',"\r\n"+'---------'+str(x+1)+'---------'+"\r\n")
            self.alertText3.update()
            self.alertText3.see(END)
            self.curllog("\r\n"+'---------'+str(x+1)+'---------'+"\r\n")
            self.curl_time()
            time.sleep(1)



def is_admin():
    if sys.platform == 'win32':
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False
    return True

if __name__ == "__main__":
    
    # print(sys.platform)
    if is_admin():
        app = Application()
        # 设置窗口标题:
        app.master.title('Net Check Tool')
        app.master.geometry('800x500')  # 这里的乘是小x
        signal.signal(signal.SIGINT, app.signal_handler)
        # 主消息循环:
        app.mainloop()
    else:
        if sys.version_info[0] == 3:
            ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, __file__, None, 1)
        else:#in python2.x
            ctypes.windll.shell32.ShellExecuteW(None, u"runas", unicode(sys.executable), unicode(__file__), None, 1)
