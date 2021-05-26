import log, sim, uos, dataCall, ujson, request, usocket, net, log, modem, utime, _thread, uhashlib, ubinascii, fota, ure
import cellLocator
from machine import Pin
from misc import Power
from aLiYun import aLiYun
from TenCentYun import TXyun
from umqtt import MQTTClient
from machine import UART

log.basicConfig(level=log.INFO)
logger = log.getLogger("dtu")


# ota 升级优化
# 新增系统日志上报功能
class RET:
    OK = "20000"
    HTTP_OK = "20001"
    MQTT_OK = "20002"
    SOCKET_TCP_OK = "20003"
    SOCKET_UDP_OK = "20004"
    Aliyun_OK = "20005"
    TXyun_OK = "20006"
    # 系统组件错误
    SIMERR = "3001"
    DIALINGERR = "3002"
    # 网络协议错误
    HTTPERR = "4001"
    REQERR = "4002"
    TCPERR = "4003"
    UDPERR = "4004"
    MQTTERR = "4005"
    ALIYUNMQTTERR = "4006"
    TXYUNMQTTERR = "4007"
    PROTOCOLERR = "4008"
    REQERR1 = "4009"
    REQERR2 = "5000"
    # 功能错误
    PASSWORDERR = "5001"
    PASSWDVERIFYERR = "5002"
    HTTPCHANNELPARSEERR = "5003"
    CHANNELERR = "5004"
    DATATYPEERR = "5005"
    METHODERR = "5006"
    DATASENDERR = "5007"
    IOTTYPERR = "5008"
    NUMBERERR = "5009"
    # 解析错误
    JSONLOADERR = "6001"
    JSONPARSEERR = "6002"
    PARSEERR = "6003"
    DATAPARSEERR = "6004"
    POINTERR = "6005"
    READFILEERR = "6006"
    CONFIGNOTEXIST = "6007"


error_map = {
    RET.OK: u"成功",
    RET.HTTP_OK: u"http连接成功",
    RET.MQTT_OK: u"mqtt连接成功",
    RET.SOCKET_TCP_OK: u"tcp连接成功",
    RET.SOCKET_UDP_OK: u"udp连接成功",
    RET.Aliyun_OK: u"阿里云连接成功",
    RET.TXyun_OK: u"腾讯云成功",
    # 系统
    RET.SIMERR: u"读取sim卡错误",
    RET.DIALINGERR: u"拨号错误",
    # 协议
    RET.HTTPERR: u"http请求失败",
    RET.REQERR: u"http请求状态500",
    RET.REQERR1: u"http请求状态302",
    RET.REQERR2: u"http请求状态404",
    RET.TCPERR: u"tcp连接失败",
    RET.UDPERR: u"udp连接失败",
    RET.MQTTERR: u"mqtt连接失败",
    RET.ALIYUNMQTTERR: u"aliyun连接失败",
    RET.TXYUNMQTTERR: u"txyun连接失败",
    RET.PROTOCOLERR: u"协议解析错误",
    # 功能错误
    RET.PASSWORDERR: u"密码未携带",
    RET.PASSWDVERIFYERR: u"密码校验错误",
    RET.HTTPCHANNELPARSEERR: u"http参数错误",
    RET.CHANNELERR: u"通道透传错误",
    RET.DATATYPEERR: u"数据类型错误",
    RET.METHODERR: u"请求方法错误",
    RET.DATASENDERR: u"数据透传失败",
    RET.IOTTYPERR: u"mqtt类型不匹配",
    RET.NUMBERERR: u"参数数量不符合",
    # 数据错误
    RET.JSONLOADERR: "json加载失败",
    RET.JSONPARSEERR: "json解析失败",
    RET.PARSEERR: "序列化解析失败",
    RET.DATAPARSEERR: "数据解析错误",
    RET.POINTERR: "指令错误",
    RET.READFILEERR: "读取文件不存在",
}

CONFIG = {
    "config_path": "usr/dtu_config.json"
}

HISTORY_ERROR = []

"""=================================================  singleton  ===================================================="""

dev_imei = modem.getDevImei()


def Singleton(cls):
    _instance = {}

    def _singleton(*args, **kargs):
        if cls not in _instance:
            _instance[cls] = cls(*args, **kargs)
        return _instance[cls]

    return _singleton


class DTUException(Exception):
    def __init__(self, message):
        self.message = message


"""=================================================== dtu object ==================================================="""


@Singleton
class ProdDtu(object):

    def __init__(self, dtu_gpio, uart):
        self.gpio = dtu_gpio
        self.uart = uart
        self.parse_data = DTUDocumentData()
        self.document_parser = ProdDocumentParse()
        self.channel = ChannelTransfer()

    def prepare(self):
        while True:
            if not sim.getStatus():
                if not self.gpio.status():
                    self.gpio.show()
                utime.sleep(1)
            else:
                break

    def dialing(self):
        config_path = CONFIG["config_path"]
        config_params = ProdDocumentParse().refresh_document(config_path)
        apn = ujson.loads(config_params)["apn"]
        print("apn: ", apn)
        if apn[0] != "" and apn[1] != "" and apn[2] != "":
            while True:
                res = dataCall.setApn(1, 0, apn[0], apn[1], apn[2], 0)
                if res == 0:
                    print("APN datacall successful")
                    break
                if res == -1:
                    print("Try APN datacall...")
        else:
            while True:
                res = dataCall.start(1, 0, "3gnet.mnc001.mcc460.gprs", "", "", 0)
                if res == 0:
                    print("datacall successful")
                    break
                if res == -1:
                    print("Try datacall...")
        count = 0
        max_count = 10
        while count < max_count:
            if not dataCall.getInfo(1, 0)[2][0]:
                utime.sleep(1)
                if not self.gpio.status():
                    self.gpio.show()
                utime.sleep(1)
            else:
                break

    def parse(self):
        self.document_parser.parse(self.parse_data)

    def request(self):
        config_path = CONFIG["config_path"]
        config_params = ProdDocumentParse().refresh_document(config_path)
        try:
            ota = ujson.loads(config_params)["ota"]
        except Exception as e:
            return
        print("ota: ", ota)
        if ota[0] == "" or ota[1] == "" or ota[2] == "":
            if ota[0] == "":
                logger.info("no uid params")
            if ota[1] == "":
                logger.info("no module_type params")
            if ota[2] == "":
                logger.info("no pk params")
            print("close ota update")
            return
        # 脚本升级
        do_fota = self.parse_data.fota
        if do_fota == 1:
            if "apn_cfg.json" in uos.listdir():  # 旧版本固件
                usr = ""
            else:  # 新固件
                usr = "usr/"
            global url_zip, targetVersion, fileMD5, action, filesize
            # 获取access token
            url = "http://220.180.239.212:8274/v1/oauth/token"
            imei = dev_imei
            secret = ubinascii.hexlify(uhashlib.md5("QUEC" + str(imei) + "TEL").digest())
            secret = secret.decode()
            # print(url + "?imei=" + imei + "&" + "secret=" + secret)
            resp = request.get(url + "?imei=" + imei + "&" + "secret=" + secret)
            if resp.status_code != 200:
                logger.info("***********acquire token failed!***********")
                return
            data = ""
            for i in resp.content:
                data += i.decode()
            json_data = ujson.loads(data)
            access_token = json_data["data"]["access_Token"]
            print("access_token:", access_token)
            # 升级包下载地址的请求
            version = self.parse_data.version
            moduleType = ota[1]
            download_url = "http://220.180.239.212:8274/v2/fota/fw"
            headers = {"access_token": access_token, "Content-Type": "application/json"}
            acquire_data = {
                "version": str(version),
                "imei": imei,
                "moduleType": moduleType,
                "battery": 100,
                "rsrp": net.csqQueryPoll(),
                "uid": ota[0],
                "pk": ota[2]
            }
            resp = request.post(download_url, data=ujson.dumps(acquire_data), headers=headers)
            json_data = ""
            for i in resp.content:
                json_data += i.decode()
            json_data = ujson.loads(json_data)
            if json_data["code"] == 200:
                targetVersion = json_data["targetVersion"]
                url_zip = json_data["url"]
                fileMD5 = json_data["fileMd5"]
                action = json_data["action"]
                filesize = json_data["config"]["fileSize"]
                print("fileSize: ", filesize)
                print("targetVersion: ", targetVersion)
            else:
                action = json_data["action"]
                msg = json_data["msg"]
                code = json_data["code"]
                logger.info(msg)

            if action:
                report_url = "http://220.180.239.212:8274/v1/fota/status/report"
                print("Please do not send instructions during the upgrade...")
                resp = request.get(url_zip)
                update_file = "dtu_handler_{}.py".format(targetVersion)
                f = open(usr + update_file, "wb+")
                count = 0
                for i in resp.content:
                    count += len(i)
                    f.write(i)
                    utime.sleep_ms(5)
                f.close()
                if filesize != count:
                    logger.info("Failed to download package data validation")
                    uos.remove(usr + "dtu_handler_V1.0.1.py")
                    #  模组状态及结果上报 升级失败，信息上报
                    data = self.data_info(version, imei, 8, "Update Failed")
                    request.post(report_url, data=ujson.dumps(data), headers=headers)
                    return
                #  模组状态及结果上报 升级成功，信息上报
                data = self.data_info(version, imei, 7, "upgrade success")
                resp = request.post(report_url, data=ujson.dumps(data), headers=headers)
                if resp.status_code == 200:
                    logger.info("The upgrade is completed and the information is reported successfully")
                else:
                    logger.info("Upgrade status information failed to be reported")
            ##################################################################################
            # 模组临终遗言信息上报
            if "system.log" not in uos.listdir(usr):
                logger.info("**********'system.log' not exist***********")
                logger.info("*********last will was not reported********")
                return
            with open(usr + "system.log", "r") as f:
                msg = f.read()
            Last_will_url = "http://220.180.239.212:8274/v1/fota/msg/report"
            res = cellLocator.getLocation("www.queclocator.com", 80, "1111111122222222", 8, 1)
            data = {
                "imei": imei,
                "version": str(version),
                "signalStrength": net.csqQueryPoll(),
                "battery": 100,
                "latitude": res[0],
                "longitude": res[1],
                "details": "last will message report",
                "reportMsg": msg
            }
            headers = {"Content-Type": "application/json"}
            resp = request.post(Last_will_url, data=ujson.dumps(data), headers=headers)
            if resp.status_code == 200:
                logger.info("last will reported successfully")
            else:
                logger.info("last will was reported failed")
                return

    def data_info(self, version, imei, code, msg):
        data = {
            "version": version,
            "ver": "v1.0",
            "imei": imei,
            "code": code,
            "msg": msg
        }
        return data

    def start(self):
        channel_number = 0
        logger.info("parse data {}".format(self.parse_data.conf))
        reg_data = {"csq": net.csqQueryPoll(), "imei": dev_imei, "iccid": sim.getIccid(),
                    "ver": self.parse_data.version}  # 首次登陆服务器默认注册信息
        for data in self.parse_data.conf:
            channel_number += 1
            code = 0x40 + channel_number
            if not data:
                continue
            protocol = data[0].lower()
            if protocol == "mqtt":
                dtu_mq = DtuMqttTransfer(code)
                status = dtu_mq.serialize(data[1:])
                try:
                    dtu_mq.connect()
                    _thread.start_new_thread(dtu_mq.wait, ())
                except Exception as e:
                    # logger.error(e)
                    self.uart.output(success=0, status=RET.MQTTERR, code=code)
                else:
                    if status == RET.OK:
                        self.channel.channel_dict[code] = dtu_mq
                    else:
                        self.uart.output(success=0, status=status, code=code)

            elif protocol == "aliyun":
                dtu_ali = ALYDtuMqttTransfer(code)
                status = dtu_ali.serialize(data[1:])
                try:
                    _thread.start_new_thread(dtu_ali.connect, ())
                    utime.sleep_ms(100)
                except Exception as e:
                    logger.error(e)
                    self.uart.output(success=0, status=RET.ALIYUNMQTTERR, code=code)
                else:
                    if status == RET.OK:
                        self.channel.channel_dict[code] = dtu_ali
                    else:
                        self.uart.output(success=0, status=status, code=code)

            elif protocol == "txyun":
                dtu_txy = TXYDtuMqttTransfer(code)
                status = dtu_txy.serialize(data[1:])
                try:
                    _thread.start_new_thread(dtu_txy.connect, ())
                    utime.sleep_ms(100)
                except Exception as e:
                    logger.error(e)
                    self.uart.output(success=0, status=RET.TXYUNMQTTERR, code=code)
                else:
                    if status == RET.OK:
                        self.channel.channel_dict[code] = dtu_txy
                    else:
                        self.uart.output(success=0, status=status, code=code)

            elif protocol == "tcp":
                tcp_sock = TcpSocket(code)
                status = tcp_sock.serialize(data[1:])
                try:
                    tcp_sock.connect()
                    _thread.start_new_thread(tcp_sock.recv, ())
                except Exception as e:
                    logger.error(e)
                    self.uart.output(success=0, status=RET.TCPERR, code=code)
                else:
                    if status == RET.OK:
                        if self.parse_data.reg == 1:
                            tcp_sock.first_reg(reg_data)
                            logger.info("TCP send first login information {}".format(reg_data))
                        if data[1] != "" or data[1] != " ":
                            if int(data[2]) != 0:
                                _thread.start_new_thread(tcp_sock.Heartbeat, ())
                        self.channel.channel_dict[code] = tcp_sock
                    else:
                        self.uart.output(success=0, status=status, code=code)

            elif protocol == "udp":
                udp_sock = UdpSocket(code)
                status = udp_sock.serialize(data[1:])
                try:
                    udp_sock.connect()
                    _thread.start_new_thread(udp_sock.recv, ())
                except Exception as e:
                    logger.error(e)
                    self.uart.output(success=0, status=RET.UDPERR, code=code)
                else:
                    if status == RET.OK:
                        if self.parse_data.reg == 1:
                            udp_sock.first_reg(reg_data)
                            logger.info("UDP send first login information {}".format(reg_data))
                        if data[1] != "" or data[1] != " ":
                            if int(data[2]) != 0:
                                _thread.start_new_thread(udp_sock.Heartbeat, ())
                        self.channel.channel_dict[code] = udp_sock
                    else:
                        self.uart.output(success=0, status=status, code=code)

            elif protocol.startswith("http"):
                dtu_req = DtuRequest(code)
                status = dtu_req.serialize(data[1:])
                if status == RET.OK:
                    data = dtu_req.req()  # 发送请求
                    print("***********************http request***********************")
                    for i in data:
                        print(i)
                    self.channel.channel_dict[code] = dtu_req
                else:
                    self.uart.output(success=0, status=status, code=code)
            else:
                continue
        _thread.start_new_thread(self.uart.read, ())


class ProdGPIO(object):
    def __init__(self):
        # self.gpio1 = Pin(Pin.GPIO1, Pin.OUT, Pin.PULL_DISABLE, 0)
        set_gpio = False
        config_path = CONFIG["config_path"]
        config_params = ProdDocumentParse().refresh_document(config_path)
        pins = ujson.loads(config_params)["pins"]
        print("pin: ", pins)
        for i in pins:
            if len(i):
                gpio = int(ure.sub("\D", "", i))
                print("gpio {} set".format(gpio))
                if gpio == 1:
                    self.gpio1 = Pin(Pin.GPIO1, Pin.OUT, Pin.PULL_DISABLE, 0)
                    set_gpio = True
                if gpio == 2:
                    self.gpio2 = Pin(Pin.GPIO2, Pin.OUT, Pin.PULL_DISABLE, 0)
                if gpio == 3:
                    self.gpio3 = Pin(Pin.GPIO3, Pin.OUT, Pin.PULL_DISABLE, 0)
                if gpio == 4:
                    self.gpio4 = Pin(Pin.GPIO4, Pin.OUT, Pin.PULL_DISABLE, 0)
                if gpio == 5:
                    self.gpio5 = Pin(Pin.GPIO5, Pin.OUT, Pin.PULL_DISABLE, 0)
                if gpio == 6:
                    self.gpio5 = Pin(Pin.GPIO6, Pin.OUT, Pin.PULL_DISABLE, 0)
                if gpio == 7:
                    self.gpio5 = Pin(Pin.GPIO7, Pin.OUT, Pin.PULL_DISABLE, 0)
                if gpio == 8:
                    self.gpio5 = Pin(Pin.GPIO8, Pin.OUT, Pin.PULL_DISABLE, 0)
                if gpio == 9:
                    self.gpio5 = Pin(Pin.GPIO9, Pin.OUT, Pin.PULL_DISABLE, 0)
                if gpio == 10:
                    self.gpio5 = Pin(Pin.GPIO10, Pin.OUT, Pin.PULL_DISABLE, 0)
                if gpio == 11:
                    self.gpio5 = Pin(Pin.GPIO11, Pin.OUT, Pin.PULL_DISABLE, 0)
                if gpio == 12:
                    self.gpio5 = Pin(Pin.GPIO12, Pin.OUT, Pin.PULL_DISABLE, 0)
                if gpio == 13:
                    self.gpio5 = Pin(Pin.GPIO13, Pin.OUT, Pin.PULL_DISABLE, 0)
                if gpio == 14:
                    self.gpio5 = Pin(Pin.GPIO14, Pin.OUT, Pin.PULL_DISABLE, 0)
                if gpio == 15:
                    self.gpio5 = Pin(Pin.GPIO15, Pin.OUT, Pin.PULL_DISABLE, 0)
                if gpio == 16:
                    self.gpio5 = Pin(Pin.GPIO16, Pin.OUT, Pin.PULL_DISABLE, 0)
                if gpio == 17:
                    self.gpio5 = Pin(Pin.GPIO17, Pin.OUT, Pin.PULL_DISABLE, 0)
                if gpio == 18:
                    self.gpio5 = Pin(Pin.GPIO18, Pin.OUT, Pin.PULL_DISABLE, 0)
                if gpio == 19:
                    self.gpio5 = Pin(Pin.GPIO19, Pin.OUT, Pin.PULL_DISABLE, 0)
        if not set_gpio:
            self.gpio1 = Pin(Pin.GPIO1, Pin.OUT, Pin.PULL_DISABLE, 0)

    def status(self):
        self.gpio1.read()

    def show(self):
        self.gpio1.write(1)


class ProdDocumentParse(object):

    def __init__(self):
        self.document = ""

    def read(self, config_path):
        if not self.document:
            self.refresh_document(config_path)

    def refresh_document(self, config_path):
        try:
            with open(config_path, mode="r") as f:
                self.document = f.read()
            return self.document  # new
        except Exception as e:
            logger.info("'dtu_config.json' not exist")
            raise Exception(RET.READFILEERR)

    def _parse_document(self, parser_obj):
        try:
            document_loader = ujson.loads(self.document)
        except Exception as e:
            DtuUart().output(0xfc, status=RET.JSONLOADERR, success=0)
            raise RET.JSONLOADERR
        try:
            dtu_data_obj = parser_obj.reload(**document_loader)
        except Exception as e:
            logger.info("e = {}".format(e))
            DtuUart().output(0xfc, status=RET.JSONPARSEERR, success=0)
            raise RET.JSONPARSEERR
        return dtu_data_obj

    def parse(self, parser_obj):
        config_path = CONFIG["config_path"]
        if not self.exist_config_file(config_path):
            # 从uart口读取数据
            DtuUart().output(0xfc, status=RET.CONFIGNOTEXIST, success=0)
        else:
            self.read(config_path=config_path)
            return self._parse_document(parser_obj=parser_obj)

    @staticmethod
    def exist_config_file(config_path):
        config_split = config_path.rsplit("/", 1)
        return config_split[1] in uos.listdir(config_split[0])


"""===================================================socket protocol==================================================="""


class DtuRequest(object):
    _data_methods = ("PUT", "POST")

    def __init__(self, code):
        self.code = code
        self.url = ""
        self.port = ""
        self.method = ""
        self.data = ""
        self.serial = 0

    def serialize(self, data):
        try:
            self.method = data[0]
            self.url = data[1]
            self.data = data[2]
            self.timeout = int(data[3])
            self.serial = int(data[4])
        except Exception as e:
            return RET.HTTPCHANNELPARSEERR
        else:
            # return DtuUart().output(self.code, status=RET.OK, success=0)
            return RET.OK

    # http发送的数据为json类型
    def send(self, data):
        print("send data:", data)
        try:
            method = data["method"]
            send_data = data["send_data"]
        except Exception as e:
            DtuUart().output(self.code, status=RET.DATAPARSEERR, success=0)
        else:
            if method.upper() in ["GET", "POST", "PUT", "DELETE", "HEAD"]:
                if isinstance(send_data, dict):
                    self.data = send_data
                    self.method = method
                    resp_content = self.req()
                    for i in resp_content:
                        print(i)
                else:
                    DtuUart().output(self.code, status=RET.DATATYPEERR, success=0)
            else:
                DtuUart().output(self.code, status=RET.METHODERR, success=0)

    def req(self):
        global resp
        uri = self.url
        if self.port:
            uri += self.port
        try:
            if self.method.upper() in self._data_methods:
                if self.method == "post":
                    resp = request.post(uri, data=ujson.dumps(self.data))
                # resp = getattr(request, self.method)(uri, self.data)
            else:
                resp = request.get(uri)
                # resp = getattr(request, self.method)(uri)
        except Exception as e:
            # logger.info(e)
            DtuUart().output(self.code, status=RET.HTTPERR, success=0)
            return RET.HTTPERR
        else:
            if resp.status_code == 302:
                DtuUart().output(self.code, status=RET.REQERR1, success=0)
            if resp.status_code == 404:
                DtuUart().output(self.code, status=RET.REQERR2, success=0)
            if resp.status_code == 500:
                DtuUart().output(self.code, status=RET.REQERR, success=0)
            if resp.status_code == 200:
                DtuUart().output(self.code, status="200", success=1)
            return resp.content


class DtuSocket(object):
    def __init__(self):
        self.cli = None
        self.url = ""
        self.port = ""
        self.keep_alive = 300
        self.ping = ""
        self.heart = 60
        self.serial = 0
        self.code = 0x00

    def connect(self):
        sock_addr = usocket.getaddrinfo(self.url, int(self.port))[0][-1]
        logger.info("sock_addr = {}".format(sock_addr))
        self.cli.connect(sock_addr)

    def send(self, data):
        try:
            send_data = data["send_data"]
        except Exception as e:
            DtuUart().output(self.code, status=RET.DATAPARSEERR, success=0)
        else:
            if isinstance(send_data, str):
                self.data = send_data
                self.cli.send(self.data)
            else:
                DtuUart().output(self.code, status=RET.DATATYPEERR, success=0)

    def recv(self):
        while True:
            try:
                data = self.cli.recv(1024)
            except Exception as e:
                print(e)
                utime.sleep_ms(50)
                continue
            else:
                if data != b'':
                    DtuUart().output(self.code, data.decode())
                else:
                    utime.sleep_ms(50)
                    continue

    def Heartbeat(self):  # 发送心跳包
        while True:
            logger.info("send heartbeats")
            try:
                self.cli.send(self.ping.encode("utf-8"))
                logger.info("Send a heartbeat: {}".format(self.ping))
            except Exception as e:
                logger.info('send heartbeat failed !')
            print("heart time", self.heart)
            utime.sleep(self.heart)

    def first_reg(self, reg_data):  # 发送注册信息
        try:
            self.cli.send(str(reg_data).encode("utf-8"))
            # logger.info("Send first login information {}".format(reg_data))
        except Exception as e:
            logger.info('send first login information failed !{}'.format(e))

    def disconnect(self):
        self.cli.close()

    def serialize(self, data):
        try:
            self.ping = data[0] if data[4] else "123"
            self.heart = int(data[1])
            self.url = data[2]
            self.port = int(data[3])
            self.keep_alive = int(data[4]) if data[4] else 300
            self.serial = int(data[5])
        except Exception as e:
            return RET.PARSEERR
        else:
            return RET.OK


class TcpSocket(DtuSocket):

    def __init__(self, code):
        super(TcpSocket, self).__init__()
        self.cli = usocket.socket(usocket.AF_INET, usocket.SOCK_STREAM)
        self.cli.settimeout(self.keep_alive)  # 链接超时最大时间

    def out_put(self, content):
        DtuUart().output(self.code, content=content)


class UdpSocket(DtuSocket):

    def __init__(self, code):
        super(UdpSocket, self).__init__()
        self.cli = usocket.socket(usocket.AF_INET, usocket.SOCK_DGRAM)
        self.cli.settimeout(self.keep_alive)

    def out_put(self, content):
        DtuUart().output(self.code, content=content)


class AbstractDtuMqttTransfer(object):

    def __init__(self):
        self.cli = None
        self.sub_topic = ""
        self.pub_topic = ""
        self.keep_alive = 300
        self.clean_session = 0
        self.code = 0x00
        self.client_id = ""
        self.url = ""
        self.port = ""
        self.qos = 0
        self.retain = 0
        self.serial = 0
        self.product_key = ""
        self.product_secret = ""
        self.device_name = ""
        self.device_secret = ""

    def connect(self):
        self.cli.connect()

    def subscribe(self):
        self.cli.subscribe(self.sub_topic)

    def publish(self, msg):
        self.cli.publish(self.pub_topic, msg)

    def send(self, data):
        try:
            send_data = data["send_data"]
            print("send data:", send_data)
        except Exception as e:
            DtuUart().output(self.code, status=RET.DATAPARSEERR, success=0)
        else:
            if isinstance(send_data, str):
                self.publish(send_data)
            else:
                DtuUart().output(self.code, status=RET.DATATYPEERR, success=0)

    def callback(self, topic, msg):
        if topic.decode() == self.sub_topic:
            print('CallBack Msg >>>> ', topic, msg.decode())
            DtuUart().output(self.code, msg.decode())

    def disconnect(self):
        self.cli.disconnect()

    def serialize(self, data):
        try:
            if data[0] not in ("tas", "mos"):
                return RET.IOTTYPERR
            self.iot_type = data[0]
            self.keep_alive = int(data[1]) if data[1] else 300
            self.client_id = data[2]
            self.device_name = data[3]
            self.product_key = data[4]
            self.device_secret = data[5] if data[5] else None
            self.product_secret = data[6] if data[6] else None
            self.clean_session = int(data[7]) if data[7] else 0
            self.qos = int(data[8]) if data[8] else 0
            self.sub_topic = data[9]
            self.pub_topic = data[10]
            self.serial = int(data[11])
        except Exception as e:
            return RET.PARSEERR
        else:
            return RET.OK


class DtuMqttTransfer(AbstractDtuMqttTransfer):
    def __init__(self, code):
        super().__init__()
        self.code = code

    def connect(self):
        self.cli = MQTTClient(self.client_id, self.url, self.port, keepalive=self.keep_alive, ssl=False,
                              ssl_params={})
        self.cli.set_callback(self.callback)
        self.cli.connect(clean_session=self.clean_session)
        self.cli.subscribe(self.sub_topic, qos=self.qos)
        self.cli.publish(self.pub_topic, "hello world", qos=self.qos)
        logger.info("mqtt set successful")
        # super(DtuMqttTransfer, self).connect()

    def wait(self):
        while True:
            self.cli.wait_msg()

    def serialize(self, data):
        try:
            self.client_id = data[0]
            self.keep_alive = int(data[1]) if data[1] else 60
            self.url = data[2]
            self.port = int(data[3])
            self.clean_session = int(data[4]) if data[4] else 0
            self.sub_topic = data[5]
            self.pub_topic = data[6]
            self.qos = int(data[7]) if data[7] else 0
            self.retain = int(data[8]) if data[8] else 0
            self.serial = int(data[9])
        except Exception as e:
            return RET.PARSEERR
        else:
            return RET.OK


class ALYDtuMqttTransfer(AbstractDtuMqttTransfer):

    def __init__(self, code):
        super().__init__()
        self.code = code

    def connect(self):
        if not self.device_secret:  # 一型一密
            if "secret.json" not in uos.listdir("usr"):
                logger.info("'secret.json' not exist")
                with open("usr/secret.json", "w") as f:
                    pass
                return
        self.cli = aLiYun(self.product_key, self.product_secret, self.device_name, self.device_secret)
        con_state = self.cli.setMqtt(self.client_id, clean_session=self.clean_session, keepAlive=self.keep_alive)
        if con_state == 0:
            if not self.device_secret:
                logger.info("Aliyun tas set successful")
            if not self.product_secret:
                logger.info("Aliyun mos set successful")
        if con_state == -1:
            if not self.device_secret:
                logger.info("Aliyun tas set failed")
                return
            if not self.product_secret:
                logger.info("Aliyun mos set failed")
                return
        self.cli.setCallback(self.callback)
        self.cli.subscribe(self.sub_topic, qos=self.qos)
        self.cli.publish(self.pub_topic, "hello world", qos=self.qos)
        self.cli.start()


class TXYDtuMqttTransfer(AbstractDtuMqttTransfer):

    def __init__(self, code):
        super().__init__()
        self.code = code

    def connect(self):
        if not self.device_secret:  # 一型一密
            if "tx_secret.json" not in uos.listdir("usr"):
                logger.info("'tx_secret.json' file not exist")
                logger.info("txyun tas set failed")
                return
        self.cli = TXyun(self.product_key, self.device_name, self.device_secret, self.product_secret)
        con_state = self.cli.setMqtt(clean_session=self.clean_session, keepAlive=self.keep_alive)
        if con_state == 0:
            if not self.device_secret:
                logger.info("txyun tas set successful")
            if not self.product_secret:
                logger.info("txyun mos set successful")
        if con_state == -1:
            if not self.device_secret:
                logger.info("txyun tas set failed")
                return
            if not self.product_secret:
                logger.info("txyun mos set failed")
                return
        self.cli.setCallback(self.callback)
        self.cli.subscribe(self.sub_topic, qos=self.qos)  # 订阅主题
        self.cli.publish(self.pub_topic, "hello world", qos=self.qos)  # 发布主题
        self.cli.start()


"""===================================================data document protocol==================================================="""


@Singleton
class DTUDocumentData(object):

    def __init__(self):
        self.fota = 1
        self.nolog = 1
        self.plate = 1
        self.reg = 1
        self.convert = 0
        self.service_acquire = 1
        self.version = ""
        self.password = ""
        self.message = {}
        self.uconf = list()
        self.conf = list()
        self.pins = list()
        self.apn = list()
        self.pins = list()

    def json_info(self, need=True):
        data_info = dict()
        for key in self.__dict__.keys():
            data_info[key] = getattr(self, key)
        if need:
            return ujson.dumps(data_info)
        else:
            return data_info

    def reload_file(self):
        try:
            with open(CONFIG["config_path"], mode="w") as f:
                f.write(self.json_info())
        except Exception as e:
            logger.info("*****'dtu_config.json' not exist*****")
            return

    def reload(self, **kwargs):
        for key in self.__dict__.keys():
            if key in kwargs:
                setattr(self, key, kwargs[key])
            else:
                setattr(self, key, type(getattr(self, key))())


class DtuProtocolData(object):
    frame_head = b'\x6a\x6a\x6a'
    frame_tail = b'\x6f\x6f\x6f'
    frame_content = b''
    supply_size = 0

    def __init__(self, func_code, content, data_length=0x00, check_sum_number=0x00):
        self.func_code = func_code
        self.data_length = data_length
        self.content = content
        self.check_sum_number = check_sum_number

    def send(self):
        return self.transfer_str_to_hex()

    @classmethod
    def transfer_hex_to_data_obj(cls, data):
        supply_size = DtuProtocolData.supply_size
        if not supply_size:
            # 数据合法
            DtuProtocolData.frame_content = data
            DtuProtocolData.supply_size = 0
        else:
            # 数据不合法
            if len(data) < supply_size:
                DtuProtocolData.frame_content += data
                DtuProtocolData.supply_size = DtuProtocolData.supply_size - len(data)
                return
            elif len(data) > supply_size:
                DtuProtocolData.frame_content += data[:supply_size]
            else:
                DtuProtocolData.frame_content += data
            DtuProtocolData.supply_size = 0

        data = DtuProtocolData.frame_content

        if data[:3] == cls.frame_head:
            if data[-3:] == cls.frame_tail:
                # 内容列表
                cls.content_parser(data)
            else:
                data_length = data[4] * 256 + data[5]
                DtuProtocolData.supply_size = data_length + 7 - len(data)
                print("data length read supply size = {}".format(data_length))
        else:
            DtuUart().output(0x70, status=RET.PROTOCOLERR, success=0)

    @classmethod
    def content_parser(cls, data):
        content = data[3:-3]
        if cls.check_sum(content[:-1]) == content[-1]:
            data_length = content[1] * 256 + content[2]
            # 功能码
            func_code = content[0]
            # 数据内容
            data_content = ""
            for i in content[3:data_length]:
                data_content += chr(i)
            # 包装数据对象处理
            dtu_obj = DtuProtocolData(func_code, data_content, data_length=data_length,
                                      check_sum_number=content[-1])
            DtuProtocolData.frame_content = b''
            DtuProtocolData.supply_size = 0
            DtuExecCommand().exec_command(dtu_obj)
        else:
            # 校验和不通过
            print("Checksum failed not allowed")
            # 内容
        DtuProtocolData.frame_content = b''
        DtuProtocolData.supply_size = 0

    def transfer_str_to_hex(self):
        data_list = list(map(ord, self.content))
        data_length = len(data_list) + 3
        # 两个字节数据长度
        data_list.insert(0, data_length // 256)
        data_list.insert(1, data_length % 256)
        # 塞入功能码
        data_list.insert(0, self.func_code)
        # 校验和
        check_sum = self.check_sum(data_list)
        data_list.append(check_sum)
        # 添加头尾
        data_list = self.add_head_and_end(data_list)
        return bytes(data_list)

    @classmethod
    def add_head_and_end(cls, data_list):
        for i in range(3):
            data_list.insert(0, 0x6a)
            data_list.append(0x6f)
        return data_list

    @classmethod
    def check_sum(cls, data_list):
        _check_sum = 0
        for num in data_list:
            _check_sum += num
            _check_sum &= 0xff
        return _check_sum


"""=================================================dtu handler ============================================================"""


@Singleton
class HandlerDtu(object):

    def __init__(self, dtu):
        self.dtu = dtu

    def refresh(self):
        try:
            self.dtu.prepare()
            self.dtu.dialing()
            self.dtu.parse()
            self.dtu.request()
            self.dtu.start()
        except Exception as e:
            raise e
        else:
            while 1:
                pass


@Singleton
class DtuUart(object):

    def __init__(self):
        # self.uart = UART(UART.UART2, 115200, 8, 0, 1, 0)
        set_uart2 = False
        self.dtu_d = DTUDocumentData()
        # 配置uart
        config_path = CONFIG["config_path"]
        config_params = ProdDocumentParse().refresh_document(config_path)
        uconf = ujson.loads(config_params)["uconf"]
        print("uconf: ", uconf)
        for i in uconf:
            if len(i):
                if int(i[0]) == 0:
                    print("UART0 DEBUG PORT set")
                    try:  # 兼容老版本的配置文件
                        self.uart = UART(UART.UART0, int(i[1]), int(i[2]), int(i[3]), int(i[4]), 0)
                    except Exception as e:
                        self.uart = UART(UART.UART0, int(i[1]), int(i[2]), self.parity_flag(i[3]), int(i[4]), 0)
                if int(i[0]) == 1:
                    print("UART1 BT PORT set")
                    try:
                        self.uart = UART(UART.UART1, int(i[1]), int(i[2]), int(i[3]), int(i[4]), 0)
                        set_uart2 = True
                    except Exception as e:
                        self.uart = UART(UART.UART1, int(i[1]), int(i[2]), self.parity_flag(i[3]), int(i[4]), 0)
                if int(i[0]) == 2:
                    print("UART2 MAIN PORT set")
                    try:
                        self.uart = UART(UART.UART2, int(i[1]), int(i[2]), int(i[3]), int(i[4]), 0)
                    except Exception as e:
                        self.uart = UART(UART.UART2, int(i[1]), int(i[2]), self.parity_flag(i[3]), int(i[4]), 0)
                if int(i[0]) == 3:
                    pass
                    # TODO 不能设置cdc口，不然会影响数据解析
                    # print("UART3 USB CDC PORT set")
                    # try:
                    #     self.uart = UART(UART.UART3, int(i[1]), int(i[2]), int(i[3]), int(i[4]), 0)
                    # except Exception as e:
                    #     self.uart = UART(UART.UART3, int(i[1]), int(i[2]), self.parity_flag(i[3]), int(i[4]), 0)
                    # self.uart = UART(UART.UART2, 115200, 8, 0, 1, 0)
        if not set_uart2:
            self.uart = UART(UART.UART2, 115200, 8, 0, 1, 0)

    def parity_flag(self, data):
        global parity
        if data == "NONE":
            parity = 0
        if data == "EVENT":
            parity = 1
        if data == "ODD":
            parity = 2
        return parity

    def output(self, code, content="", status=RET.OK, success=1):
        return_message = dict(success=success, code=status, data=content)
        logger.info("return message {}".format(return_message))
        if not success:
            HISTORY_ERROR.append(dict(code=code, error_code=status))
        json_data = ujson.dumps(return_message)
        if self.dtu_d.plate:
            json_data = dev_imei + json_data
        content_transfer = DtuProtocolData(code, json_data).send()
        self.uart.write(content_transfer)

    def read(self):
        while 1:
            # 返回是否有可读取的数据长度
            msgLen = self.uart.any()
            # 当有数据时进行读取
            if msgLen:
                msg = self.uart.read(msgLen)
                # 初始数据是字节类型（bytes）,将字节类型数据进行编码
                DtuProtocolData.transfer_hex_to_data_obj(msg)

            else:
                utime.sleep_ms(100)
                continue


"""===================================================dtu command=========================================================="""


@Singleton
class DTUSearchCommand(object):
    def __init__(self):
        self.dtu_c = DTUDocumentData()

    def get_imei(self, code):
        self.output(code, dev_imei)

    def get_number(self, code):
        logger.info(sim.getPhoneNumber())
        self.output(code, sim.getPhoneNumber())

    def get_version(self, code):
        logger.info(self.dtu_c.version)
        self.output(code, self.dtu_c.version)

    def get_csq(self, code):
        self.output(code, str(net.csqQueryPoll()))

    def get_cur_config(self, code):
        logger.info("get_cur_config")
        self.output(code, self.dtu_c.json_info(need=False))

    def get_diagnostic_info(self, code):
        logger.info("get_diagnostic_message")
        self.output(code, str(HISTORY_ERROR))

    def output(self, code, content="", status=RET.OK, success=1):
        DtuUart().output(code, content=content, status=status, success=success)


@Singleton
class BasicSettingCommand(object):

    def __init__(self):
        self.dtu_c = DTUDocumentData()

    def restart(self, code, data):
        logger.info("Restarting...")
        Power.powerRestart()

    def output(self, code, content="", status=RET.OK, success=1):
        DtuUart().output(code, content=content, status=status, success=success)

    def set_int_data(self, code, data, sign):
        logger.info("data: %s" % data)
        try:
            number = data[sign]
            number = int(number)
        except Exception as e:
            logger.error("e = {}".format(e))
            self.output(code, success=0, status=RET.DATAPARSEERR)
        else:
            setattr(self.dtu_c, sign, number)
            self.dtu_c.reload_file()
            self.output(code)

    def set_plate(self, code, data):
        self.set_int_data(code, data, 'plate')

    def set_reg(self, code, data):
        self.set_int_data(code, data, 'reg')

    def set_version(self, code, data):
        self.set_int_data(code, data, 'version')

    def set_passwd(self, code, data):
        try:
            passwd = str(data["password"])
        except Exception as e:
            logger.error("e = {}".format(e))
            self.output(code, success=0, status=RET.DATAPARSEERR)
        else:
            setattr(self.dtu_c, "password", passwd)
            self.dtu_c.reload_file()
            self.output(code)

    def set_fota(self, code, data):
        self.set_int_data(code, data, 'fota')

    def set_ota(self, code, data):
        print("set_ota: ", code, data)
        try:
            ota = data["ota"]
            if not isinstance(ota, list):
                raise DTUException(RET.DATATYPEERR)
            if len(ota) != 3:
                raise DTUException(RET.NUMBERERR)
        except DTUException as e:
            logger.error(e)
            self.output(code, success=0, status=e.message)
        except Exception as e:
            logger.error(e)
            self.output(code, success=0, status=RET.DATAPARSEERR)
        else:
            setattr(self.dtu_c, "ota", ota)
            self.dtu_c.reload_file()
            self.output(code)

    def set_nolog(self, code, data):
        self.set_int_data(code, data, 'nolog')

    def set_service_acquire(self, code, data):
        self.set_int_data(code, data, 'service_acquire')

    def set_uconf(self, code, data):
        try:
            uconf = data["uconf"]
            if not isinstance(uconf, list):
                raise DTUException(RET.DATATYPEERR)
            if len(uconf) != 4:
                raise DTUException(RET.NUMBERERR)
        except DTUException as e:
            logger.error(e)
            self.output(code, success=0, status=e.message)
        except Exception as e:
            logger.error(e)
            self.output(code, success=0, status=RET.DATAPARSEERR)
        else:
            setattr(self.dtu_c, "uconf", uconf)
            self.dtu_c.reload_file()
            self.output(code)

    def set_conf(self, code, data):
        try:
            conf = data["conf"]
            if not isinstance(conf, list):
                raise DTUException(RET.DATATYPEERR)
            if len(conf) != 7:
                raise DTUException(RET.NUMBERERR)
        except DTUException as e:
            logger.error(e)
            self.output(code, success=0, status=e.message)
        except Exception as e:
            logger.error(e)
            self.output(code, success=0, status=RET.DATAPARSEERR)
        else:
            setattr(self.dtu_c, "conf", conf)
            self.dtu_c.reload_file()
            self.output(code)

    def set_apns(self, code, data):
        print("apn_code_data: ", code, data)
        self.dtu_c.apn = data
        self.output(code)
        try:
            apn = data["apn"]
            if not isinstance(apn, list):
                raise DTUException(RET.DATATYPEERR)
            if len(apn) != 3:
                raise DTUException(RET.NUMBERERR)
        except DTUException as e:
            logger.error(e)
            self.output(code, success=0, status=e.message)
        except Exception as e:
            logger.error(e)
            self.output(code, success=0, status=RET.DATAPARSEERR)
        else:
            setattr(self.dtu_c, "apn", apn)
            self.dtu_c.reload_file()
            self.output(code)

    def set_pins(self, code, data):
        print("pins_code_data: ", code, data)
        try:
            pins = data["pins"]
            if not isinstance(pins, list):
                raise DTUException(RET.DATATYPEERR)
            if len(pins) != 3:
                raise DTUException(RET.NUMBERERR)
        except DTUException as e:
            logger.error(e)
            self.output(code, success=0, status=e.message)
        except Exception as e:
            logger.error(e)
            self.output(code, success=0, status=RET.DATAPARSEERR)
        else:
            setattr(self.dtu_c, "pins", pins)
            self.dtu_c.reload_file()
            self.output(code)


@Singleton
class ChannelTransfer(object):
    def __init__(self):
        self.dtu_c = DTUDocumentData()
        self.channel_dict = {}


@Singleton
class DtuExecCommand(object):

    def __init__(self):
        self.not_need_password_verify_code = [0x00, 0x01, 0x02, 0x03, 0x05]
        self.search_command = {
            0x00: "get_imei",
            0x01: "get_number",
            0x02: "get_version",
            0x03: "get_csq",
            0x04: "get_cur_config",
            0x05: "get_diagnostic_info"
        }
        self.basic_setting_command = {
            0xff: "restart",
            0x50: "set_message",
            0x51: "set_passwd",
            0x52: "set_plate",
            0x53: "set_reg",
            0x54: "set_version",
            0x55: "set_fota",
            0X56: "set_nolog",
            0X57: "set_service_acquire",
            0X58: "set_uconf",
            0x59: "set_conf",
            0x60: "set_apns",
            0x61: "set_pins",
            0x62: "set_ota",
        }
        self.search_command_func_code_list = self.search_command.keys()
        self.basic_setting_command_list = self.basic_setting_command.keys()
        self.dtu_uart = DtuUart()
        self.dtu_d = DTUDocumentData()
        self.ctf = ChannelTransfer()

    def exec_command(self, dt_b):
        func_code = int(dt_b.func_code)
        data = str()
        if func_code not in self.not_need_password_verify_code:
            try:
                # 解析数据
                json_loads = ujson.loads(dt_b.content)
            except Exception as e:
                # json解析失败
                self.dtu_uart.output(func_code, success=0, status=RET.JSONLOADERR)
            else:
                try:
                    passwd = json_loads["password"]
                except Exception as e:
                    self.dtu_uart.output(func_code, success=0, status=RET.PASSWORDERR)
                    return
                else:
                    if passwd != self.dtu_d.password:
                        self.dtu_uart.output(func_code, status=RET.PASSWDVERIFYERR, success=0)
                        return
                    else:
                        try:
                            data = json_loads["data"]
                        except Exception as e:
                            # 成功返回实例子
                            self.dtu_uart.output(func_code, success=0, status=RET.JSONLOADERR)
                            return
        if func_code in self.search_command_func_code_list:
            getattr(DTUSearchCommand(), self.search_command[func_code])(func_code)
        elif func_code in self.basic_setting_command_list:
            getattr(BasicSettingCommand(), self.basic_setting_command[func_code])(func_code, data)
        elif 0x41 <= func_code <= 0x47:
            try:
                channel_obj = self.ctf.channel_dict[func_code]
            except Exception as e:
                logger.error(e)
                self.dtu_uart.output(func_code, status=RET.CHANNELERR, success=0)
            else:
                try:
                    channel_obj.send(data)
                except Exception as e:
                    logger.error("error sending %s" % e)
                    self.dtu_uart.output(success=0, code=func_code, status=RET.DATASENDERR)
        else:
            self.dtu_uart.output(success=0, code=func_code, status=RET.POINTERR)


"""=================================================== run ============================================================"""


def run():
    dtu = ProdDtu(dtu_gpio=ProdGPIO(), uart=DtuUart())
    HandlerDtu(dtu).refresh()


if __name__ == '__main__':
    run()
