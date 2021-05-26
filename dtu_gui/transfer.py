import logging
import json
from time import sleep, time


def init_logger():
    # 第一步，创建一个logger
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)  # Log等级总开关
    # 第二步，创建一个handler，用于写入日志文件
    logfile = './quec_cp.log'
    fh = logging.FileHandler(logfile, mode='a')  # open的打开模式这里可以进行参考
    fh.setLevel(logging.DEBUG)  # 输出到file的log等级的开关
    # 第三步，再创建一个handler，用于输出到控制台
    ch = logging.StreamHandler()
    ch.setLevel(logging.WARNING)  # 输出到console的log等级的开关
    # 第四步，定义handler的输出格式
    formatter = logging.Formatter("%(asctime)s - %(filename)s[line:%(lineno)d] - %(levelname)s: %(message)s")
    fh.setFormatter(formatter)
    ch.setFormatter(formatter)
    # 第五步，将logger添加到handler里面
    logger.addHandler(fh)
    logger.addHandler(ch)
    return logger


logger = init_logger()


class TransferS(object):
    frame_head = b'\x6a\x6a\x6a'
    frame_tail = b'\x6f\x6f\x6f'

    def __init__(self, func_code, content, data_length=0x00, check_sum_number=0x00):
        self.func_code = func_code
        self.data_length = data_length
        self.content = content
        self.check_sum_number = check_sum_number

    def send(self):
        return self.transfer_str_to_hex()

    @classmethod
    def transfer_hex_to_data_obj(cls, data):
        if data[:3] == cls.frame_head and data[-3:] == cls.frame_tail:
            # 内容列表
            content = data[3:-3]
            print(cls.check_sum(content[:-1]))
            print(content[-1])
            if cls.check_sum(content[:-1]) == content[-1]:
                # 功能码
                func_code = content[0]
                # 数据内容
                data_length = content[1] * 256 + content[2]

                data_content = ""
                for i in content[3:data_length]:
                    data_content += chr(i)
                return TransferS(func_code, data_content, data_length=data_length, check_sum_number=content[-1])
            else:
                # 校验和不通过
                print("not allowed")
        else:
            return None

    def transfer_str_to_hex(self):
        try:
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
        except Exception as e:
            print(e)
            return False

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
