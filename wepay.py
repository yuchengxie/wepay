import datetime
import time
import json
import socket
import random
import hashlib
from urllib import request as request2
import xmltodict
import requests
from flask import Flask, request

APP_ID = 'wxf680bb88ef1bcc01'
MCH_ID = '1527353211'
APP_SECRET = '6257954d8d4bc0c769852a3fd802a55f'
SPBILL_CREATE_IP = '113.110.218.211'
PAY_KEY = 'itissampleitissampleitissample12'   # itissampelitissampelitissampel12
OPEN_ID = ''
SESSION_KEY = ''
notify_url = 'http://www.weixin.qq.com/wxpay/pay.php'

# 生成随机数字符串/nonce_str

app = Flask(__name__)


def getNonceStr():
    data = "123456789zxcvbnmasdfghjklqwertyuiopZXCVBNMASDFGHJKLQWERTYUIOP"
    nonce_str = ''.join(random.sample(data, 30))
    return nonce_str

# 商户订单号/out_trade_no'


def getPayOrdrID():
    date = datetime.datetime.now()
    payOrdrID = date.strftime("%Y%m%d%H%M%S%f")
    return payOrdrID


def getHostIp():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
    finally:
        s.close()

    # return ip
    return '27.38.249.93'

# 生成签名的函数


def order():
    nonce_str = getNonceStr()
    out_trade_no = getPayOrdrID()
    # spbill_create_ip = getHostIp()
    spbill_create_ip = SPBILL_CREATE_IP
    total_fee = 1
    openid = ''
    body = 'test'
# appid,mch_id,nonce_str,sign,body,out_trade_no,total_fee,spbill_create_ip,notify_url,trade_type
    order_dict = {
        "appid": APP_ID,
        "body": body,
        "mch_id": MCH_ID,
        "nonce_str": nonce_str,
        "openid": openid,
        "out_trade_no": out_trade_no,
        "spbill_create_ip": spbill_create_ip,
        "total_fee": total_fee,
        "trade_type": 'JSAPI',
        "notify_url": notify_url,
        'sign_type': 'MD5',
        "sign": ''
    }
    print('first sign')
    sign = xcx_pay_sign(order_dict)
    order_dict['sign'] = sign
    # print('signed_dict = ', order_dict )
    order_xmlstr = dict2xmlstr(order_dict)
    print('xmstr:', order_xmlstr)

    # 测试
    # f1 = open('test.txt','w')
    # f1.write(order_xmlstr)

    # print(type(order_xmlstr),'order_xmlstr = ', order_xmlstr )

    order_xmlbytes = order_xmlstr.encode('utf-8')
    print('>>>>>>>>order_xmlbytes:', order_xmlbytes)

    url = 'https://api.mch.weixin.qq.com/pay/unifiedorder'
    try:
        # rsp = request.urlopen(url, order_xmlbytes)
        rsp = request.urlopen(url, order_xmlstr)
        print('rsp:', rsp)
        msg = rsp.read().decode('utf-8')
        print('>>>msg:', msg)
        # xmlresp = xmltodict.parse(msg)
        # print('xmlresp = ', xmlresp)
        # response = requests.request('post', url, data=order_xmlstr)
        # xmlresp = xmltodict.parse(response.content)
        # print('xmlresp:',xmlresp)
    finally:
        pass


def xcx_pay_sign(order_dict):
    '''
    小程序支付签名算法：
    1. 将集合M内非空参数值的参数按照参数名ASCII码从小到大排序（字典序），使用URL键值对的格式（即key1=value1&key2=value2…）拼接成字符串stringA
    ◆ 参数名ASCII码从小到大排序（字典序）；
    ◆ 如果参数的值为空不参与签名；
    ◆ 参数名区分大小写；
    ◆ 验证调用返回或微信主动通知签名时，传送的sign参数不参与签名，将生成的签名与该sign值作校验。
    ◆ 微信接口可能增加字段，验证签名时必须支持增加的扩展字段
    2. 在stringA最后拼接上key得到stringSignTemp字符串，并对stringSignTemp进行MD5运算，再将得到的字符串所有字符转换为大写，得到sign值signValue
    '''
    print("xcx_pay_sign:", order_dict)
    stringA = ''
    if isinstance(order_dict, dict):
        for k, v in sorted(order_dict.items(), key=lambda order_dict: order_dict[0]):
            if ('sign' != k) & ('' != v):
                stringA += k + '=' + str(v) + '&'
    else:
        pass  # 待实现！！！改成异常处理

    # 上面的循环导致最后一个字符是'&'，这里去掉，后续考虑改进
    # if '&' == stringA[-1:] : stringA = stringA[:-1]

    stringSignTemp = stringA + "key=" + PAY_KEY  # 确保此秘钥生效
    sign = MD5(stringSignTemp).upper()
    print('sign = ', sign)
    return sign


def dict2xmlstr(dict):
    '''
    将订单字典类型转化为XML字符串
    这里考虑改一下：自动加上CDATA标签，然后转成bytes类型，方法名改成dict2xmlbytes!!!
    '''
    xml = ''
    for key, value in dict.items():
        xml += '<{0}>{1}</{0}>'.format(key, value)
    xml = '<xml>{0}</xml>'.format(xml)

#   xml.replace(' ','')
#   xml.replace('\n','')
#   xml.replace('\r','')

    return xml


def MD5(str):
    '''
    MD5签名
    '''
    md5 = hashlib.md5()
    md5.update(str.encode('utf-8'))
    return md5.hexdigest()


def xml_to_dict(xml_data):
    return xmltodict.parse(xml_data)


def trans_dict_to_xml(data):
    xml = []
    for k in sorted(data.keys()):
        v = data.get(k)
        if k == 'detail' and not v.startswith('<![CDATA['):
            v = '<![CDATA[{}]]>'.format(v)
        xml.append('<{key}>{value}</{key}>'.format(key=k, value=v))
    return '<xml>{}</xml>'.format(''.join(xml))


def trans_xml_to_dict(xml):
    # todo
    return 'data'


@app.route('/')
def hello():
    return "hello service"


@app.route('/createorder', methods=['POST'])
def createOrder():
    openid = request.json.get('openid')
    print('>>> get openid:', openid)
    nonce_str = getNonceStr()
    out_trade_no = getPayOrdrID()
    spbill_create_ip = SPBILL_CREATE_IP
    total_fee = 1  # 注意订单总金额，单位为分
    body = 'test'

    order_dict = {
        "appid": APP_ID,
        "body": body,
        "mch_id": MCH_ID,
        "nonce_str": nonce_str,
        "openid": openid,
        "out_trade_no": out_trade_no,
        "spbill_create_ip": spbill_create_ip,
        "total_fee": total_fee,
        "trade_type": 'JSAPI',
        "notify_url": notify_url,
        'sign_type': 'MD5',
        "sign": ''
    }
    # 一次签名
    sign = xcx_pay_sign(order_dict)
    order_dict['sign'] = sign
    order_xmlstr = dict2xmlstr(order_dict)
    order_xmlbytes = order_xmlstr.encode('utf-8')
    url = 'https://api.mch.weixin.qq.com/pay/unifiedorder'
    try:
        rsp = request2.urlopen(url, order_xmlbytes)
        msg = rsp.read().decode('utf-8')
        xmlresp = xmltodict.parse(msg)
        data = {}
        if xmlresp['xml']['return_code'] == 'SUCCESS':
            if xmlresp['xml']['result_code'] == 'SUCCESS':
                # 二次签名
                data = {
                    "appId": xmlresp['xml']['appid'],
                    "nonceStr": getNonceStr(),
                    "package": "prepay_id=" + xmlresp['xml']['prepay_id'],
                    "signType": "MD5",
                    "timeStamp": str(int(time.time()))
                }
                print('sign again')
                data['paySign'] = xcx_pay_sign(data)
                data = json.dumps(data).encode('utf-8')
                return data
    except ValueError as e:
        return 'error'


@app.route("/getopenid", methods=["GET"])
def getOpenid():
    code = request.args.get('code')
    print('get code:',code)
    url = "https://api.weixin.qq.com/sns/jscode2session?appid={0}&secret={1}&js_code={2}&grant_type=authorization_code".format(
        APP_ID, APP_SECRET, code)
    print('getopenid url:',url)
    rsp = request2.urlopen(url, None)
    print('rsp.status:', rsp.status)
    msg = rsp.read().decode('utf-8')
    print('msg:',msg)
    dic = json.loads(msg)
    print('dic:',dic)
    openid = dic["openid"]
    return openid


if __name__ == "__main__":
    # app.run(port=3000, host="0.0.0.0", debug=True)
    app.run(port=3001, host="0.0.0.0", debug=True)
