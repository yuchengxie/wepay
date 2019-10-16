# 统一下单

import requests
import hashlib
import xmltodict
import time
import random
import string
import datetime

from config import APPID, MCHID, KEY, NOTIFY_URL


# 生成nonce_str
def generate_randomStr():
    return ''.join(random.sample(string.ascii_letters + string.digits, 32))

# 生成签名


def generate_sign(param):
    stringA = ''

    ks = sorted(param.keys())
    # 参数排序
    for k in ks:
        stringA += k + "=" + str(param[k]) + "&"
    # 拼接商户KEY
    stringSignTemp = stringA + "key=" + KEY

    # md5加密
    hash_md5 = hashlib.md5(stringSignTemp.encode('utf8'))
    sign = hash_md5.hexdigest().upper()

    return sign

# 发送xml请求


def send_xml_request(url, param):
    # dict 2 xml
    param = {'root': param}
    xml = xmltodict.unparse(param)

    response = requests.post(url, data=xml.encode(
        'utf-8'), headers={'Content-Type': 'text/xml'})
    # xml 2 dict
    msg = response.text
    xmlmsg = xmltodict.parse(msg)

    return xmlmsg

# 统一下单


def generate_out_trade_no():
    date = datetime.datetime.now()
    payOrdrID = date.strftime("%Y%m%d%H%M%S%f")
    return payOrdrID


def generate_bill(out_trade_no, fee, openid):
    url = "https://api.mch.weixin.qq.com/pay/unifiedorder"
    nonce_str = generate_randomStr()        # 订单中加nonce_str字段记录（回调判断使用）
    out_trade_no = generate_out_trade_no()     # 支付单号，只能使用一次，不可重复支付

    '''
    order.out_trade_no = out_trade_no
    order.nonce_str = nonce_str
    order.save()
    '''

    # 1. 参数
    param = {
        "appid": APPID,
        "mch_id": MCHID,    # 商户号
        "nonce_str": nonce_str,     # 随机字符串
        "body": 'TEST_pay',     # 支付说明
        "out_trade_no": out_trade_no,   # 自己生成的订单号
        "total_fee": fee,
        "spbill_create_ip": '127.0.0.1',    # 发起统一下单的ip
        "notify_url": NOTIFY_URL,
        "trade_type": 'JSAPI',      # 小程序写JSAPI
        # "openid": openid,
    }
    # 2. 统一下单签名
    sign = generate_sign(param)
    param["sign"] = sign  # 加入签名
    print('>>> param:', param)
    # 3. 调用接口
    xmlmsg = send_xml_request(url, param)
    print('>>> xmlmsg:', xmlmsg)
    
    # 4. 获取prepay_id
    if xmlmsg['xml']['return_code'] == 'SUCCESS':
        if xmlmsg['xml']['result_code'] == 'SUCCESS':
            prepay_id = xmlmsg['xml']['prepay_id']
            # 时间戳
            timeStamp = str(int(time.time()))
            # 5. 根据文档，六个参数，否则app提示签名验证失败，https://pay.weixin.qq.com/wiki/doc/api/app/app.php?chapter=9_12
            data = {
                "appid": APPID,
                "partnerid": MCHID,
                "prepayid": prepay_id,
                "package": "Sign=WXPay",
                "noncestr": nonce_str,
                "timestamp": timeStamp,
            }            # 6. paySign签名
            paySign = generate_sign(data)
            data["paySign"] = paySign  # 加入签名
            # 7. 传给前端的签名后的参数
            return data


# def generate_bill(out_trade_no, fee, openid)
generate_bill(111, 1, '')
