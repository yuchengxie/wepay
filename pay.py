import string
import socket, time, random, hashlib, json, traceback
from urllib import request

import xmltodict

'''
小程序全局变量
'''
# 临时用全局变量处理唯一的一个用户的支付，后续需要改成数据库管理。因为可能有多个客户同时支付
XCX_APP_ID = 'wx60c655b77c6a6b74'
XCX_MCH_ID = '1527353211'
XCX_APP_SECRET = 'b518fda7aa099d622a029c414cf4188e'
SPBILL_CREATE_IP = '52.80.151.83'
PAY_KEY = '0hobf98Q3TNUBBphrgbd89dmj980fadg'   # DJJOIBFDoihaeno9VASDFDB98512U0OE
XCX_OPEN_ID = ''
XCX_SESSION_KEY = ''


# ----------------------------------------------以下为小程序---------------------------------------------------#
# 商户服务器与客户端之间通过Json通信，
# 商户服务其与小程序服务器之间通过XML通信，当前编码仍存在问题，且经过XML解析后，并不好用。问题如下：
# 待改进问题：
# 1. 编码问题
# content = '<xml><return_code><![CDATA[FAIL]]></return_code>\\n<return_msg><![CDATA[\\xe7\\xad\\xbe\\xe5\\x90\\x8d\\xe9\\x94\\x99\\xe8\\xaf\\xaf]]></return_msg>\\n</xml>'
# 在经过ElementTree、minidom、xmltodict解析后，中文部分的CDATA标签被去掉，且字符间的\也同时被去掉，变成为'\xe7\xad\xbe\xe5\x90\x8d\xe9\x94\x99\xe8\xaf\xaf
# 这种状态是没有完成解码的状态，因此只能通过s.encode('latin-1').decode('utf-8')的方式重新解码！！！
# 2. 需要用装饰器写log
# 3. 需要写单元测试
# 4. 前端代码和后端代码合并
# ----------------------------------------------以下为小程序---------------------------------------------------#


def generate_ssn(openid, session_key):
  '''
  session_key不能传出服务器，因此根据session_key生成session_id，并传给客户端，以跟客户端保持相同session。
  绑定生成的sesion_key和session_id，保存session状态。暂时没有想清楚保持session的意义，因为有了订单状态，可以用订单状态管理
  '''
  ssn_id = 10000
  pass
  return ssn_id


def get_order_id(ssn_id, pdct_id):
  '''
  生成订单号，后续需要把订单封装成类。
  '''
  # 为了保证测试，每次下的订单号不同，生成订单号。订单号前8位是本日日期，后6位是随机数字
  order_id = time.strftime('%Y%m%d',time.localtime(time.time())) + random_str(6, string.digits)
  pass
  return order_id


class order(object):
  '''
  考虑将order写为抽象类，后续不同的商品可能会有一些order上实现的差异
  订单的状态：订单生成，付款子状态（待付款，付款超时，付款成功，付款通知验证完毕），产品交付子状态（发货，验收，关闭），订单关闭。
  '''
  def __init__(self, order_id, order_status, open_id):
    self.order_id = ''
    self.order_status = ''
    self.open_id = ''
    self.user_name = ''
    self.history = ''    # 描述历史上订单的操作过程

  # 生成订单id和取id分成两个方法
  def gen_order_id(self):
    order_id = time.strftime('%Y%m%d',time.localtime(time.time())) + random_str(6, string.digits)
    return order_id

  # 防止关键数据被改动，写get方法，用property装饰器实现
  def get_order_id(self):
    pass


def random_str(size=32, chars=string.ascii_uppercase + string.ascii_lowercase + string.digits):
  '''
  生成随机字符串
  '''
  return ''.join(random.choice(chars) for _ in range(size))


def get_price(order_id):
  '''
  根据订单生成价格，这个地方可能逻辑有问题，考虑跟订单一起封装成类。
  '''
  pass
  return 1


def MD5(str):
  '''
  MD5签名
  '''
  md5 = hashlib.md5()
  md5.update(str.encode('utf-8'))
  return md5.hexdigest()


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
    for k,v in sorted(order_dict.items(),key=lambda order_dict:order_dict[0]):
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
  return xml


def xcx_login_(environ, method, response, slug=''):
  '''
  小程序，在服务器侧完成登陆：1. 根据从客户端收到的code向微信服务器请求openid和session_key 2. 管理登陆状态
  code: 用户登录凭证（有效期五分钟）。开发者需要在开发者服务器后台调用 code2Session，使用 code 换取 openid 和 session_key 等信息
  slug是如何判断的，当前处理后为空？？？
  '''
  # if '' == XCX_OPEN_ID 补充已经登录，不用重复登录，并返回openid的信息
  print("xcx_login_")
  print("environ:", environ)
  print("method:", method)
  print("response:", response)
  print("slug:", slug)
  if 'POST' == method:
    body = environ['wsgi.input'].read(int(environ.get('CONTENT_LENGTH',0)))
    body = json.loads(body)

    url = 'https://api.weixin.qq.com/sns/jscode2session?appid=' + XCX_APP_ID + \
          '&secret=' + XCX_APP_SECRET + \
          '&js_code=' + body.get('code') + \
          '&grant_type=authorization_code'

    try:
      rsp = request.urlopen(url)
      rsp = json.loads(rsp.read())  # loads()将字符串转化为字典，这一段后续优化，封装为解读url，考虑用requests包取代request！！！
      print("rsp:", rsp)
      # 根据jscode2session返回的openid和session_key建立商户服务器的登陆状态。
      # 当前用全局变量存储openid和session_key，并生成session_id以表示session，后续要改
      global XCX_OPEN_ID
      global XCX_SESSION_KEY
      XCX_OPEN_ID = rsp['openid']
      print('openid = ', rsp['openid'])
      XCX_SESSION_KEY = rsp['session_key']

      ssn_id = generate_ssn(XCX_OPEN_ID, XCX_SESSION_KEY)

    except:
      traceback.print_exc()

  # 将session_id传回给客户端，让客户端和商户服务器保持同样的session状态；openid传回给客户端可能没什么用，后续可以考虑删除。
  rsp_data = {
      'ssn_id': ssn_id,
      'openid': rsp['openid'],
  }
  rsp_data = json.dumps(rsp_data).encode('utf-8')
  response('200 OK',[('Content-Type','application/Json')])    # 传200 ok不确定是否正确？？？
  print("rsp_data:", rsp_data)
  return [ rsp_data ]


def xcx_order_(environ, method, response, slug=''):
  '''
  小程序，下单流程：
  1. 客户端根据下单的内容向微信接口服务器发送下单请求，获取prepay_id
  2. 在商户服务器再次签名
  3. 将签名结果返回给客户端
  '''
  print("xcx_order_:", environ)
  print("environ:", environ)
  print("method:", method)
  print("response:", response)
  print("slug:", slug)
  # if '' == XCX_OPEN_ID 补充如果没有登录，要求主动登录的信息

  if 'POST' == method:
    # 读取客户端下单请求信息
    body = environ['wsgi.input'].read(int(environ.get('CONTENT_LENGTH',0)))
    body = json.loads(body)

    order_id = get_order_id(body.get('ssn_id'), body.get('pdct_id'))
    nonce_str = random_str(32)
    total_fee = get_price(order_id)

    seedInfo = socket.getaddrinfo('cd.pinwen.wang',443,socket.AF_UNSPEC,socket.SOCK_STREAM)
    if seedInfo:
      ipAddr = seedInfo[0][4][0]
    else: ipAddr = SPBILL_CREATE_IP

    # 根据统一支付接口组织信息，并发送至微信接口服务器
    order_dict = {
        'appid': XCX_APP_ID,
        # 'attach': 'pay test',
        'body': 'JSAPItest',
        'mch_id': XCX_MCH_ID,
        # 'detail': body.get('pdct_id'),
        'nonce_str': nonce_str,
        'notify_url': 'https://cd.pinwen.wang/wx/xcx/payresult',    # 此url用于接收支付结果通知
        'openid': XCX_OPEN_ID,
        'out_trade_no': 1,
        'spbill_create_ip': ipAddr,
        'total_fee': total_fee,
        'trade_type': 'JSAPI',
        'sign_type': 'MD5',
        'sign': '',
    }    # 数据类型可能要检查一下？？？
    print('first sign')
    sign = xcx_pay_sign(order_dict)
    order_dict['sign'] = sign
    # print('signed_dict = ', order_dict )
    order_xmlstr = dict2xmlstr(order_dict)
    print(type(order_xmlstr),'order_xmlstr = ', order_xmlstr )
    order_xmlbytes = order_xmlstr.encode('utf-8')   # 待dict2xmlstr()优化后，
    # order_xmlbytes = order_xmlstr.encode('latin-1')

    url = 'https://api.mch.weixin.qq.com/pay/unifiedorder'

    try:
      # 向微信服务器“统一下单请求”接口发起请求
      rsp = request.urlopen(url, order_xmlbytes)
      print("rsp:", rsp)

      # 请求响应中包含prepay_id
      # print('rsp.read() = ', rsp.read())
      msg = rsp.read().decode('utf-8')
      print('msg = ', msg)
      xmlresp = xmltodict.parse(msg)
      print('xmlresp = ', xmlresp)
      data = {}
      if xmlresp['xml']['return_code'] == 'SUCCESS':
        if xmlresp['xml']['result_code'] == 'SUCCESS':

          # 再次签名
          data = {
              "appId": xmlresp['xml']['appid'],
              "nonceStr": random_str(32),
              "package": "prepay_id=" + xmlresp['xml']['prepay_id'],
              "signType": "MD5",
              "timeStamp": str(int(time.time()))
          }
          print('sign again')
          data['paySign'] = xcx_pay_sign(data)

          # 签名后返回给前端
          response('200 OK',[('Content-Type','application/Json')])    # 传200 ok不确定是否正确？？？
          print("data:", data)
          return [ json.dumps(data).encode('utf-8') ]
        else:
          data['rsp_code'] = xmlresp['xml']['result_code']
          response('400 Bad Request', [('Content-Type','application/Json')])
          print("data:", data)
          return [ json.dumps(data).encode('utf-8') ]
      else:
        data['rsp_code'] = xmlresp['xml']['return_code']
        return_msg = xmlresp['xml']['return_msg']
        print(type(return_msg), 'return_msg = ', return_msg)
        print(ord(return_msg[0]),ord(return_msg[1]))
        data['rsp_msg'] = return_msg.encode('latin-1').decode('utf-8')
        response('400 Bad Request', [('Content-Type','application/Json')])
        print("data:", data)
        return [ json.dumps(data).encode('utf-8') ]

    except:
      traceback.print_exc()
      # 尚未做异常处理

def xcx_payresult_(environ, method, response, slug=''):
  '''
  小程序，支付完成后，微信会把相关支付结果发送给商户，商户需要接收处理，并按文档规范返回应答。
  在下单时通知小程序服务器支付结果通知地址：当前为：'notify_url': 'http://cd.pinwen.wang/wx/application.py'
  后台通知交互时，如果微信收到商户的应答不符合规范或超时，微信会判定本次通知失败，重新发送通知，直到成功为止（在通知一直不成功的情况下，
  微信总共会发起10次通知，每次通知时间距离最近一次的间隔为15/15/30/180/1800/1800/1800/1800/3600，单位：秒），但微信不保证通知最终一定能成功。
  '''
  print('xcx_payresult_ :')
  print("environ:", environ)
  print("method:", method)
  print("response:", response)
  print("slug:", slug)
  xml_input = environ['wsgi.input'].read(int(environ.get('CONTENT_LENGTH',0)))
  xml_input = xmltodict.parse(xml_input)

  rsp_xml_dict = {
      'return_code': '',
      'return_msg': '',
  }

  if xml_input['xml']['return_code'] == 'SUCCESS':
    # 1. 做签名验证，校验订单金额是否一致，防止假通知
    # 2. 判断是否已经处理过此通知。在对业务数据进行状态检查和处理之前，要采用数据锁进行并发控制，以避免函数重入造成的数据混乱。
    # 3. 技术人员可登进微信商户后台扫描加入接口报警群，获取接口告警信息。

    if xml_input['xml']['result_code'] == 'SUCCESS':
      rsp_xml_dict['return_code'] = 'SUCCESS'
      rsp_xml_dict['return_msg'] = 'OK'
      response('200 OK',[('Content-Type','application/xml')])
      print("rsp_xml_dict:", rsp_xml_dict)
      return [ dict2xmlstr(rsp_xml_dict) ]
    else:
      pass  # 需要做失败后的业务处理！！！
      rsp_xml_dict['return_code'] = 'FAIL'
      rsp_xml_dict['return_msg'] = '业务失败原因：比如签名失败'
      response('200 OK', [('Content-Type','application/xml')])
      print("rsp_xml_dict:", rsp_xml_dict)
      return [ dict2xmlstr(rsp_xml_dict) ]
  else:
    pass  # 需要做失败后的业务处理！！！
    rsp_xml_dict['return_code'] = 'FAIL'
    rsp_xml_dict['return_msg'] = '失败原因：如校验失败'
    response('200 OK', [('Content-Type','application/xml')])   # 200 ok可能是错的，再理解下
    print("rsp_xml_dict:", rsp_xml_dict)
    return [ dict2xmlstr(rsp_xml_dict) ]


def xcx_query_payresult_(environ, method, response, slug=''):
  '''
  在订单状态不明或者没有收到微信支付结果通知的情况下，建议商户主动调用微信支付结果查询。待实现主动查询!!!
  '''
  pass


# if __name__ == "__main__":
#   # xcx_login_()
#   # xcx_order_(environ, method, response, slug='')
#   # xcx_order_('', 'POST', '', '')
#   print('hello')

# if __name__ == "__main__":
    # print('hello')
    # xcx_order_('', 'POST', '', '')

from flask import Flask
app=Flask(__name__)

print(app)

@app.route('/')
def hello_world():
    return "hello world Flask"
if __name__ == '__main__':
    app.run('localhost',3000)