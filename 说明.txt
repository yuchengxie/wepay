
Web Service 用如下 3 个 path 发起小程序调用：

global_router = WSGIRouter( [
     ('/wx/xcx/login', xcx_login_),  # 小程序 - 登陆 
     ('/wx/xcx/order', xcx_order_),  # 小程序 - 下单
     ('/wx/xcx/payresult', xcx_payresult_),  # 小程序 - 支付结果通知
])
