from tempmail import EMail
import requests
import hashlib
import string
import random
import json
import uuid
import time
import re
import os
def md5(input_string):
    return hashlib.md5(input_string.encode()).hexdigest()
def get_sign(xid, t):
    e = [
        {"alg": "md5", "salt": "KHBJ07an7ROXDoK7Db"},
        {"alg": "md5", "salt": "G6n399rSWkl7WcQmw5rpQInurc1DkLmLJqE"},
        {"alg": "md5", "salt": "JZD1A3M4x+jBFN62hkr7VDhkkZxb9g3rWqRZqFAAb"},
        {"alg": "md5", "salt": "fQnw/AmSlbbI91Ik15gpddGgyU7U"},
        {"alg": "md5", "salt": "/Dv9JdPYSj3sHiWjouR95NTQff"},
        {"alg": "md5", "salt": "yGx2zuTjbWENZqecNI+edrQgqmZKP"},
        {"alg": "md5", "salt": "ljrbSzdHLwbqcRn"},
        {"alg": "md5", "salt": "lSHAsqCkGDGxQqqwrVu"},
        {"alg": "md5", "salt": "TsWXI81fD1"},
        {"alg": "md5", "salt": "vk7hBjawK/rOSrSWajtbMk95nfgf3"}
    ]
    md5_hash = f"YvtoWO6GNHiuCl7xundefinedmypikpak.com{xid}{t}"
    for item in e:
        md5_hash += item["salt"]
        md5_hash = md5(md5_hash)
    return md5_hash
# 网络请求函数
def init(xid, mail, change_ip):
    url = 'http://user.mypikpak.com/v1/shield/captcha/init'
    body = {
        "client_id": "YvtoWO6GNHiuCl7x",
        "action": "POST:/v1/auth/verification",
        "device_id": xid,
        "captcha_token": "",
        "meta": {
            "email": mail
        }
    }
    headers = {
        'host': 'user.mypikpak.com',
        'content-length': str(len(json.dumps(body))),
        'accept': '*/*',
        'accept-encoding': 'gzip, deflate, br',
        'referer': 'https://pc.mypikpak.com',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'cross-site',
        'user-agent': 'MainWindow Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) '
                      'PikPak/2.3.2.4101 Chrome/100.0.4896.160 Electron/18.3.15 Safari/537.36',
        'accept-language': 'zh-CN',
        'content-type': 'application/json',
        'sec-ch-ua': '" Not A;Brand";v="99", "Chromium";v="100"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'x-client-id': 'YvtoWO6GNHiuCl7x',
        'x-client-version': '2.3.2.4101',
        'x-device-id': xid,
        'x-device-model': 'electron%2F18.3.15',
        'x-device-name': 'PC-Electron',
        'x-device-sign': 'wdi10.ce6450a2dc704cd49f0be1c4eca40053xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
        'x-net-work-type': 'NONE',
        'x-os-version': 'Win32',
        'x-platform-version': '1',
        'x-protocol-version': '301',
        'x-provider-name': 'NONE',
        'x-sdk-version': '6.0.0',
        'X-Forwarded-For': str(change_ip)
    }
    response = requests.post(url, json=body, headers=headers)
    print(response.text)
    response_data = response.json()
    if 'url' in response_data:
        print('初始安全验证中......')
        return response_data
    else:
        print('邮箱或者IP频繁,请更换IP或者稍后重试......')
        raise Exception(response_data.get('error_description', 'Unknown error'))
def get_new_token(result, xid, captcha, change_ip):
    traceid = result['traceid']
    pid = result['pid']
    header = {'X-Forwarded-For': str(change_ip)}
    response2 = requests.get(
        f"http://user.mypikpak.com/credit/v1/report?deviceid={xid}&captcha_token={captcha}&type"
        f"=pzzlSlider&result=0&data={pid}&traceid={traceid}", headers=header)
    response_data = response2.json()
    print('获取验证TOKEN中......')
    return response_data
def verification(captcha_token, xid, mail, change_ip):
    url = 'http://user.mypikpak.com/v1/auth/verification'
    body = {
        "email": mail,
        "target": "ANY",
        "usage": "REGISTER",
        "locale": "zh-CN",
        "client_id": "YvtoWO6GNHiuCl7x"
    }
    headers = {
        'host': 'user.mypikpak.com',
        'content-length': str(len(json.dumps(body))),
        'accept': '*/*',
        'accept-encoding': 'gzip, deflate, br',
        'referer': 'https://pc.mypikpak.com',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'cross-site',
        'user-agent': 'MainWindow Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) '
                      'PikPak/2.3.2.4101 Chrome/100.0.4896.160 Electron/18.3.15 Safari/537.36',
        'accept-language': 'zh-CN',
        'content-type': 'application/json',
        'sec-ch-ua': '" Not A;Brand";v="99", "Chromium";v="100"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'x-captcha-token': captcha_token,
        'x-client-id': 'YvtoWO6GNHiuCl7x',
        'x-client-version': '2.3.2.4101',
        'x-device-id': xid,
        'x-device-model': 'electron%2F18.3.15',
        'x-device-name': 'PC-Electron',
        'x-device-sign': 'wdi10.ce6450a2dc704cd49f0be1c4eca40053xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
        'x-net-work-type': 'NONE',
        'x-os-version': 'Win32',
        'x-platform-version': '1',
        'x-protocol-version': '301',
        'x-provider-name': 'NONE',
        'x-sdk-version': '6.0.0',
        'X-Forwarded-For': str(change_ip)
    }

    response = requests.post(url, json=body, headers=headers)
    response_data = response.json()
    print('发送验证码中......')
    return response_data
def verify(xid, verification_id, code, change_ip):
    url = 'http://user.mypikpak.com/v1/auth/verification/verify'
    body = {
        "verification_id": verification_id,
        "verification_code": code,
        "client_id": "YvtoWO6GNHiuCl7x"
    }
    headers = {
        'host': 'user.mypikpak.com',
        'content-length': str(len(json.dumps(body))),
        'accept': '*/*',
        'accept-encoding': 'gzip, deflate, br',
        'referer': 'https://pc.mypikpak.com',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'cross-site',
        'user-agent': 'MainWindow Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) '
                      'PikPak/2.3.2.4101 Chrome/100.0.4896.160 Electron/18.3.15 Safari/537.36',
        'accept-language': 'zh-CN',
        'content-type': 'application/json',
        'sec-ch-ua': '" Not A;Brand";v="99", "Chromium";v="100"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'x-client-id': 'YvtoWO6GNHiuCl7x',
        'x-client-version': '2.3.2.4101',
        'x-device-id': xid,
        'x-device-model': 'electron%2F18.3.15',
        'x-device-name': 'PC-Electron',
        'x-device-sign': 'wdi10.ce6450a2dc704cd49f0be1c4eca40053xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
        'x-net-work-type': 'NONE',
        'x-os-version': 'Win32',
        'x-platform-version': '1',
        'x-protocol-version': '301',
        'x-provider-name': 'NONE',
        'x-sdk-version': '6.0.0',
        'X-Forwarded-For': str(change_ip)
    }
    response = requests.post(url, json=body, headers=headers)
    response_data = response.json()
    print('验证码验证结果中......')
    return response_data
def signup(xid, mail, code, verification_token, change_ip):
    url = 'http://user.mypikpak.com/v1/auth/signup'
    body = {
        "email": mail,
        "verification_code": code,
        "verification_token": verification_token,
        "password": "QWer123..",
        "client_id": "YvtoWO6GNHiuCl7x"
    }
    headers = {
        'host': 'user.mypikpak.com',
        'content-length': str(len(json.dumps(body))),
        'accept': '*/*',
        'accept-encoding': 'gzip, deflate, br',
        'referer': 'http://pc.mypikpak.com',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'cross-site',
        'user-agent': 'MainWindow Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) '
                      'PikPak/2.3.2.4101 Chrome/100.0.4896.160 Electron/18.3.15 Safari/537.36',
        'accept-language': 'zh-CN',
        'content-type': 'application/json',
        'sec-ch-ua': '" Not A;Brand";v="99", "Chromium";v="100"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'x-client-id': 'YvtoWO6GNHiuCl7x',
        'x-client-version': '2.3.2.4101',
        'x-device-id': xid,
        'x-device-model': 'electron%2F18.3.15',
        'x-device-name': 'PC-Electron',
        'x-device-sign': 'wdi10.ce6450a2dc704cd49f0be1c4eca40053xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
        'x-net-work-type': 'NONE',
        'x-os-version': 'Win32',
        'x-platform-version': '1',
        'x-protocol-version': '301',
        'x-provider-name': 'NONE',
        'x-sdk-version': '6.0.0',
        'X-Forwarded-For': str(change_ip)
    }
    response = requests.post(url, json=body, headers=headers)
    response_data = response.json()
    print('验证注册结果中......')
    return response_data
def init1(xid, access_token, sub, sign, t, change_ip):
    url = 'https://user.mypikpak.com/v1/shield/captcha/init'
    body = {
        "client_id": "YvtoWO6GNHiuCl7x",
        "action": "POST:/vip/v1/activity/invite",
        "device_id": xid,
        "captcha_token": access_token,
        "meta": {
            "captcha_sign": "1." + sign,
            "client_version": "undefined",
            "package_name": "mypikpak.com",
            "user_id": sub,
            "timestamp": t
        },
    }
    headers = {
        'host': 'user.mypikpak.com',
        'content-length': str(len(json.dumps(body))),
        'accept': '*/*',
        'accept-encoding': 'gzip, deflate, br',
        'accept-language': 'zh-CN',
        'referer': 'https://pc.mypikpak.com',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'cross-site',
        'user-agent': 'MainWindow Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) '
                      'PikPak/2.3.2.4101 Chrome/100.0.4896.160 Electron/18.3.15 Safari/537.36',
        'content-type': 'application/json',
        'sec-ch-ua': '" Not A;Brand";v="99", "Chromium";v="100"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'x-client-id': 'YvtoWO6GNHiuCl7x',
        'x-client-version': '2.3.2.4101',
        'x-device-id': xid,
        'x-device-model': 'electron%2F18.3.15',
        'x-device-name': 'PC-Electron',
        'x-device-sign': 'wdi10.ce6450a2dc704cd49f0be1c4eca40053xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
        'x-net-work-type': 'NONE',
        'x-os-version': 'Win32',
        'x-platform-version': '1',
        'x-protocol-version': '301',
        'x-provider-name': 'NONE',
        'x-sdk-version': '6.0.0',
        'X-Forwarded-For': str(change_ip)
    }

    response = requests.post(url, json=body, headers=headers)
    response_data = response.json()
    print('通过二次安全验证中......')
    return response_data
def invite(access_token, captcha_token, xid, change_ip):
    url = 'https://api-drive.mypikpak.com/vip/v1/activity/invite'
    body = {
        "apk_extra": {
            "invite_code": ""
        }
    }
    headers = {
        'host': 'api-drive.mypikpak.com',
        'content-length': str(len(json.dumps(body))),
        'accept': '*/*',
        'accept-encoding': 'gzip, deflate, br',
        'accept-language': 'zh-CN',
        'authorization': 'Bearer ' + access_token,
        'referer': 'https://pc.mypikpak.com',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'cross-site',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) PikPak/2.3.2.4101 '
                      'Chrome/100.0.4896.160 Electron/18.3.15 Safari/537.36',
        'content-type': 'application/json',
        'sec-ch-ua': '" Not A;Brand";v="99", "Chromium";v="100"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'x-captcha-token': captcha_token,
        'x-client-id': 'YvtoWO6GNHiuCl7x',
        'x-client-version': '2.3.2.4101',
        'x-device-id': xid,
        'x-system-language': 'zh-CN',
        'X-Forwarded-For': str(change_ip)
    }
    response = requests.post(url, json=body, headers=headers)
    response_data = response.json()
    print('确认邀请')
    return response_data
def init2(xid, access_token, sub, sign, t, change_ip):
    url = 'https://user.mypikpak.com/v1/shield/captcha/init'
    body = {
        "client_id": "YvtoWO6GNHiuCl7x",
        "action": "post:/vip/v1/order/activation-code",
        "device_id": xid,
        "captcha_token": access_token,
        "meta": {
            "captcha_sign": "1." + sign,
            "client_version": "undefined",
            "package_name": "mypikpak.com",
            "user_id": sub,
            "timestamp": t,
        },
    }
    headers = {
        'host': 'user.mypikpak.com',
        'content-length': str(len(json.dumps(body))),
        'accept': '*/*',
        'accept-encoding': 'gzip, deflate, br',
        'accept-language': 'zh-CN',
        'referer': 'https://pc.mypikpak.com',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'cross-site',
        'user-agent': 'MainWindow Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) '
                      'PikPak/2.3.2.4101 Chrome/100.0.4896.160 Electron/18.3.15 Safari/537.36',
        'content-type': 'application/json',
        'sec-ch-ua': '" Not A;Brand";v="99", "Chromium";v="100"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'x-client-id': 'YvtoWO6GNHiuCl7x',
        'x-client-version': '2.3.2.4101',
        'x-device-id': xid,
        'x-device-model': 'electron%2F18.3.15',
        'x-device-name': 'PC-Electron',
        'x-device-sign': 'wdi10.ce6450a2dc704cd49f0be1c4eca40053xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
        'x-net-work-type': 'NONE',
        'x-os-version': 'Win32',
        'x-platform-version': '1',
        'x-protocol-version': '301',
        'x-provider-name': 'NONE',
        'x-sdk-version': '6.0.0',
        'X-Forwarded-For': str(change_ip)
    }

    response = requests.post(url, json=body, headers=headers)
    response_data = response.json()
    print('通过三次次安全验证中.......')
    return response_data
def activation_code(access_token, captcha, xid, in_code, change_ip):
    url = 'http://api-drive.mypikpak.com/vip/v1/order/activation-code'
    body = {
        "activation_code": in_code,
        "page": "invite"
    }
    headers = {
        'host': 'api-drive.mypikpak.com',
        'content-length': str(len(json.dumps(body))),
        'accept': '*/*',
        'accept-encoding': 'gzip, deflate, br',
        'accept-language': 'zh-CN',
        'authorization': 'Bearer ' + access_token,
        'referer': 'https://pc.mypikpak.com',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'cross-site',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) PikPak/2.3.2.4101 '
                      'Chrome/100.0.4896.160 Electron/18.3.15 Safari/537.36',
        'content-type': 'application/json',
        'sec-ch-ua': '" Not A;Brand";v="99", "Chromium";v="100"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'x-captcha-token': captcha,
        'x-client-id': 'YvtoWO6GNHiuCl7x',
        'x-client-version': '2.3.2.4101',
        'x-device-id': xid,
        'x-system-language': 'zh-CN',
        'X-Forwarded-For': str(change_ip)
    }
    response = requests.post(url, json=body, headers=headers)
    response_data = response.json()
    print('开始填写你的邀请码......')
    print(json.dumps(response_data, indent=4))
    return response_data
def choose_email(EMAIL_CHOSSE):
    # 如果EMAIL_CHOSSE等于1，则创建一个EMail对象，并打印出邮箱地址
    if EMAIL_CHOSSE == 1:
        email = EMail()
        print(f'邮箱：{str(email)}')
        return email
    # 如果EMAIL_CHOSSE等于2，则调用requests库的post方法，向服务器发送请求，创建一个新的邮箱
    elif EMAIL_CHOSSE == 2:
        json_data = {
            "min_name_length": 10,
            "max_name_length": 10
        }
        url = 'https://api.internal.temp-mail.io/api/v3/email/new'
        response = requests.post(url, json=json_data)
        response_data = response.json()
        mail = response_data['email']
        print(f'获取邮箱:{mail}')
        return mail
    # 如果EMAIL_CHOSSE等于3，则使用random库生成一个随机邮箱
    elif EMAIL_CHOSSE == 3:
        mail = ''.join(random.choices(string.ascii_lowercase + string.digits, k=10))
        mail = str(mail)+'@isco.eu.org'
        print(f'获取邮箱:{mail}')
        return mail
    # 如果EMAIL_CHOSSE等于4，则使用str方法将EMail对象转换为字符串，并分割@符号，取第一个值作为用户名，剩余值作为邮箱名
    elif EMAIL_CHOSSE == 4:
        name = str(EMail()).split('@')[0]
        # user是邮箱@前面的字符，例如我的是zsan60591@gmail.com
        user = 'zsan60591'
        mail = user+'+'+name+'@gmail.com'
        print(f'获取邮箱:{mail}')
        return mail
    elif EMAIL_CHOSSE == 5:
        name = str(EMail()).split('@')[0]
        # user是邮箱@前面的字符，例如我的是zsan60591@gmail.com
        user = 'zsan60591'
        mail = user + "+" + name + "@outlook.com"
        print(f'获取邮箱:{mail}')
        return mail
    # 如果EMAIL_CHOSSE不等于1、2、3、4，则打印出提示信息
    else:
        exit()
        return None
def get_emailcode(EMAIL_CHOSSE, mail, max_retries=10, delay=1):
    '''
    根据EMAIL_CHOSSE的值获取对应邮箱的验证码
    :param EMAIL_CHOSSE: 1为使用SMTP服务获取验证码，2为使用Temp-mail获取验证码，3为使用Sunls获取验证码，4为手动输入
    :param mail: 邮箱地址
    :param max_retries: 最大重试次数
    :param delay: 每次重试的延迟时间
    :return: 返回获取到的验证码
    '''
    if EMAIL_CHOSSE == 1:
        msg = mail.wait_for_message(timeout=60000)
        rule = r'<h2>(.*?)</h2>'
        code = re.findall(rule, str(msg))[0]
        print(f'获取邮箱验证码:{code}')
        return code
    elif EMAIL_CHOSSE == 2:
        retries = 0
        while retries < max_retries:
            url = f'https://api.internal.temp-mail.io/api/v3/email/{mail}/messages'
            response = requests.get(url)
            html = response.json()
            if html:
                text = (html[0])['body_text']
                code = re.search('\\d{6}', text).group()
                print(f'获取邮箱验证码:{code}')
                return code
            else:
                time.sleep(delay)
                retries += 1
        print("获取邮箱邮件内容失败，未收到邮件...")
        return None
    elif EMAIL_CHOSSE == 3:
        retries = 0
        while retries < max_retries:
            response = requests.get(f"https://mail.sunls.de/api/mail?to={mail}")
            mails = response.json()
            for mail in mails:
                if mail["from"]["address"] == "noreply@accounts.mypikpak.com":
                    uid = mail["uid"]
                    break
            else:
                time.sleep(delay)
                retries += 1
                continue
            detail_response = requests.get(f"https://mail.sunls.de/api/detail?uid={uid}")
            html_content = detail_response.json()["__html"]
            match = re.search(r'\b\d{6}\b', html_content)
            if match:
                verification_code = match.group()
                print(f'邮箱验证码 {verification_code}')
                return verification_code
            else:
                time.sleep(delay)
                retries += 1
        print("获取邮箱邮件内容失败，未收到邮件...")
        return None
    elif EMAIL_CHOSSE == 4:
        code = input('输入收到的验证码')
        return code
    else:
        exit()
        return None
def get_change_ip():
    m = random.randint(0, 255)
    n = random.randint(0, 255)
    x = random.randint(0, 255)
    y = random.randint(0, 255)
    randomIP = str(m) + '.' + str(n) + '.' + str(x) + '.' + str(y)
    return randomIP
def geturl(captcha_token, xid):
    url = f'https://user.pikpak.me/captcha/v2/spritePuzzle.html?action=POST:/v1/auth/verification&appName=NONE&appid=XBASE&captcha_token={captcha_token}&credittype=1&device_id={xid}&deviceid={xid}&event=xbase-auth-verification&hl=zh-CN&mainHost=user.pikpak.me&platformVersion=NONE&privateStyle=&traceid=&redirect_uri=https://mypikpak.com/loading&state=getcaptcha{str(int(time.time()*1000))}'
    return url
# 开始主进程
def main(incode, EMAIL_CHOOSE):
    # 开始计时
    try:
        change_ip = get_change_ip()
        # change_ip = '127.0.0.1'
        start_time = time.time()
        print(f'程序开始运行')
        # 生成唯一标识符
        xid = str(uuid.uuid4()).replace('-', '')
        # 选择邮箱
        email = choose_email(EMAIL_CHOOSE)
        mail = str(email)
        # 初始化
        Init = init(xid, mail, change_ip)
        captcha_token_info = geturl(Init['captcha_token'], xid)
        print(f'请在浏览器打开网址，然后手动过滑块然后复制过滑块过后的url里面的captcha_token ， 网址是：  {captcha_token_info}  ')
        captcha_token = input('请输入你获取的captcha_token:  ')
        # 验证
        Verification = verification(captcha_token, xid, mail, change_ip)
        # 获取邮箱验证码
        code = get_emailcode(EMAIL_CHOOSE, email)
        # 验证
        verification_response = verify(xid, Verification['verification_id'], code, change_ip)
        # 注册
        signup_response = signup(xid, mail, code, verification_response['verification_token'], change_ip)
        # 当前时间
        current_time = str(int(time.time()))
        # 获取签名
        sign = get_sign(xid, current_time)
        # 初始化1
        init1_response = init1(xid, signup_response['access_token'], signup_response['sub'], sign, current_time, change_ip)
        # 邀请
        invite(signup_response['access_token'], init1_response['captcha_token'], xid, change_ip)
        # 初始化2
        init2_response = init2(xid, signup_response['access_token'], signup_response['sub'], sign, current_time, change_ip)
        # 激活
        activation = activation_code(signup_response['access_token'], init2_response['captcha_token'], xid,
                                     incode, change_ip)
        # 结束计时
        end_time = time.time()
        run_time = f'{(end_time - start_time):.2f}'
        try:
            # 判断激活是否成功
            if activation['add_days'] == 5:
                print(f'邀请码: {incode} => 邀请成功, 运行时间: {run_time}秒')
                print(f'邀请邮箱: {mail}\n邮箱密码: QWer123..')
            elif activation['add_days'] == 0:
                print(f'邀请码: {incode} => 邀请失败, 运行时间: {run_time}秒')
            else:
                print(f'程序异常请重试!!!, 运行时间: {run_time}秒')
        except:
            print('检查你的邀请码是否有效!!!')
        # 等待用户按回车键
        input('按回车键再次邀请...')
        # 再次运行主函数
        main(incode, EMAIL_CHOOSE)
    # 捕获异常
    except Exception as e:
        print('异常捕获:', e)
        input('按回车键重试...')
        main(incode, EMAIL_CHOOSE)
        return 0
if __name__ == '__main__':
    print('作者：1930520970 白栀')
    print('赞助码：https://img.picui.cn/free/2024/06/21/6674e6ca74ab6.jpg')
    print('手动获取token版，使用请看运行提示，电信流量可以直接使用，其他的请连外网')
    print('请勿倒卖滥用')
    # 有三个邮箱接口,EMAIL_CHOOSE默认为1,自行测试!!!
    EMAIL_CHOOSE = 2
    # 获取用户输入的邀请码
    incode = input('请输入邀请码:')
    # 调用main函数，传入邀请码和EMAIL_CHOOSE变量
    main(incode, EMAIL_CHOOSE)
