#!/usr/bin/env python3
# _*_ coding: utf-8 _*_


"""
auth: bigger.wing
version:
function: 用于登录认证，返回成功认证后的session和token
          对于扫描器后续的所有动作都需要在cookie中带上session和token
usage:
note:

"""


import requests
# SSL为自签名证书，urllib3.disable_warnings用于去除ssl warning
requests.packages.urllib3.disable_warnings()
from module_get_config import get_config

config = get_config()
username = config['scanner']['username']
password = config['scanner']['password']


def get_cookie(scanner):
    url = 'https://' + scanner + '/accounts/login/?next=/'
    res = requests.get(url, verify=False)
    sessionid = res.cookies['sessionid']
    csrftoken = res.cookies['csrftoken']

    return {
        'sessionid': sessionid,
        'csrftoken': csrftoken,
    }


def ns_authentication(scanner):
    cookie_str = get_cookie(scanner=scanner)
    sessionid = cookie_str['sessionid']
    csrftoken = cookie_str['csrftoken']

    url = 'https://' + scanner + '/accounts/login_view/'

    headers = {
        'Referer': 'https://' + scanner + '/accounts/login/?next=/',
        'Cookie': 'sessionid=' + sessionid + '; csrftoken=' + csrftoken
    }

    data = {
        'username': username,
        'password': password,
        'csrfmiddlewaretoken': csrftoken
    }

    res = requests.post(url=url, headers=headers, data=data, verify=False)

    # 用于判断是否登录成功
    if '新建任务' and '任务列表' and '报表输出' in res.text:
        # sessionid一定要使用POST返回的值，不能使用第一次的sessionid
        # csrftoken是继承下来的值
        sessionid = res.cookies['sessionid']

        return {
            'sessionid': sessionid,
            'csrftoken': csrftoken,
            'msg': 'Authentication Successfully',
            'state_code': 1
        }
    else:
        return {
            'sessionid': sessionid,
            'csrftoken': csrftoken,
            'msg': 'Authentication Failed',
            'state_code': 0
        }


if __name__ == '__main__':
    scanner = '172.16.165.10'
    authentication = ns_authentication(scanner)
    print(authentication)