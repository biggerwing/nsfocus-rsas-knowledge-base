#!/usr/bin/env python3
# _*_ coding: utf-8 _*_


"""
auth: bigger.wing
version: 
function: 
usage: 
note: 本地下载后的解析和在线解析有一点区别
      本地下载后的解析，源文件中多出了tbody标签
      在线解析的，源文件中无tbody标签
"""


import json
import requests
import pymysql
from nsfocus_auth import ns_authentication
requests.packages.urllib3.disable_warnings()
from multiprocessing.dummy import Pool as ThreadPool
from bs4 import BeautifulSoup as bsp
from module_crawl_to_db import crawl_to_db
from module_get_config import get_config


# 扫描器登录认证
config = get_config()
scanner = config['scanner']['host']
authentication = ns_authentication(scanner)


def get_vul_data(id):
    sessionid = authentication['sessionid']
    csrftoken = authentication['csrftoken']
    left_menustatue_NSFOCUSRSAS = '3|0|https://' + scanner + '/template/index/'

    url = 'https://' + scanner + '/template/show_vul_desc'
    params = {'id': id}

    headers = {
        'Cookie': 'sessionid=' + sessionid + '; csrftoken=' + csrftoken + '; left_menustatue_NSFOCUSRSAS=' + left_menustatue_NSFOCUSRSAS
    }

    res = requests.get(url=url, params=params, headers=headers, verify=False)

    if res.text:
        result = {
            'id': id,
            'content': res.text,
            'vul_url': res.url,
            'status_code': 1,
            'msg': 'Found'
        }
    else:
        result = {
            'id': id,
            'content': '',
            'vul_url': res.url,
            'status_code': 0,
            'msg': 'NOT Found'
        }

    return result


def get_vul_detail(id):
    vul_detail = {'id': id}

    data = get_vul_data(id)

    if data['status_code'] == 1:
        content = data['content']
    try:
        res = bsp(content, 'html.parser')           # html.parser参数用于去除warning

        # 获取漏洞风险等级
        img = res.table.td.img.get('src')
        vul_risk_icon = list(img.split('/'))[-1]
        if 'vuln_high.gif' == vul_risk_icon:
            vul_risk = 'high'
        elif 'vuln_middle.gif' in vul_risk_icon:
            vul_risk = 'middle'
        elif 'vuln_low.gif' in vul_risk_icon:
            vul_risk = 'low'
        else:
            pass

        vul_detail.update({'风险等级': vul_risk})

        # tr下面的内容以k:v的形式输出
        vul_desc = res.table.find_all('tr')
        for item in vul_desc:
            name = item.th.get_text().strip()
            value = item.td.get_text().strip()
            result = {name: value}
            vul_detail.update(result)

        # print(json.dumps(vul_detail, indent=4, ensure_ascii=False))
        print(vul_detail)
        crawl_to_db(vul_detail)

    except:
        pass


def get_new_list():
    hostname = config['database']['host']
    username = config['database']['username']
    password = config['database']['password']
    conn = pymysql.connect(
        host=hostname,
        user=username,
        password=password,
        db='gaea',
        charset='utf8mb4'
    )

    cursor = conn.cursor()

    sql = "select vul_id from vul_detail"
    cursor.execute(sql)
    result = cursor.fetchall()
    all_list = list(range(1000, 120000))
    for x in result:
        all_list.remove(int(x[0]))

    return all_list


if __name__ == '__main__':
    # 获取扫描线程。因扫描器本身性能问题，线程数不能设置过大，否则会导致扫描器卡死
    # 建议在空闲的时候爬
    thread = get_config()['scanner']['thread']

    # 获取需要增量更新的id
    # ids = list(range(100001, 100005))
    ids = get_new_list()

    # 多线程爬取
    pool = ThreadPool(thread)
    pool.map(get_vul_detail, ids)