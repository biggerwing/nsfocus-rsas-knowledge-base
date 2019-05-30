#!/usr/bin/env python3
# _*_ coding: utf-8 _*_


"""
auth: bigger.wing
version: 
function: 
usage: 
note: 数据库字段：
    vul_id          <--> id            爬取的链接ID，如https://172.16.165.10/template/show_vul_desc?id=390795
    risk_level      <--> 风险等级       绿盟定义的风险等级，高/中/低
    vul_name        <--> 漏洞名称       漏洞名称
    vul_desc        <--> 漏洞描述       漏洞的详细描述
    vul_solution    <--> 解决方法       漏洞修复解决办法
    danger_point    <--> 危险分值       漏洞评分
    danger_plugin   <--> 危险插件       是否是危险插件， 是/否
    first_found     <--> 发现日期       漏洞首次出现的日期
    cve_id          <--> CVE编号
    cnnvd_id        <--> CNNVD编号
    cncve_id        <--> CNCVE编号
    bugtraq_id      <--> BUGTRAQ
    nsfocus_id      <--> NSFOCUS
    cvss_point      <--> CVSS评分
    cnvd_id         <--> CNVD编号
"""


import json
import pymysql
from module_get_config import get_config


config = get_config()
hostname = config['database']['host']
username = config['database']['username']
password = config['database']['password']


def crawl_to_db(content):
    conn = pymysql.connect(
        host=hostname,
        user=username,
        password=password,
        db='gaea',
        charset='utf8mb4'
    )

    vul_id = content['id']
    risk_level = (content.get('风险等级') if content.get('风险等级') else '无')
    vul_name = content.get('漏洞名称')
    vul_desc = (content.get('漏洞描述') if content.get('漏洞描述') else '无')
    vul_solution = (content.get('解决方法') if content.get('解决方法') else '无')
    danger_point = (content.get('危险分值') if content.get('危险分值') else '无')
    danger_plugin = (content.get('危险插件') if content.get('危险插件') else '无')
    first_found = (content.get('发现日期') if content.get('发现日期') else '无')
    cve_id = (content.get('CVE编号') if content.get('CVE编号') else '无')
    cnnvd_id = (content.get('CNNVD编号') if content.get('CNNVD编号') else '无')
    cncve_id = (content.get('CNCVE编号') if content.get('CNCVE编号') else '无')
    bugtraq_id = (content.get('BUGTRAQ') if content.get('BUGTRAQ') else '无')
    nsfocus_id = (content.get('NSFOCUS') if content.get('NSFOCUS') else '无')
    cvss_point = (content.get('CVSS评分') if content.get('CVSS评分') else '无')
    cnvd_id = (content.get('CNVD编号') if content.get('CNVD编号') else '无')

    vul_detail = {
        'vul_id': vul_id,
        'risk_level': risk_level,
        'vul_name': vul_name,
        'vul_desc': vul_desc,
        'vul_solution': vul_solution,
        'danger_point': danger_point,
        'danger_plugin': danger_plugin,
        'first_found': first_found,
        'cve_id': cve_id,
        'cnnvd_id': cnnvd_id,
        'cncve_id': cncve_id,
        'bugtraq_id': bugtraq_id,
        'nsfocus_id': nsfocus_id,
        'cvss_point': cvss_point,
        'cnvd_id': cnvd_id
    }

    cursor = conn.cursor()

    # 数据库语句特殊符号转义
    db_format = pymysql.escape_string
    vul_name = db_format(vul_name)
    vul_desc = db_format(vul_desc)
    vul_solution = db_format(vul_solution)
    cve_id = db_format(cve_id)
    cnnvd_id = db_format(cnnvd_id)
    cncve_id = db_format(cncve_id)
    bugtraq_id = db_format(bugtraq_id)
    nsfocus_id = db_format(nsfocus_id)
    cvss_point = db_format(cvss_point)
    cnvd_id = db_format(cnvd_id)

    # 数据有则更新，没有则插入
    sql_update = "insert into vul_detail(vul_id, risk_level, vul_name, vul_desc, vul_solution, danger_point, danger_plugin, first_found, cve_id, cnnvd_id, cncve_id, bugtraq_id, nsfocus_id, cvss_point, cnvd_id) " \
                 "values ('%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s') " \
                 "on duplicate key update " \
                 "vul_id='%s', risk_level='%s', vul_name='%s', vul_desc='%s', vul_solution='%s', danger_point='%s', danger_plugin='%s', first_found='%s', cve_id='%s', cnnvd_id='%s', cncve_id='%s', bugtraq_id='%s', nsfocus_id='%s', cvss_point='%s', cnvd_id='%s'" \
                 % (vul_id, risk_level, vul_name, vul_desc, vul_solution, danger_point, danger_plugin, first_found, cve_id, cnnvd_id, cncve_id, bugtraq_id, nsfocus_id, cvss_point, cnvd_id,
                    vul_id, risk_level, vul_name, vul_desc, vul_solution, danger_point, danger_plugin, first_found, cve_id, cnnvd_id, cncve_id, bugtraq_id, nsfocus_id, cvss_point, cnvd_id)

    cursor.execute(sql_update)

    conn.commit()
    cursor.close()
    conn.close()

    return vul_detail


if __name__ == '__main__':
    vul_detail = {'id': '71845', '风险等级': 'high', '漏洞名称': 'AjaXplorer远程命令注入和本地文件泄露漏洞【原理扫描】', '漏洞描述': 'AjaXplorer可将任一Web服务器转换为文件管理系统，也是云存储提供者。\n\nAjaXplorer 2.6之前版本存在远程命令执行和本地文件泄露漏洞，攻击者可利用此漏洞在受影响应用中执行任意命令，并获取敏感信息。\n\n<*来源：Julien Cayssol\n  \n  链接：http://www.metasploit.com/modules/exploit/multi/http/ajaxplorer_checkinstall_exec\n*>', '解决方法': '厂商补丁：\n\nAjaXplorer\n----------\n目前厂商已经发布了升级补丁以修复这个安全问题，请到厂商的主页下载：\n\nhttp://ajaxplorer.info/', '危险分值': '8.0', '危险插件': '否', '发现日期': '2012-10-30', 'BUGTRAQ': '39334', 'NSFOCUS': '21312'}

    result = crawl_to_db(vul_detail)
    print(result)
