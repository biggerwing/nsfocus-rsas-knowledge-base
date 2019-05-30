#!/usr/bin/env python3
# _*_ coding: utf-8 _*_


"""
auth: bigger.wing@gmail.com
version: 
function: 获取配置
usage: 
note: 
"""



import json
import os


current_abs_path = os.path.abspath(__file__)
current_abs_path_dir = os.path.dirname(current_abs_path)
config_path = os.path.abspath(current_abs_path_dir) + '/config/config.json'


def get_config(file=config_path):

    with open(file, 'r') as config:
        contents = config.read()
        data = json.loads(contents)
        return data


if __name__ == '__main__':
    result = get_config()
    print(json.dumps(result, indent=4, ensure_ascii=False))
    print(result['database']['username'])
    print(result['nmap']['host_scan']['rate'])
    print(result['masscan']['rate'])
    print(result['scanner']['username'])
    print(result['scanner']['password'])


