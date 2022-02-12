#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2022/2/10
# @Author  : starnight_cyber
# @Github  : https://github.com/starnightcyber
# @Software: PyCharm
# @File    : sample.py

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import ssl
import time
from Nessus import Nessus

# Do not support ssl and disable warning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
ssl._create_default_https_context = ssl._create_unverified_context
timestamp = time.strftime("%Y-%m-%d", time.localtime(time.time()))


if __name__ == '__main__':
    # replace your scanner url, ak/sk
    url = 'https://127.0.0.1:8834'.strip('/')
    ak = 'input_ak'
    sk = 'input_sk'
    nessus = Nessus(url, ak, sk)
    # eg. 全局操作
    nessus.show()
    # nessus.clear_all()
    # exit()

    # eg.目录操作
    # nessus.list_folders()
    # nessus.create_folder('input_folder_name')
    # time.sleep(2)
    # nessus.list_folders()
    # nessus.delete_folder(358)
    # nessus.clear_all_folders()

    # eg. 扫描策略
    # nessus.get_scan_policies()

    # eg. 扫描器
    # nessus.get_scanners()

    # eg. 扫描操作，创建扫描任务
    # nessus.get_all_scans()
    # targets = '114.114.114.114'
    # nessus.create_scan(targets, policy_id=8)
    # nessus.create_scan(targets, name='scan_task_no_1', policy_id=8)
    # nessus.create_scan(targets, name='scan_task_no_2', description='routine scan task', folder_id=283, policy_id=8)
    # nessus.create_scan(targets, name='scan_task_no_3', description='routine scan task', folder_id=283, policy_id=8)
    # nessus.launch_scan(261)
    # nessus.launch_all_scan()

    # eg. 扫描操作，停止和删除任务
    # nessus.stop_scan(306)
    # # 停止扫码，nessus 节点需要一点时间反应
    # time.sleep(15)
    # nessus.delete_scan(306)

    # eg.获取扫描结果，导出扫描报告
    # nessus.get_scan_detail(354)
    # nessus.export_scan_result(354)

