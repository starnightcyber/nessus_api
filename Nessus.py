#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2022/2/9
# @Author  : starnight_cyber
# @Github  : https://github.com/starnightcyber
# @Software: PyCharm
# @File    : Nessus.py
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import json
import time
import pandas as pd
import ssl
from prettytable import PrettyTable
import random

# Do not support ssl and disable warning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
ssl._create_default_https_context = ssl._create_unverified_context


def gen_random_str(str_len=6):
    '''
    生成小写字符和数字的随机组合字符串，默认 6 位
    Gen 6 bits random string of small letter and digit combination by default
    :param str_len: random string length
    :return: 6 bits random string  by default
    '''
    random_str = ""
    for i in range(str_len):
        temp = random.randrange(0, 99)
        if temp % 2 == 0:
            ch = chr(random.randrange(ord('a'), ord('z') + 1))
            random_str += ch
        else:
            ch = str((random.randrange(0, 10)))
            random_str += ch
    return random_str


class Nessus:
    def __init__(self, url='', ak='', sk=''):
        '''
        初始化 Nessus 扫描节点，需要填入扫描器 URL, rest api ak/sk 信息，才能调用
        Inint nessus scanner with url, rest api ak/sk;
        :param url: nessus scanner url
        :param ak: rest api ak
        :param sk: rest api ak
        '''
        # 填充扫描器地址和 AK/SK 参数
        # fill the scanner parameters
        self.url = url.strip('/')
        self.ak = ak
        self.sk = sk
        # 通用头部，需配置Header: X-ApiKeys(AK/SK), Content-Type
        self.headers = {
            'X-ApiKeys': 'accessKey={}; secretKey={};'.format(self.ak, self.sk),
            'Content-Type': 'application/json',
            'Accept-Encoding': 'gzip, deflate',
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:96.0) Gecko/20100101 Firefox/96.0'
        }
        # 预留：时间戳格式，创建任务时可先创建一个默认的时间格式的 folder
        self.timestamp = time.strftime("%Y-%m-%d", time.localtime(time.time()))
        # 预留：一些数据信息方便调用
        # 当前 nessus console 存在的 folders 信息
        self.folders = {}
        # 当前 nessus console 存在的扫描任务 scan_ids 信息, 从 scan_id -> (scan_name, scan_status) 的一个 tuple
        self.scans = {}

    def list_folders(self):
        '''
        获取当前 nessus scanner console 的 folders 信息
        List all the folders in nessus scanner console
        :return: None
        '''
        print('[*] list_folders ...')
        # GET /folders
        url = '{}/{}'.format(self.url, 'folders')
        try:
            resp = requests.get(url=url, headers=self.headers, verify=False)
            # print(json.dumps(json.loads(resp.content), indent=4, ensure_ascii=False))
            resp_json = json.loads(resp.content)
            # 构造一个 folder table，获取对应的字段进行填充
            t = PrettyTable(['folder_id', 'name', 'type', 'custom'])
            for folder in resp_json['folders']:
                folder_id = folder['id']
                folder_name = folder['name']
                folder_type = folder['type']
                custom = folder['custom']
                t.add_row([folder_id, folder_name, folder_type, custom])
                # 保存 folders 信息
                self.folders[folder_id] = folder_name
            print(t)
        except Exception as e:
            print(str(e))

    def create_folder(self, folder_name=''):
        '''
        创建一个任务目录，便于管理
        To create a folder for better management
        :param folder_name: give a name to the folder, default will be timestamp to indicate the create time
        :return: None
        '''
        print('[*] create_folder ...')
        # POST /folders
        url = '{}/{}'.format(self.url, 'folders')
        # prepare the folder_name
        if folder_name == '' or folder_name == 'input_folder_name':
            folder_name = self.timestamp
        data = {
            'name': folder_name
        }
        try:
            resp = requests.post(url=url, headers=self.headers,
                                 data=json.dumps(data, ensure_ascii=False).encode("utf-8"), verify=False)
            if resp.status_code == 200:
                print('[+] Folder {} created ...'.format(folder_name))
            else:
                print(str(resp.content))
        except Exception as e:
            print(str(e))

    def delete_folder(self, folder_id):
        '''
        删除指定任务目录
        Delete a given folder id
        :param folder_id: folder_id
        :return: None
        '''
        # check whether the folder exists
        if folder_id not in self.folders.keys():
            print('[-] The [No.{}] folder_id is not exists ...'.format(folder_id))
            exit()

        print('[*] delete_folder ... [No.{}]'.format(folder_id))
        # DELETE /folders/{folder_id}
        url = '{}/{}/{}'.format(self.url, 'folders', folder_id)
        # print('url => {}'.format(url))
        try:
            resp = requests.delete(url=url, headers=self.headers, verify=False)
            if resp.status_code == 200:
                print('[*] Folder [No.{0}] - [{1}] deleted ...'.format(folder_id, self.folders[folder_id]))
            else:
                print(str(resp.content))
        except Exception as e:
            print(str(e))
        finally:
            del self.folders[folder_id]
            pass

    def clear_all_folders(self):
        '''
        删除所有的任务目录，默认系统目录无法删除，可删除用户创建的
        Delete all the folders for clean, only custom folder can be deleted
        :return: None
        '''
        print('[*] clear_all_folders ...')
        # 只有 type: custom 的 folder 才能被删除，系统默认自带的无法删除
        for folder_id in list(self.folders.keys()):
            self.delete_folder(folder_id)
        self.folders = {}

    def get_scanners(self):
        '''
        获取 nessus scanner 信息
        Get nessus scanner information
        :return: None
        '''
        print('[*] get_scanners ...')
        url = '{}/{}'.format(self.url, 'scanners')
        # print('url => {}'.format(url))
        try:
            resp = requests.get(url=url, headers=self.headers, verify=False)
            # print(json.dumps(json.loads(resp.content), indent=4, ensure_ascii=False))
            if resp.status_code == 200:
                t = PrettyTable(
                    ['name', 'type', 'platform', 'ui_version', 'engine_version', 'expiration_date'])
                for scanner in json.loads(resp.content)['scanners']:
                    t.add_row([scanner['license']['name'], scanner['license']['type'], scanner['platform'],
                               scanner['ui_version'], scanner['engine_version'], scanner['license']['expiration_date']])
                print(t)
            else:
                print(str(resp.content))
        except Exception as e:
            print(str(e))

    def get_all_scans(self):
        '''
        获取所有扫描任务信息
        retrieve all the scans
        :return: None
        '''
        print('[*] get_all_scans ...')
        # GET /scans
        url = '{}/{}'.format(self.url, 'scans')
        # print('url => {}'.format(url))
        try:
            resp = requests.get(url=url, headers=self.headers, verify=False)
            if resp.status_code == 200 and json.loads(resp.content)['scans'] is not None:
                # print(json.dumps(json.loads(resp.content)['scans'], indent=4, ensure_ascii=False))
                # 构造一个扫描任务 table，获取对应的字段进行填充
                t = PrettyTable(['folder_id', 'folder_name', 'scan_id', 'task_name', 'status', 'creation_date',
                                 'last_modification_date', 'scan_task_uuid'])
                for scan in json.loads(resp.content)['scans']:
                    creation_date = time.strftime("%Y-%m-%d %H:%M:%S",
                                                           time.localtime(scan['creation_date']))
                    last_modification_date = time.strftime("%Y-%m-%d %H:%M:%S",
                                                           time.localtime(scan['last_modification_date']))
                    folder_name = self.folders[scan['folder_id']]
                    t.add_row([scan['folder_id'], folder_name, scan['id'], scan['name'], scan['status'],
                               creation_date, last_modification_date, scan['uuid']])
                    # 单独保存 scan_id 信息，从 scan_id -> (scan_name, scan_status) 的一个 tuple
                    self.scans[scan['id']] = (scan['name'], scan['status'])
                print(t)
            else:
                print('[-] No scan tasks ...')
        except Exception as e:
            print(str(e))

    def get_scan_policies(self):
        '''
        获取所有自定义扫描策略
        Get self-defined scan policies
        :return: None
        '''
        print('[*] get_scan_policies ...')
        # GET /policies
        url = '{}/{}'.format(self.url, 'policies')
        # print('url => {}'.format(url))
        try:
            resp = requests.get(url=url, headers=self.headers, verify=False)
            if resp.status_code == 200:
                # print(json.dumps(json.loads(resp.content)['policies'], indent=4, ensure_ascii=False))
                # 构造一个扫描策略 policy table，获取对应的字段进行填充
                t = PrettyTable(['policy_id', 'name', 'owner', 'visibility', 'last_modification_date', 'description', 'policy_uuid'])
                for policy in json.loads(resp.content)['policies']:
                    last_modification_date = time.strftime("%Y-%m-%d", time.localtime(policy['last_modification_date']))
                    t.add_row([policy['id'], policy['name'], policy['owner'], policy['visibility'],
                               last_modification_date, policy['description'], policy['template_uuid']])
                print(t)
            else:
                print(str(resp.content))
        except Exception as e:
            print(str(e))

    def create_scan(self, targets, name='nessus scan', description='nessus', folder_id='', policy_id='8'):
        '''
        创建扫描任务，需至少填充扫描策略参数，建议备注清楚 name 及其它参数
        Create a scan, must set policy_id parameter to specify the scan policy
        :param targets: scan target ips
        :param name: scan task name
        :param description: scan task description
        :param folder_id: put the task to folder_id
        :param policy_id: using which scan policy
        :return: None
        '''
        print('[*] create_scan ...')
        # POST /scans
        url = '{}/{}'.format(self.url, 'scans')
        # print('url => {}'.format(url))
        # nesssus 创建任务时，使用 burpsuite 抓个包，就是需要填充的数据字段
        data = {
            "uuid": "ad629e16-03b6-8c1d-cef6-ef8c9dd3c658d24bd260ef5f9e66",
            "settings": {
                # "emails": "",
                # "filter_type": "and",
                # "filters": [],
                "launch_now": 'true',      # 是否立即执行，设置为 true 则直接执行，否则只创建任务
                "name": name,
                "description": description,
                "folder_id": folder_id,     # 没有设置 folder_id, 则在 All Scans 可以看到
                "scanner_id": "1",
                "policy_id": policy_id,
                "text_targets": targets,
                # "file_targets": ""
            }
        }
        try:
            resp = requests.post(url=url, headers=self.headers,
                                 data=json.dumps(data, ensure_ascii=False).encode("utf-8"), verify=False)
            if resp.status_code == 200:
                # print(json.dumps(json.loads(resp.content), indent=4, ensure_ascii=False))
                # 创建扫描任务成功，输出 scan_id 和 uuid
                scan_id = json.loads(resp.content)['scan']['id']
                uuid = json.loads(resp.content)['scan']['uuid']
                print('[+] Scan [No.{}] -- {} created succeed ...'.format(scan_id, uuid))
            else:
                print(str(resp.content))
        except Exception as e:
            print(str(e))

    def launch_scan(self, scan_id):
        '''
        启动扫描任务，指定扫描任务 ID 即可
        Launch a scan with a specific scan_id
        :param scan_id: launch a scan scan_id
        :return: None
        '''
        print('[*] launch_scan ...')
        # POST /scans/{scan_id}/launch
        url = '{}/{}'.format(self.url, 'scans/{}/launch'.format(scan_id))
        # print('url => {}'.format(url))
        try:
            resp = requests.post(url=url, headers=self.headers, verify=False)
            if resp.status_code == 200:
                print(json.dumps(json.loads(resp.content), indent=4, ensure_ascii=False))
            else:
                print(str(resp.content))
        except Exception as e:
            print(str(e))

    def launch_all_scan(self):
        '''
        启动所有的扫描任务
        To launch all the scans
        :return: None
        '''
        print('[*] launch_all_scan ...')
        for scan_id in self.scans.keys():
            self.launch_scan(scan_id)

    def get_scan_detail(self, scan_id):
        '''
        获取扫描任务的详细信息
        Get scan task detailed information
        :param scan_id: scan_id
        :return: None
        '''
        print('[*] get_scan_detail ...')
        url = '{}/{}'.format(self.url, 'scans/{}'.format(scan_id))
        # print('url => {}'.format(url))
        try:
            resp = requests.get(url=url, headers=self.headers, verify=False)
            if resp.status_code == 200:
                # print(json.dumps(json.loads(resp.content), indent=4, ensure_ascii=False))
                content = json.loads(resp.content)
                print(content.keys())
                # print(json.dumps(json.loads(resp.content)['vulnerabilities'], indent=4, ensure_ascii=False))
                vuls = json.loads(resp.content)['vulnerabilities']
                print('vulnerabilities => {}'.format(len(vuls)))
                # 构造一个扫描任务的 table，获取并填充对应字段
                t = PrettyTable(
                    ['No.', 'plugin_id', 'severity', 'plugin_name', 'plugin_family', 'count'])
                index = 0
                for line in vuls:
                    index += 1
                    # print(line)
                    severity = line['severity']
                    plugin_name = line['plugin_name']
                    plugin_family = line['plugin_family']
                    count = line['count']
                    plugin_id = line['plugin_id']
                    t.add_row([index, plugin_id, severity, plugin_name, plugin_family, count])
                print(t)
            else:
                print(str(resp.content))
        except Exception as e:
            print(str(e))

    def delete_scan(self, scan_id):
        '''
        删除扫描任务，运行状态下的任务无法删除
        Detele a scan, active scan can not be deleted directly
        :param scan_id: scan_id
        :return: None
        '''
        # check whether the scan_id exists
        if scan_id not in self.scans.keys():
            print('[-] The [No.{}] scan task is not exists ...'.format(scan_id))
            exit()

        print('[*] delete_scan ... [No.{}]'.format(scan_id))
        # DELETE /scans/{scan_id}
        url = '{}/{}'.format(self.url, 'scans/{}'.format(scan_id))
        # print('url => {}'.format(url))
        try:
            resp = requests.delete(url=url, headers=self.headers, verify=False)
            if resp.status_code == 200:
                print('[-] Scan task_id [No.{}] deleted ...'.format(scan_id))
            else:
                print(str(resp.content))
        except Exception as e:
            print(str(e))
        finally:
            del self.scans[scan_id]
            pass

    def stop_scan(self, scan_id):
        '''
        停止扫描任务，需指定 scan_id
        Stop a scan with specific scan_id
        :param scan_id: scan_id
        :return: None
        '''
        print('[*] stop_scan ... [No.{}]'.format(scan_id))
        # POST /scans/{scan_id}/stop
        url = '{}/{}'.format(self.url, 'scans/{}/stop'.format(scan_id))
        # print('url => {}'.format(url))
        try:
            resp = requests.post(url=url, headers=self.headers, verify=False)
            if resp.status_code == 200:
                print('[*] Scan task_id [No.{}] stopped ...'.format(scan_id))
            else:
                print(str(resp.content))
        except Exception as e:
            print(str(e))

    def clear_all_scans(self):
        '''
        删除所有的扫描任务
        To clean/delete all the scans
        :return: None
        '''
        print('[*] clear_all_scans ...')
        flag = 0
        for scan_id in self.scans.keys():
            # running scan can not be deleted, so we stop it first
            # 先停止 running 状态的任务，再删除
            if self.scans[scan_id][1] == 'running':
                flag = 1
                self.stop_scan(scan_id)
        if flag:
            print('[*] Waiting 15s for running task to stop ...')
            time.sleep(15)
        for scan_id in list(self.scans.keys()):
            self.delete_scan(scan_id)
        self.scans = {}

    def export_scan_result(self, scan_id):
        '''
        导出指定扫描任务 ID 的 csv 格式扫描结果报告,
        Export detailed scan result information to csv
            Step 1: request report;
            Step 2: check report status;
            Step 3: download csv format report
        :param scan_id: scan_id
        :return: None
        '''
        # check whether the scan_id exists and scan task is finished
        if scan_id not in self.scans.keys():
            print('[-] The [No.{}] scan task is not exists ...'.format(scan_id))
            exit()
        elif self.scans[scan_id][1] != 'completed':
            # only completed scan task result can be exported
            print('[-] Can not export non-completed scan results ...'.format(scan_id))
        else:
            pass
        print('[*] export_scan_result ... [No.{}]'.format(scan_id))
        # nessus 一个报告/任务最多可以有 2500 个目标ip
        # POST /scans/{scan_id}/export，
        url = '{}/{}'.format(self.url, 'scans/{}/export?limit=2500'.format(scan_id))
        print('url => {}'.format(url))
        # 导出 csv 格式，所需字段可自定义
        data = {
            "format": "csv",
            "reportContents": {
                "csvColumns": {
                    "id": 'true',
                    "cve": 'true',
                    "cvss": 'true',
                    "risk": 'true',
                    "hostname": 'true',
                    "protocol": 'true',
                    "port": 'true',
                    "plugin_name": 'true',
                    "synopsis": 'true',
                    "description": 'true',
                    "solution": 'true',
                    "see_also": 'true',
                    "plugin_output": 'true',
                    # "stig_severity": 'false',
                    # "cvss3_base_score": 'false',
                    # "cvss_temporal_score": 'false',
                    # "cvss3_temporal_score": 'false',
                    # "risk_factor": 'false',
                    # "references": 'false',
                    # "plugin_information": 'false',
                    # "exploitable_with": 'false'
                }
            },
            # "extraFilters": {
            #     "host_ids": [],
            #     "plugin_ids": []
            # }
        }
        try:
            resp = requests.post(url=url, headers=self.headers,
                                 data=json.dumps(data, ensure_ascii=False).encode("utf-8"), verify=False)
            if resp.status_code == 200:
                # the server return a token which is need to get the report
                token = json.loads(resp.content)['token']
                # print('token => {}'.format(token))
                # check the whether the report is ready in a loop
                while True:
                    # GET /tokens/b83d730489b82529b4695edcf39c523cb689ace5627b32f3855ebb5009662d28/status
                    url = '{}/{}'.format(self.url, 'tokens/{}/status'.format(token))
                    print('url => {}'.format(url))
                    resp = requests.get(url=url, headers=self.headers, verify=False)
                    if resp.status_code == 200:
                        status = json.loads(resp.content)['status']
                        if status == 'ready':
                            break
                        else:
                            time.sleep(3)
                # if server responds ready, then using the token to download the report
                url = '{}/{}'.format(self.url, 'tokens/{}/download'.format(token))
                print('url => {}'.format(url))
                # save to file as csv
                df = pd.read_csv(url, encoding='utf_8_sig')
                out_file_name = '{}_{}.csv'.format(self.scans[scan_id][0], gen_random_str())
                print('[*] Save export to {} ...'.format(out_file_name))
                df.to_csv(out_file_name, encoding='utf_8_sig')
            else:
                print(str(resp.content))
        except Exception as e:
            print(str(e))

    def export_all_scan_results(self):
        '''
        导出 nessus scanner 中所有已完成的扫描任务报告
        To export all the completed scans
        :return: None
        '''
        print('[*] export_all_scan_results ...')
        for scan_id in self.scans.keys():
            # 只有扫描任务状态为 completed 才能导出
            self.export_scan_result(scan_id)

    def show(self):
        '''
        输出展示一个 nessus scanner 节点的信息、扫描策略、任务目录及所有扫描任务
        Show the nessus scanner info, scan_policies, scan folders and all the scans
        :return: None
        '''
        self.get_scanners()
        self.get_scan_policies()
        self.list_folders()
        self.get_all_scans()

    def clear_all(self):
        '''
        删除所有的任务目录和扫描任务
        Delete all the folders and scans
        :return: None
        '''
        self.clear_all_folders()
        self.clear_all_scans()
