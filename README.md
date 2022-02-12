## Nessus_API
封装了 Nessus REST API 的一些日常会经常使用的操作，比如创建目录，创建/删除扫描任务，导出扫描报告等，没有去封装 Nessus 提供的所有操作，也不是很必要。

官方封装 `(Nessus 6)`：`https://github.com/tenable/nessrest`


## 目录文件说明
```
.
├── Nessus.py							# 封装 Nessus REST API 调用类
├── Pydoc_module_Nessus.html			# Nessus 文档
├── README.md
├── __init__.py
└── sample.py							# sample 调用 Nessus 示例
```

## Nessus 封装类
文档请参考本地 Pydoc_module\_Nessus.html 文档。

|  函数   | 说明  | 
|  ----  | ----  | 
| `show `  | 展示当前 nessus scanner 节点、扫描策略、目录和扫描任务信息  | 
| `gen_random_str `  | 生成随机小写字符和数字组合的字符串，默认 6 位  | 
| `list_folders `  | 列出当前 nessus scanner 的扫描目录 | 
| `create_folder `  | 创建目录  | 
| `delete_folder `  | 删除目录  | 
| `clear_all_folders `  | 删除所有目录  | 
| `get_scanners `  | 获取 nessus scanner 节点信息  | 
| `get_scan_policies `  | 获取自定义扫描策略  | 
| `create_scan `  | 创建扫描任务  | 
| `launch_scan `  | 启动扫描任务  | 
| `launch_all_scan `  | 启动所有扫描任务  | 
| `get_scan_detail `  | 获取扫描任务详细信息  | 
| `get_all_scans `  | 获取所有扫描任务信息  | 
| `stop_scan `  | 停止扫描任务  | 
| `delete_scan `  | 删除扫描任务  | 
| `clear_all_scans `  | 清理/删除所有扫描任务  | 
| `export_scan_result `  | 导出扫描任务结果  | 
| `export_all_scan_results `  | 导出所有扫描任务结果  | 
| `clear_all `  | 清楚所有自定义目录和扫描任务  | 

## Sample 

### create_scan
```
Total ips => 11502  task_num => 11   
[*] create_scan ...
[+] Scan [No.571] -- template-0cc833f5-3b5a-91e2-dce8-d20697f1ae6aee25d02c47206063 created succeed ...
[*] create_scan ...
[+] Scan [No.573] -- template-65010e1b-d2f1-7b51-f101-8c035d1fe2311e6e176eac780a6f created succeed ...
[*] create_scan ...
[+] Scan [No.575] -- template-c3b38128-aafd-5bfa-a32d-cd6f2d8ea9a288c9d66971ff00bd created succeed ...
[*] create_scan ...
[+] Scan [No.577] -- template-10d89ef4-1371-5d92-c6ea-3149af87eb71d0cc2890346e38b5 created succeed ...
[*] create_scan ...
[+] Scan [No.579] -- template-88ac1d40-f688-6031-5501-8e853aad84eb4baff684e6255539 created succeed ...
[*] create_scan ...
[+] Scan [No.581] -- template-c7e06a80-723b-0abf-ae22-c48ba397cdbb12b16e4b796b277b created succeed ...
[*] create_scan ...
[+] Scan [No.583] -- template-81a38b8d-76c8-89f4-5311-dd0d966c6925a09148f2b8c78d1f created succeed ...
[*] create_scan ...
[+] Scan [No.585] -- template-556a25aa-c134-d5fd-2381-f104dfb7b9c1f3f1fa441fadb41d created succeed ...
[*] create_scan ...
[+] Scan [No.587] -- template-f43ea764-77bd-8607-e634-44ba185429787f58b66080be5be3 created succeed ...
[*] create_scan ...
[+] Scan [No.589] -- template-5809adca-9d1e-3b98-e137-015623f17d596d96dff01bf667ff created succeed ...
[*] create_scan ...
[+] Scan [No.591] -- template-901f0565-f018-5cbd-1aa3-5b4e6af972697a84f031a899ee15 created succeed ...
[*] create_scan ...
[+] Scan [No.593] -- template-7fa719e5-fa0d-dda6-d5d8-bdc08fd932b7a6f1f63b5c344469 created succeed ...
```

### show
```
[*] get_scanners ...
+---------------------+------------+----------+------------+----------------+-----------------+
|         name        |    type    | platform | ui_version | engine_version | expiration_date |
+---------------------+------------+----------+------------+----------------+-----------------+
| Nessus Scanner (SC) | sc_scanner |  LINUX   |   8.10.1   |     8.10.1     |        0        |
+---------------------+------------+----------+------------+----------------+-----------------+
[*] get_scan_policies ...
+-----------+---------------+-----------+------------+------------------------+----------------------+------------------------------------------------------+
| policy_id |      name     |   owner   | visibility | last_modification_date |     description      |                     policy_uuid                      |
+-----------+---------------+-----------+------------+------------------------+----------------------+------------------------------------------------------+
|     8     |  weekly-scan  | security |  private   |       2021-08-02       |   每周例行扫描任务   | ad629e16-03b6-8c1d-cef6-ef8c9dd3c658d24bd260ef5f9e66 |
|    247    |   fast_scan   | security |  private   |       2022-02-09       | 常见高危端口快速探测 | ad629e16-03b6-8c1d-cef6-ef8c9dd3c658d24bd260ef5f9e66 |
|    248    | all_port_scan | security |  private   |       2022-02-09       |      全端口扫描      | ad629e16-03b6-8c1d-cef6-ef8c9dd3c658d24bd260ef5f9e66 |
|    249    |      test     | security |  private   |       2022-02-09       |    just for test     | 731a8e52-3ea6-a291-ec0a-d2ff0619c19d7bd788d6be818b65 |
+-----------+---------------+-----------+------------+------------------------+----------------------+------------------------------------------------------+
[*] list_folders ...
+-----------+----------+-------+--------+
| folder_id |   name   |  type | custom |
+-----------+----------+-------+--------+
|     6     |  Trash   | trash |   0    |
|     7     | My Scans |  main |   0    |
+-----------+----------+-------+--------+
[*] get_all_scans ...
+-----------+-------------+---------+--------------------+-----------+---------------------+------------------------+------------------------------------------------------+
| folder_id | folder_name | scan_id |     task_name      |   status  |    creation_date    | last_modification_date |                    scan_task_uuid                    |
+-----------+-------------+---------+--------------------+-----------+---------------------+------------------------+------------------------------------------------------+
|     7     |   My Scans  |   571   | routine_scan_no.0  | completed | 2022-02-11 14:45:52 |  2022-02-11 15:35:26   | 65342f6e-ec8a-b659-e092-8b338ee34ae6513fdf73c2323d5f |
|     7     |   My Scans  |   593   | routine_scan_no.11 |  running  | 2022-02-11 14:46:00 |  2022-02-11 16:38:08   | 3e43a68d-335c-917d-f71d-95f4e7da42fe3a45a2fb007ca490 |
|     7     |   My Scans  |   589   | routine_scan_no.9  |  running  | 2022-02-11 14:45:59 |  2022-02-11 16:38:08   | ae601915-dca0-6fe7-6eb9-98d7e7ecfd489b551a28edf96fe2 |
|     7     |   My Scans  |   591   | routine_scan_no.10 |  running  | 2022-02-11 14:45:59 |  2022-02-11 16:38:08   | 39ca27b0-346f-d939-56ad-020835670128e2b875acc4aaa3a2 |
|     7     |   My Scans  |   587   | routine_scan_no.8  |  running  | 2022-02-11 14:45:58 |  2022-02-11 16:38:08   | 5d555108-7a40-f29f-1b98-0c40198effb36df436b17b832e93 |
|     7     |   My Scans  |   585   | routine_scan_no.7  |  running  | 2022-02-11 14:45:57 |  2022-02-11 16:38:08   | ebcc7b21-2472-6276-e373-d57a606c655eeb1ead355d088c99 |
|     7     |   My Scans  |   581   | routine_scan_no.5  |  running  | 2022-02-11 14:45:56 |  2022-02-11 16:38:08   | 6f6297f7-66f6-6627-6f7c-561fb322851e4e4049da5718028a |
|     7     |   My Scans  |   583   | routine_scan_no.6  |  running  | 2022-02-11 14:45:56 |  2022-02-11 16:38:08   | 9ac21a19-a7d3-e8c6-6a4b-09101976d96d66f599c55d32ba06 |
|     7     |   My Scans  |   579   | routine_scan_no.4  |  running  | 2022-02-11 14:45:55 |  2022-02-11 16:38:08   | 2c5d4fe7-959d-92d0-09b9-16c80d172ec7852c267bcc4f1d33 |
|     7     |   My Scans  |   575   | routine_scan_no.2  |  running  | 2022-02-11 14:45:54 |  2022-02-11 16:38:08   | bc3ecc70-fc95-fa2f-a750-b650411f4bbec4a0d13647c9206c |
|     7     |   My Scans  |   577   | routine_scan_no.3  |  running  | 2022-02-11 14:45:54 |  2022-02-11 16:38:08   | 44721e19-c377-3d06-64e9-7fbfb73cccab61e00969cac67031 |
|     7     |   My Scans  |   573   | routine_scan_no.1  |  running  | 2022-02-11 14:45:53 |  2022-02-11 16:38:08   | 4e527c65-c117-5a93-4b95-9c6f07925d221655bfd8200a3c64 |
+-----------+-------------+---------+--------------------+-----------+---------------------+------------------------+------------------------------------------------------+

```