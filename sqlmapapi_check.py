# -*- coding: utf-8 -*-
"""
SQLMap Injection Management Script
Manages timeout and exits if a WAF is detected.
"""

import os
import sys
import json
import time
import requests

def usage():
    print('+' + '-' * 50 + '+')
    print('\t   Python sqlmapapi_test')
    print('\t\t Code BY:YIYANG')
    print('+' + '-' * 50 + '+')
    if len(sys.argv) != 2:
        print("Usage: python sqlmapapi.py url.txt")
        sys.exit()

def task_new(server):
    url = f"{server}/task/new"
    req = requests.get(url)
    response = req.json()
    return response['success'], response['taskid']

def task_start(server, taskid, data, headers):
    url = f"{server}/scan/{taskid}/start"
    req = requests.post(url, data=json.dumps(data), headers=headers)
    return req.json()['success']

def task_status(server, taskid):
    url = f"{server}/scan/{taskid}/status"
    req = requests.get(url)
    return req.json()['status']

def task_log(server, taskid):
    url = f"{server}/scan/{taskid}/log"
    scan_json = json.loads(requests.get(url).text)['log']
    if scan_json:
        print(scan_json[-1]['message'])
        return 'retry' in scan_json[-1]['message']
    return False

def task_data(server, taskid):
    url = f"{server}/scan/{taskid}/data"
    vuln_data = requests.get(url).json()['data']
    return len(vuln_data) > 0

def task_stop(server, taskid):
    url = f"{server}/scan/{taskid}/stop"
    return requests.get(url).json()['success']

def task_kill(server, taskid):
    url = f"{server}/scan/{taskid}/kill"
    return requests.get(url).json()['success']

def task_delete(server, taskid):
    url = f"{server}/scan/{taskid}/delete"
    requests.get(url)

def get_url(urls):
    return [url for url in urls if '?' in url]

if __name__ == "__main__":
    usage()
    targets = [x.rstrip() for x in open(sys.argv[1])]
    targets = get_url(targets)
    server = 'http://127.0.0.1:8775'
    headers = {'Content-Type': 'application/json'}
    vuln = []

    for i, target in enumerate(targets, start=1):
        try:
            data = {
                "url": target,
                "batch": True,
                "randomAgent": True,
                "tamper": 'space2comment',
                "tech": 'BT',
                "timeout": 15,
                "level": 1
            }

            new, taskid = task_new(server)
            if not new:
                print("Failed to create scan")
                continue

            print("Scan created")
            start = task_start(server, taskid, data, headers)
            if not start:
                print("Scan cannot be started")
                continue

            print(f"--------------->>> Starting scan for target {i}")
            start_time = time.time()

            while start:
                status = task_status(server, taskid)
                if status == 'running':
                    print("Scan running...")
                elif status == 'terminated':
                    print("Scan terminated\n")
                    if task_data(server, taskid):
                        print(f"--------------->>> Vulnerability found in {target}\n")
                        with open('injection.txt', 'a') as f:
                            f.write(target + '\n')
                        vuln.append(target)
                    else:
                        print(f"--------------->>> {target} is not vulnerable\n")
                    task_delete(server, taskid)
                    break
                else:
                    print("Scan encountered an error")
                    break

                time.sleep(10)
                if task_log(server, taskid) or (time.time() - start_time > 30):
                    print("Strong WAF detected or timeout reached, abandoning target.")
                    if task_stop(server, taskid):
                        print("Scan stopped")
                    if task_kill(server, taskid):
                        print("Scan killed")
                    task_delete(server, taskid)
                    break

        except Exception as e:
            print(f"An error occurred: {e}")

    for each in vuln:
        print(each + '\n')
