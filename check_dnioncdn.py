#!/usr/bin/env python
#coding: utf-8
#Filename: check_dnioncdn.py
#Author: 'Kevin Tan'
#Date: '2015-07-22'
#Modify: '2015-08-05'

import requests
import time
import sys
import re

"""
本程序的功能介绍：
  主要用于查询帝联CDN所有的加速域名及域名所有节点的状态信息。
  必备工作：需要上传一个用于检测状态（HTTP）的文件到CDN
  1、通过API接口查询所有的加速域名
  2、通过API接口查询到每个域名的所有节点服务器ip地址
  3、用HTTP协议去GET这个检测文件是否成功

注：请在 values 里填写dnion cdn的用户标识码
"""

# 定义打印字体颜色
HEADER = '\033[95m'
OKBLUE = '\033[94m'
OKGREEN = '\033[92m'
WARNING = '\033[93m'
FAIL = '\033[91m'
ENDC = '\033[0m'
BOLD = '\033[1m'

# 变量定义
URL_query = 'http://ip.taobao.com/service/getIpInfo.php?ip='
url = 'http://push.dnion.com/domain.do'
values = {'captcha': ''}
ip_url = 'http://push.dnion.com/currentIp.do'
domain = {'domain': ''}
err_ip = []
err_code = []

# 查询ip地址归属地
def query_ip_info(ip):
	if not ip:
		print 'argument shoud not be none'
		return
	url = URL_query + str(ip)
	try:
		r = requests.get(url, timeout=2)
	except Exception as e:
		return e
	else:
		data = r.json()
		if data['code'] == 0:
			data = data['data']
			return '('+ data['country'] + '/' + data['area'] + '/' + data['region'] + '/' + data['city'] + '/' + data['isp'] + ')'
		else:
			return 'Query Failure: ', data['data']

# url状态检测
def  url_check(ip, url, domain):
	urls = 'http://' + str(ip) + '/' + str(url)
	try:
		r = requests.get(urls, headers={'Host': domain}, timeout=2)
		if r.status_code in (200, 301, 302, 304):
			return OKGREEN + 'Ok! %s' % r.status_code + ENDC
		else:
			err_code.append(r.status_code)
			return WARNING + 'error! %s' % r.status_code + ENDC
	except Exception:
		err_ip.append(ip)
		return FAIL + 'no connect!' + ENDC

# 查询所有加速域名
def get_cdn_domain(status):
	r = requests.get(url, params=values, timeout=2)
	datas = r.text.strip(' ').split('\n')
	if status == 1:
		for i, data in enumerate(datas):
			if data:
				print '[%s] %s' % (i, data)
	else:
		return datas

# 检查域名是否存在
def check_domain(domain):
	all_domain = get_cdn_domain(0)
	if domain in all_domain:
		print 'Domain exist!'
	else:
		print 'Domain No Exist.\nSorry Goodbye!'
		sys.exit(0)

# 查询某一个加速域名的状态
def get_single_domain(single_domain, url):
	url = str(url)
	domain['domain'] = single_domain.strip()
	values.update(domain)
	r = requests.get(ip_url, params=values, timeout=2)
	lines = r.text.strip(' ').split('\n')
	lines_stat = []
	print 'Start check Current domain: %s' % single_domain
	print 'URL: http://' + single_domain + '/' + url
	time.sleep(3)
	for i, line in enumerate(lines):
		if line:
			lines_stat.append(line)
			print '[%s]  %s --> ' % (i, line),
			print url_check(line, url, single_domain),
			print query_ip_info(line)
	print '\nTotal ip: %s' % len(lines_stat)
	print 'HTTP Code Normal: %s' % (len(lines_stat) - len(err_code) - len(err_ip))
	if not err_code is None:
		print 'Failure Code: %s' % len(err_code)
	if not err_ip is None:
		print 'Failure ip: %s' % len(err_ip)
		for erri,errip in enumerate(err_ip):
			if errip:
				print '[%s] %s %s %s ==>' % (erri, FAIL, errip, ENDC),
				print query_ip_info(errip)

def Usage():
	help = """
使用帮助：
  方法一：查询所有的加速域名
  #python check_dnioncdn.py all

  方法二：查询某一个加速域名所有节点的状态
  #python check_dnioncdn.py images.sina.com images/testcdn.jpg
	"""
	return help

def run():
	pattern = re.compile(r'\w+(\.\w+)+\.(com|com.cn|edu|cn|net)')
	if len(sys.argv) == 2 and 'all' == sys.argv[1]:
		print 'All Domain:'
		get_cdn_domain(1)
	elif len(sys.argv) == 3:
		url = pattern.match(sys.argv[1])
		if url:
			print 'Domain Checking......'
			check_domain(sys.argv[1])
			get_single_domain(sys.argv[1], sys.argv[2])
		else:
			print 'Domain Error！\nSorry Goodbye!'
			sys.exit(0)
	else:
		print FAIL + 'Argument Error！' + ENDC
		print Usage()

if __name__ == "__main__":
	run()

