# 关于check_dnioncdn.py  
## 随便说说：  
**为什么要写这个脚本？**
公司的项目有上百个，已经使用的加速域名有几十个，目前还在不断的上涨，有的加速域名是自己维护，有的则是合作方维护。经常有项目的兄弟或是合作方的朋友咨询CDN的故障（或是某个省市的节点是否有问题），每当遇到这样的情况，一是只能靠CDN厂商去检查；二是让那个省市的朋友帮忙测试下，沟通起来非常的不方便。于是就产生了自己写个程序检测，有问题就直接反应给CDN厂商，可以直接跳过沟通和确认问题的环节。  

## 目前的功能：
1、通过dnion的API接口获取所有的加速域名  
2、通过获取到的加速域名来进一步获取某个域名在全国加速节点的ip地址  
3、对该域名所在的每个加速节点进行http状态检测，来判断该节点是否有问题  

## 想实现但还没有实现的问题：MD5校验
**其实倒是有思路但是不完善，所以没有做进去，如下：**  
通过程序把文件下载到本地进行MD5校验，但是这里有个问题：如果是单个小文件还好说，可是像我们公司的文件动辄上百兆，甚至上GB的文件都有，每个节点去下载校验根本就行不通。  

目前就这样了，如果想到更好的办法再把这个功能加上。  

## Fix：  
1、修正域名检测正则  
2、调整参数检查逻辑  
3、规范编码格式  

## 交流方式：  
Email：jaryer@gmail.com  
