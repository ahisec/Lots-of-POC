因为某些原因，公开一个nacos的0day


环境准备：
下载nacos2.3.2或2.4.0版本，解压，使用
startup.cmd -m standalone 启动nacos
补充POC信息
POC是一个python项目，依赖requests和flask，请先使用requiments.txt安装依赖
1.配置config.py中的ip和端口，执行service.py，POC攻击需要启动一个jar包下载的地方，jar包里可以放任意代码，都可执行，我这里放了一个接收参数执行java命令的
2.执行exploit.py，输入地址和命令即可执行。
