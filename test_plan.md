## 测试计划

* 测试host: colocrossing1

## Iptabels 规则测试
* 执行扫描端口
* 屏蔽端口：23222
* 重新扫描端口，并且检查我们的程序是否已经显示将`23222`端口屏蔽
* /home/openthedoor/fwctl block 23222 后尝试连接`23222`端口，确保连接失败(在我们的机器上进行访问，：http://host:23222/)
* /home/openthedoor/fwctl block 23222 --allow 154.21.81.194 确认连接成功(在我们的机器上进行访问，：http://host:23222/)

##  ufw or Firewalld 规则测试
* 执行扫描端口
* 用nc启动一个临时测试的端口（安全端口）
* 进行屏蔽端口
* 重新扫描端口，并且检查我们的程序是否已经显示将该端口屏蔽
* /home/openthedoor/fwctl block <port> 后尝试连接该端口，确保连接失败(在我们的机器上进行访问)
* /home/openthedoor/fwctl block <port> --allow 154.21.81.194 确认连接成功(在我们的机器上进行访问)