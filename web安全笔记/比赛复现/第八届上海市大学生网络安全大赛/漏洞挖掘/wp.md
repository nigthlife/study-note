# wp

* 192.168.33.55 \(redis写计划任务\) 已经拿flag

* 192.168.33.127

```c
192.168.33.127:22 open
192.168.33.127:111 open
192.168.33.127:80 open
192.168.33.127:3306 open
```

* 192.168.33.149

```c
192.168.33.149:22 open
192.168.33.149:80 open
192.168.33.149:53 open
192.168.33.149:2222 open
```

`curl http://192.168.33.127 -u Admin -p bQqYfe5eqN2CttsV`​

http://192.168.33.127/zabbix使用上面的账号密码登录

[【后利用】| zabbix攻击思路总结 | CTF导航 (ctfiot.com)](https://www.ctfiot.com/102266.html)

```python
timeout 1 cat /root/flag
```

按照这个思路即可成功在该机器执行命令获取到第二个flag
