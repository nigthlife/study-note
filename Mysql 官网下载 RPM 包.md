**Mysql 官网下载 RPM 包**

>   wget https://dev.mysql.com/get/mysql80-community-release-el8-1.noarch.rpm

**强力卸载**

```bash
for i in $(rpm -qa|grep mysql);do rpm -e $i --nodeps;done
rm -rf /var/lib/mysql && rm -rf /etc/my.cnf && rm -rf /usr/share/mysql
whereis mysql
find / -name mysql
yum remove mysql mysql-server mysql-libs
```

 **安装 rpm 包**

>   先到rpm包的目录下
>
>   yum localinstall rpm包

**yum 安装**

>   yum update 
>
>   yum install mysql-server

**查看 mysql 是否安装成功**

>   ps -ef | grep mysql 
>
>   mysqladmin --version

 **启动 mysql 服务**

>   systemctl start mysqld 
>
>   systemctl enable mysqld 
>
>   systemctl status mysqld

**查看mysql默认读取my.cnf的目录**

>   mysql --help|grep 'my.cnf'

**数据库文件存放目录**

```ba
cd /var/lib/mysql
ls -l
```

