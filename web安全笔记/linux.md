# linux

## 渗透常用命令

```nginx

```



## 通用配置

**linux中网卡位置：/sys/class/net/eth0/address**

### 进程

```nginx
# 查看端口状态
netstat -tunpl |grep 22

# 查看端口占用
lsof -i:端口号
```



### vm没有网络

```nginx
# 编辑dns文件
vim  /etc/resolv.conf

# kali（Debian）重启网卡
service networking restart
/etc/init.d/networking restart

# 启用网卡
sudo ifconfig eth0 up  
sudo ifconfig -a # 查看IP
sudo dhclient eth0  #  分配IP

# dns配置文件
sudo vim /etc/resolv.conf
# 测试dns是否可用
nslookup www.baidu.com
# 不可用徐再次配置文件加入
nameserver 8.8.8.8
nameserver 114.114.114.114
# 如果在执行完service networking restart命令后，dns恢复原样
# 是因为设置了NetworkManager服务所致


# ifconfig -a 只有localhost，设置静态ip和dhcp的地方
sudo vim /etc/network/interfaces

# 动态dhcp方式
auto eth0
iface eth0 inet dhcp

# 静态方式
auto eth0
iface eth0 inet static
address 外面本地ip地址
netmask 外面本地ip地址的子网掩码
gateway 外面本地ip地址的网关

# dhcp静态
auto eth0
iface eth0 inet dhcp
address 外面本地ip地址
netmask 外面本地ip地址的子网掩码
gateway 外面本地ip地址的网关

# 网路未托管配置，设置托管后就不能手动配置dns的nameserver
cd /etc/NetworkManager/
sudo vim NetworkManager.conf
将false改为true

# 查看网络状态
systemctl status networking.service

```

## kali



### 安装python3.10

==vm虚拟机安装建议拍个快照==

```nginx
# 更新软件包列表
sudo apt update

# 下载源码
wget https://www.python.org/ftp/python/3.10.11/Python-3.10.11.tgz

# 解压缩下载的源代码
tar -xf Python-3.10.11.tgz

# 进入解压缩后的目录
cd Python-3.10.11

# 配置安装选项
./configure --enable-optimizations

# 编译源代码
make -j$(nproc)

# 安装Python 3.10（不能写install，会替换掉原系统的python3）
sudo make altinstall

# 检查
python3.10 --version
python3 --version
python2 --version

# 全部输出表示三个版本共存成功
```



### 调整字体显示

```nginx
# 安装面板
sudo apt-get install gnome-tweaks

# 打开面板
gnome-tweaks
```

### 配置clash

```nginx
# 进入root用户
cd /root

# 下载clash
wget https://github.com/Dreamacro/clash/releases/download/v1.16.0/clash-linux-amd64-v1.16.0.gz

# 解压clash
gunzip clash-linux-amd64-v1.16.0.gz

# 把名称变短
mv clash-linux-amd64-v1.16.0.gz clash
# 赋予可执行权限
chmod +x clash

# 测试一下生成config.yaml文件(生成位置：/root/.config/clash/)
/clash -t

# 编辑config.yaml
vim ~/.config/clash/config.yaml

# 打开Windows的clash，到配置模块，选择你的配置右键编辑
# 然后粘贴到linux中的config.yaml中

# 运行
/clash

# 运行胡网页版视图
http://clash.razord.top/#/proxies
# 更换为9090端口，点登录
```



### 设置源

```nginx
sudo vim /etc/apt/sources.list
# 注释官方源

# 中科大Kali镜像源
deb http://mirrors.ustc.edu.cn/kali kali-rolling main non-free contrib
deb-src http://mirrors.ustc.edu.cn/kali kali-rolling main non-free contrib
# 阿里云Kali镜像源
deb http://mirrors.aliyun.com/kali kali-rolling main non-free contrib
deb-src http://mirrors.aliyun.com/kali kali-rolling main non-free contrib
# 清华大学Kali镜像源
deb http://mirrors.tuna.tsinghua.edu.cn/kali kali-rolling main contrib non-free
deb-src https://mirrors.tuna.tsinghua.edu.cn/kali kali-rolling main contrib non-free

# 更新源
apt-get update

```

### 安装中文输入法

```nginx
# 执行命令安装输入法框架
sudo apt install fcitx fcitx-googlepinyin

# 重启
reboot

# 配置fcitx
搜索框里面搜fcitx



# 删除fcitx
sudo apt-get remove fcitx 
sudo apt-get remove fcitx-module*
sudo apt-get remove fcitx-frontend*
sudo apt-get fcitx* --purge  
# 重启
sudo  reboot 
```



### 用户相关

```nginx
# 第一次登录设置root账号密码（需要先输入一次当前登录账号密码，因为sudo权限）
sudo passwd root

# kali切换root用户
su root
```

### ssh

```nginx
# kali开启ssh22端口服务
vim /etc/ssh/sshd_config
# 找到 #PasswordAuthentication yes  把#的注释去掉
PasswordAuthentication yes
# 将 #PermitRootLogin prohibit-password 修改为：PermitRootLogin yes
PermitRootLogin yes

# 查看ssh服务状态
/etc/init.d/ssh status

# 启动ssh
/etc/init.d/ssh start
```



### openvpn

```nginx
# kali安装openvpn
wget -O openvpn.sh https://get.vpnsetup.net/ovpn
# 使用默认选项自动安装 OpenVPN。
sudo bash openvpn.sh --auto

# 连接内网
sudo openvpn 0to1.ovnp
```

### fscan工具

```nginx
# fscan
source /etc/profile
```

### 主题

**主题列表**：https://github.com/ohmyzsh/ohmyzsh/wiki/External-themes

```nginx
# 进入用户目录
cd ~

# 官方主题 
git clone https://github.com/ohmyzsh/ohmyzsh.git ~/.oh-my-zsh
# 备份kali官方主题
cp ~/.zshrc ~/.zshrc.orig
# 覆盖主题
cp ~/.oh-my-zsh/templates/zshrc.zsh-template ~/.zshrc

# 禁用主题自动更新
vim .zshrc
# 最末尾添加
zstyle ':omz:update' mode disabled

# 使用主题
source .zshrc



# 热情主题
# 下载: 
git clone https://github.com/ChesterYue/ohmyzsh-theme-passion
# 覆盖主题:
cp ./ohmyzsh-theme-passion/passion.zsh-theme ~/.oh-my-zsh/themes/passion.zsh-theme
# 修改配置: 
vim ~/.zshrc 
# 找到ZSH_THEME，并修改为如下
ZSH_THEME="passion";

# 这个主题依赖bc命令，bc是一个计算器命令，用于计算时间
sudo apt install bc
# 使用主题
source ~/.zshrc
```



## Ubuntu

### 用户相关

```nginx
# Ubuntu切换root用户
sudo passwd root

# Ubuntu未开放root账户登录，修改一下文件可以设置root登录
vi /etc/lightdm/lightdm.conf
    [SeatDefaults]
    user-session=ubuntu
    greeter-session=unity-greeter
    greeter-show-manual-login=true    #手工输入登陆系统的用户名和密码
    allow-guest=false    		     #不允许guest登录

# 创建用户
    adduser [perl编写，ubuntu中建议使用]
    useradd	[编写脚本时使用]

    sudo adduser username

    # 	将用户追加到sudo组内
    # 	-a表示追加用户到指定组
    #	-G选项表示不要将用户从其它组中移除。
    sudo usermod -aG sudo username

# 删除用户
    userdel	[脚本中使用]
    deluser	[ubuntu中建议使用，因为其他发行版中没有deluser]

    # deluser仅在指定用户参数时，deluser将删除用户而不删除用户文件
    # 如果你需要用户的家目录和邮件等信息请使用--remove-home选项。
    sudo deluser username
    sudo deluser --remove-home username

# 查看所有用户
cat /etc/passwd

# 只输出用户名命令
cat /etc/passwd |cut -f 1 -d :

# 查看用户总数
cat /etc/passwd | wc -l

# 用户权限解析
admin:x:1000:1000::/home/admin:/bin/bash
username:password:UserID:GroupID:comment:home directory:shell
用户名：密码：用户id：用户所在组id：备注：用户家目录：shell所在命令
```

### ssh

```nginx
# 创建ssh-key
ssh-keygen -t rsa -b 4096 -C "my-email@meathill.com"

# 首先，将你的电脑上的公 key 添加到服务器 ~/.ssh/authorized_keys。
# 接着编辑服务器上的 /etc/ssh/sshd_config，禁用密码登录。
ChallengeResponseAuthentication no
PasswordAuthentication no

#最后重启 ssh 服务：
service ssh restart。

# 配置ssh
sudo apt-get install openssh-server
sudo apt-get install openssh-client
ps -e |grep ssh
	buntu:~# ps -e | grep ssh
    1918 ?        00:00:00 ssh-agent
    6599 ?        00:00:00 sshd
    
# ssh-server配置文件位于，在这里可以定义SSH的服务端口
/etc/ssh/sshd_config

```



### 防火墙

```nginx

# 查看防火墙当前状态
sudo ufw status
# 开启防火墙 
sudo ufw enable
# 关闭防火墙
sudo ufw disable

# 开放防火墙端口
sudo ufw allow 3306

# 解决获取UbuntuPPA源失败
sudo apt-get install software-properties-common

# 开放端口可被外部访问
/sbin/iptables -I INPUT -p tcp --dport 8080 -j ACCEPT

# 查看进程占用端口
netstat -anp|grep 80
lsof -i:8888	
# 关闭端口占用
kill -9 26993
```





## centOs

### 防火墙

```nginx
# centOs查看防火墙状态
systemctl status firewalld
```

