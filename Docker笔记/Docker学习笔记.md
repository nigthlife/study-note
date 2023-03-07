# Docker学习笔记

## 0、前言

**文档**

官方文档：https://docs.docker.com/docker-for-windows/ 

中文文档：https://dockerdocs.cn/get-started/index.html

**仓库**

https://hub.docker.com/

b站教程：https://www.bilibili.com/video/BV1og4y1q7M4?



## 1、安装docker

**centos安装**

```c
# 卸载旧的版本
$ sudo yum remove docker \
                  docker-client \
                  docker-client-latest \
                  docker-common \
                  docker-latest \
                  docker-latest-logrotate \
                  docker-logrotate \
                  docker-engine
```

**Ubuntu安装**

卸载旧版与设置存储库

```py
# 卸载旧版docker
sudo apt-get remove docker docker-engine docker.io containerd runc

# 设置存储库
# 更新apt包索引并安装包以允许apt通过 HTTPS 使用存储库
sudo apt-get update
sudo apt-get install \
    ca-certificates \
    curl \
    gnupg \
    lsb-release

# 添加 Docker 的官方 GPG 密钥
sudo mkdir -p /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg

# 设置存储库
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
```

**安装 Docker 引擎**

```shell
# 更新apt包索引
sudo apt-get update

# 安装 Docker Engine、containerd 和 Docker Compose

# 最新版
sudo apt-get install docker-ce docker-ce-cli containerd.io docker-compose-plugin 
    
    # 要安装特定版本的 Docker Engine，首先列出存储库中的可用版本
    apt-cache madison docker-ce | awk '{ print $3 }'
        5:20.10.16~3-0~ubuntu-jammy
        5:20.10.15~3-0~ubuntu-jammy	
        5:20.10.14~3-0~ubuntu-jammy
        5:20.10.13~3-0~ubuntu-jammy
    # 然后选择进行安装
    VERSION_STRING=5:20.10.13~3-0~ubuntu-jammy
	sudo apt-get install docker-ce=$VERSION_STRING docker-ce-cli=$VERSION_STRING containerd.io docker-compose-plugin
```

**启动docker**

```py
systemctl start docker
    # 查看docker状态
ps -ef | grep docker

# 通过镜像验证 Docker Engine 安装是否成功（当容器运行时，它会打印一条确认消息并退出）
sudo docker run hello-world
```

## 2、docker命令

```py
systemctl start docker
systemctl stop docker
systemctl restart docker
/* ------------------------------------------------------------------------------
		帮助命令
	-------------------------------------------------------------------------------*/
docker version 			     # 显示docker的基本信息
docker info 				 # 系统信息，镜像和容器的数量
docker 命令 --help 		    # 全部信息
 /* ------------------------------------------------------------------------------
		镜像命令
	-------------------------------------------------------------------------------*/
docker images				# 查看所有本地主机上的镜像
    # 镜像仓库源		# 镜像的标签		# 镜像的ID		   # 镜像的创建时间		# 镜像的大小
	REPOSITORY    	TAG       		IMAGE ID       	CREATED         	  SIZE
	hello-world   	latest    		feb5d9fea6a5   	15 months ago   	  13.3kB
docker images -a			# 显示所有镜像信息
docker images -q			# 显示所有镜像的id
 /* ------------------------------------------------------------------------------
		镜像搜索
	-------------------------------------------------------------------------------*/
docker search mysql			# 镜像搜索
docker search mysql --filter=STARS=3000 # 搜索出Stars大于3000的
 /* ------------------------------------------------------------------------------
		下载镜像
	-------------------------------------------------------------------------------*/
    docker pull mysql 			# 下载mysql镜像，default tag，默认最新版latest
    # 等价于
    docker pull docker.io/library/mysql:latest
    docker pull mysql:5.7		# 指定版本下载 
 /* ------------------------------------------------------------------------------
		删除镜像
	-------------------------------------------------------------------------------*/
    docker rmi -f feb5d9fea6a5	# 删除一个 可以通过名称 也可以指定id -f表示删除所有
    docker rmi -f id id id		# 删除多个 用空格分隔id
    docker rmi -f $(docker images -aq) 	# 删除所有 # images -aq就是查所有镜像id，从而递归删除
 /* ------------------------------------------------------------------------------
		容器命令
        #  启动和停止容器的操作
        docker start
        docker restart
        docker stop	
        docker kill
	-------------------------------------------------------------------------------*/
    #  新建容器并启动
    docker run [可选参数] image
    docker run -it linux /bin/bash

    # 参数说明
    --name=“Name” # 容器名字，用于区分容器
    -d 后台方式运行
    -it 使用交互方式运行，进入容器查看内容
    -p 指定容器的端口 如-p 8080::8080
        -p ip:主机端口：容器端口
        -p 主机端口:容器端口
        -p 容器端口
    -p 随机指定端口
    --net	网络配置
    -e 环境配置修改或设置
    
    # 案例
    
    # 启动nginx
    docker run -d --name nginx01 -p:9998:80 nginx

	/* ------------------------------------------------------------------------------
    	进入退出容器
	-------------------------------------------------------------------------------*/
    docker run -it centos /bin/bash 	  # 进入
    docker exec -it 容器id bashSHELL		#  进入当前正在运行的容器（开启一个新的终端）
    docker attach 容器id					#  进入当前正在运行的容器（不会开启新终端）

    ls				# 查看目录
    exit			# 退出
    Ctrl + P + Q	# 容器不停止退出 注意必须在英文输入法下，中文输入法不行

 /* ------------------------------------------------------------------------------
		 查看运行的容器
	-------------------------------------------------------------------------------*/
    docker ps					# 查看正在运行的容器
    docker ps -a				# 查看曾经运行的容器
    docker ps -a - n=number		# 显示最近创建的容器，设置显示个数
    docker ps -aq				# 只显示容器的编号

 /* ------------------------------------------------------------------------------
		 删除容器
	-------------------------------------------------------------------------------*/

    docker rm 容器id					   # 删除指定容器 不能删除正在运行的容器，如果强制删除 rm -f
    docker rm -f $(docker ps -aq)		# 删除所有容器
    docker ps -a -q|xargs docker rm		# 删除所有容器

 /* ------------------------------------------------------------------------------
		 后台启动docker
	-------------------------------------------------------------------------------*/
    docker run -d 镜像名
    # 用docker ps 查看的时候 发现停止了
    # 后台运行，docker发现前台没有，容器启动后，发现自己没有提供服务，会立刻停止

    # 用完即删除方式运行容器(会删除容器，但不会删除镜像)
    docker run -it --rm tomcat:9.0
 /* ------------------------------------------------------------------------------
		  查看日志
	-------------------------------------------------------------------------------*/
    docker logs
    docker logs -f -t --tail n 【id】
 /* ------------------------------------------------------------------------------
		  从容器内拷贝文件到主机上
	-------------------------------------------------------------------------------*/
    
    docker attach 容器id	   # 进入正在运行的容器
    cd /home				# 进入容器home目录
    touch test.java			# 在目录中创建java文件
    exit					# 退出并停止容器，容器虽然被停止，但是数据都会保留

	
    docker cp 容器id:/home/test.java /home	# 容器数据拷贝到主机
    ls						# 查看是否拷贝成功

    # 拷贝是一个手动过程，未来我们使用 -v 卷的技术，可以实现自动同步 /home /home
    
     /* ------------------------------------------------------------------------------
		  查看内容占用
	-------------------------------------------------------------------------------*/
    docker stats
```

### 2.1、提交镜像

>   核心：`docker commit -a="changjing" -m="add webappsFile" cedf6e527bb4 tomcat01:1.0`

```py
# 后台运行tomcat
root@ubuntu:/home/peek# docker run -d tomcat
# 查看是否成功运行
root@ubuntu:/home/peek# docker ps
CONTAINER ID   IMAGE     COMMAND             CREATED         STATUS         PORTS      NAMES
cedf6e527bb4   tomcat    "catalina.sh run"   8 seconds ago   Up 6 seconds   8080/tcp   peaceful_mcnulty
# 交互模式进入tomcat
root@ubuntu:/home/peek# docker exec -it cedf6e527bb4 /bin/bash
# 查看文件
root@cedf6e527bb4:/usr/local/tomcat# ls
bin           conf             lib      logs            NOTICE     RELEASE-NOTES  temp     webapps.dist
BUILDING.txt  CONTRIBUTING.md  LICENSE  native-jni-lib  README.md  RUNNING.txt    webapps  work
# 复制文件到指定目标下
root@cedf6e527bb4:/usr/local/tomcat# cp -r webapps.dist/* webapps/
root@cedf6e527bb4:/usr/local/tomcat# cd webapps
root@cedf6e527bb4:/usr/local/tomcat/webapps# ll
total 32
drwxr-xr-x  1 root root 4096 Dec 24 12:31 ./
drwxr-xr-x  1 root root 4096 Dec  9 20:41 ../
drwxr-xr-x 15 root root 4096 Dec 24 12:31 docs/
drwxr-xr-x  7 root root 4096 Dec 24 12:31 examples/
drwxr-xr-x  6 root root 4096 Dec 24 12:31 host-manager/
drwxr-xr-x  6 root root 4096 Dec 24 12:31 manager/
drwxr-xr-x  3 root root 4096 Dec 24 12:31 ROOT/
# 退出
root@cedf6e527bb4:/usr/local/tomcat/webapps# exit
# 查看容器id
root@ubuntu:/home/peek# docker ps
CONTAINER ID   IMAGE     COMMAND             CREATED              STATUS              PORTS      NAMES
cedf6e527bb4   tomcat    "catalina.sh run"   About a minute ago   Up About a minute   8080/tcp   peaceful_mcnulty
# 打包生成镜像
	# -a：作者名称为：changjing
    # -m：附带的信息为：add webappsFile
    # cedf6e527bb4：为要打包的容器id
    # tomcat01：为打包的镜像名称
    # 1.0：为tag标签信息
root@ubuntu:/home/peek# docker commit -a="changjing" -m="add webappsFile" cedf6e527bb4 tomcat01:1.0
sha256:46a21b743f69855c6b9ba8ff0683aa5b5f0ccbb1ba5fe62a62a7c27822daa994
# 查看所有镜像，发送已经成功生成
root@ubuntu:/home/peek# docker images
REPOSITORY            TAG       IMAGE ID       CREATED         SIZE
tomcat01              1.0       46a21b743f69   5 seconds ago   478MB
tomcat                latest    1dad8c5497f9   2 weeks ago     474MB
tomcat                9.0       24849d4d07c1   2 weeks ago     476MB
portainer/portainer   latest    5f11582196a4   4 weeks ago     287MB
```

