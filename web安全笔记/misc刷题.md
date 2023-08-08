

## [SWPU 2019]神奇的二维码

### 查看文件成分

``` nginx
[09:23:13] [/tmp/misc] ❱❱❱ binwalk MISC-神奇的二维码-BitcoinPay.png

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             PNG image, 400 x 400, 8-bit/color RGBA, non-interlaced
28932         0x7104          RAR archive data, version 5.x
29034         0x716A          RAR archive data, version 5.x
94226         0x17012         RAR archive data, version 5.x
99220         0x18394         RAR archive data, version 5.x
```
> **可以发现存在几个压缩包**

### 分离出压缩包

``` NGINX
binwalk -e MISC-神奇的二维码-BitcoinPay.png

[09:25:12] [/tmp/misc] ❱❱❱ ls
1  MISC-神奇的二维码-BitcoinPay.png  _MISC-神奇的二维码-BitcoinPay.png.extracted
[09:25:14] [cost 0.087s] ls

[09:25:15] [/tmp/misc] ❱❱❱ cd _MISC-神奇的二维码-BitcoinPay.png.extracted
[09:25:17] [cost 0.077s] cd _MISC-神奇的二维码-BitcoinPay.png.extracted

[09:25:17] [/tmp/misc/_MISC-神奇的二维码-BitcoinPay.png.extracted] ❱❱❱ ls
17012.rar  18394.rar  7104.rar  716A.rar

```

### 解压

```nginx
# 使用 unrar命令解压，没有使用下面命令安装
	sudo apt-get update
	sudo apt-get install unrar

# 
unrar e 17012.rar
unrar e 18394.rar		# 解不开，需要密码
unrar e 7104.rar
unrar e 716A.rar
```

### 分析

```nginx
[09:36:30] ❱❱❱ cat encode.txt
YXNkZmdoamtsMTIzNDU2Nzg5MA==%

# 解码
asdfghjkl1234567890

# 解压文件 看看flag在不在里面^_^.rar 密码为上面的

# 解码flag.doc内容
一直base64解码，直到解不动为止

# 获取解压18394.rar的密码
comEON_YOuAreSOSoS0great
```

