# [羊城杯 2020]a_piece_of_java

## 0、



## 1、审计

> 使用Java反编译攻击打开jar包，可以发现如下文件夹
>
> ```nginx
> web
> ├─ ChallengeApplication.class
> ├─ controller
> ├─ invocation
> └─ model
> ```

> **首先看到controller**

```java
package BOOT-INF.classes.gdufs.challenge.web.controller;

import gdufs.challenge.web.model.Info;
import gdufs.challenge.web.model.UserInfo;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;
import java.util.Base64;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;
import org.nibblesec.tools.SerialKiller;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class MainController {
  
  // 主页
  @GetMapping({"/index"})
  // 会判断是否存在cookie，有cookie重定向 
  public String index(@CookieValue(value = "data", required = false) String cookieData) {
    if (cookieData != null && !cookieData.equals(""))
      return "redirect:/hello"; 
    return "index";
  }
  
  // 传入用户名密码并设置到cookie中，然后重定向到/hello
  @PostMapping({"/index"})
  public String index(@RequestParam("username") String username, @RequestParam("password") String password, HttpServletResponse response) {
    UserInfo userinfo = new UserInfo();
    userinfo.setUsername(username);
    userinfo.setPassword(password);
    Cookie cookie = new Cookie("data", serialize(userinfo));
    cookie.setMaxAge(2592000);
    response.addCookie(cookie);
    return "redirect:/hello";
  }
  
  // 
  @GetMapping({"/hello"})
  public String hello(@CookieValue(value = "data", required = false) String cookieData, Model model) {
    if (cookieData == null || cookieData.equals(""))
      return "redirect:/index"; 
    // 反序列化cookie，获取用户对象
    Info info = (Info)deserialize(cookieData);
    if (info != null)
      model.addAttribute("info", info.getAllInfo()); 
    return "hello";
  }
  
  private String serialize(Object obj) {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    try {
      ObjectOutputStream oos = new ObjectOutputStream(baos);
      oos.writeObject(obj);
      oos.close();
    } catch (Exception e) {
      e.printStackTrace();
      return null;
    } 
    return new String(Base64.getEncoder().encode(baos.toByteArray()));
  }
  
  private Object deserialize(String base64data) {
    Object obj;
    ByteArrayInputStream bais = new ByteArrayInputStream(Base64.getDecoder().decode(base64data));
    try {
      SerialKiller serialKiller = new SerialKiller(bais, "serialkiller.conf");
      obj = serialKiller.readObject();
      serialKiller.close();
    } catch (Exception e) {
      e.printStackTrace();
      return null;
    } 
    return obj;
  }
}

```

> 反序列化点位置

```nginx
  // 
  @GetMapping({"/hello"})
  public String hello(@CookieValue(value = "data", required = false) String cookieData, Model model) {
    if (cookieData == null || cookieData.equals(""))
      return "redirect:/index"; 
    // 反序列化cookie，获取用户对象
    Info info = (Info)deserialize(cookieData);
    if (info != null)
      model.addAttribute("info", info.getAllInfo()); 
    return "hello";
  }
```

> `serialkiller.conf`文件中白名单

```nginx
<?xml version="1.0" encoding="UTF-8"?>
<!-- serialkiller.conf -->
<config>
    <refresh>6000</refresh>
    <mode>
        <!-- set to 'false' for blocking mode -->
        <profiling>false</profiling>
    </mode>
    <blacklist>

    </blacklist>
    <whitelist>
        <regexp>gdufs\..*</regexp>
        <regexp>java\.lang\..*</regexp>
    </whitelist>
</config>
```

> 在`/hello"`方法中还可以看到需要传入一个model，这个是model对象，可以传入参数为model文件夹中的class

```nginx
model
├─ DatabaseInfo.class
├─ Info.class
└─ UserInfo.class
```

> 在依次查看这三个类，在`DatabaseInfo.class`可以发现jdbc反序列化
>
> 而且对参数没有过滤

```nginx
private void connect() {
        String url = "jdbc:mysql://" + this.host + ":" + this.port + "/jdbc?user=" + this.username + "&password=" + this.password + "&connectTimeout=3000&socketTimeout=6000";

        try {
            this.connection = DriverManager.getConnection(url);
        } catch (Exception var3) {
            var3.printStackTrace();
        }

    }
```

> 最后再看看`invocation`文件夹中的类是干什么的

```nginx

```

