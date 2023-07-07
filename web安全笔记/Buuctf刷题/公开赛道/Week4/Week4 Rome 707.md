# Week4 Rome 707

## 0、知识点与工具

>   java ROME反序列化

>   [jd-gui反编译工具](http://java-decompiler.github.io/)

>   [ysoserial反序列化工具](https://github.com/frohoff/ysoserial/releases/tag/v0.0.6)



## 1、分析

>   首先下载jar包然后使用jd-gui进行反编译
>
>   然后在META-INF中查看入口函数

![](https://peekab.oss-cn-hangzhou.aliyuncs.com/ctfImg/NewStarCTF/Week3/202212071515878.png)

>   发现主函数同文件中有一个controller，

![](https://peekab.oss-cn-hangzhou.aliyuncs.com/ctfImg/NewStarCTF/Week3/20221207151623.png)

>   可以发现这里是反序列点



## 2、关于ROME

>   Rome 就是为 RSS聚合开发的[框架](https://so.csdn.net/so/search?q=框架&spm=1001.2101.3001.7020)， 可以提供RSS阅读和发布器

>   Rome 提供了 **ToStringBean** 这个类，提供深入的 toString 方法对[JavaBean](https://so.csdn.net/so/search?q=JavaBean&spm=1001.2101.3001.7020)进行操作

==ROME的利用链==

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

