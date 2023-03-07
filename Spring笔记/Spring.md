# 目录

[TOC]



## [1、Spring简介](#目录)

-   Spring：春天 ---> 给软件行业带来了春天
-   2002,首次推出了Spring框架的雏形: interface21框架!
-   Spring框架即以interface21框架为基础,经过重新设计 ,并不断丰富其内涵,于2004年月24日，发布了1.0正式版。
-   Spring以IOC（反转控制）赫尔AOP（面向切面编程）为内核
-   Spring提供了展现SpringMVC和持久层Spring JDBCTemplate以及业务层事务管理等众多的企业级应用技术
-   **Rod Johnson**，Spring Framework创始人， 著名作者。很难想象Rod Johnson的学历， 真的让好多人大吃一
    惊，他是悉尼大学的博士,然而他的专业不是计算机，而是音乐学。
-   **Spring理念: 使现有的技术更加容易使用，本身是一个大杂烩， 整合了现有的技术框架!**
-   SSH : Struct2 + Spring + Hibernate! (以前) 
-   SSM : SpringMvc + Spring + Mybatis!  

Spring => **轻量级开源框架**

官网：https://spring.io/projects/spring-framework#learn

下载地址：https://repo.spring.io/release/org/springframework/spring/

GitHub地址：https://github.com/spring-projects/spring-framework

官方文档：https://docs.spring.io/spring-framework/docs/current/reference/html/core.html#spring-core

**maven仓库地址**

![image-20210303153513429](G:\各科笔记\Spring笔记\Spring.assets\image-20210303153513429.png)

```xml
<properties>
    <spring.version>5.0.5.RELEASE</spring.version>
</properties>
<!--导入spring的context坐标，context依赖core、beans、expression-->
<dependencies> 
    <dependency>  
        <groupId>org.springframework</groupId> 
        <artifactId>spring-context</artifactId> 
        <version>${spring.version}</version>
    </dependency>
</dependencies>

<!-- Maven地址 -->
<!-- https://mvnrepository.com/artifact/org.springframework/spring-aop -->
<dependency>
    <groupId>org.springframework</groupId>
    <artifactId>spring-aop</artifactId>
    <version>5.2.0.RELEASE</version>
</dependency>
```



1、优点

-   Spring是一个开源的免费的框架（容器！）

-   Spring是一个轻量级的、非入侵式的框架，也就是导入它并不会对你项目产生影响

-   特性：控制反转（IOC） ， 面向切面编程（AOP）

-   **支持事务的处理（声明式事务管理）**，对框架的整合支持

-   **方便解耦**，简化开发

-   提高开发效率，提高可维护性，提高可扩展性

    >    通过 Spring 提供的 IOC容器，可以将对象间的依赖关系交由 Spring 进行控制，避免硬编码所造成的过度耦合。用户也不必再为单例模式类、属性文件解析等这些很底层的需求编写代码，可以更专注于上层的应用。

-   方便集成各种优秀框架

    >   对各种优秀框架（Struts、Hibernate、Hessian、Quartz等）的支持

-   降低JavaEE API 的使用难度

    >   对 JavaEE API（如 JDBC、JavaMail、远程调用等）进行了薄薄的封装层，使这些 API 的使用难度大为降低

-   



**总结：Spring就是一个轻量级的控制反转（IOC） 和 面向切面编程（AOP）的框架**



#### 2、组成(体系)

![image-20210309093510518](G:\各科笔记\Spring笔记\Spring.assets\image-20210309093510518.png)

![image-20210312085645481](G:\各科笔记\Spring笔记\Spring.assets\image-20210312085645481.png)

#### 3、[扩展](##1、Spring简介)



![image-20210309093754486](G:\各科笔记\Spring笔记\Spring.assets\image-20210309093754486.png)



-   Spring Boot
    -   一个快速开发的脚手架
    -   基于SpringBoot可以快速的开发单个微服务
    -   约定大于配置
-   Spring Cloud
    -   SpringCLoud是基于SpringBoot实现的



因为现在大多数公司都在使用SpringBoot进行快速开发，学习SpringBoot的前提， 需要完全掌握Spring及
SpringMVC!  



**Spring弊端:发展了太久之后，违背了原来的理念!配置十分繁琐,人称:”配置地狱!”**



## [2、IOC理论推导](##1、Spring简介)

 1、UserDao 接口

```java
public interface UserDao {

    void getUser();
}

```

 2、UserDaoImpl 实现类

```java
public class UserDaoImpl implements UserDao {
    public void getUser() {
        System.out.println("默认获取用户的数据");
    }
}

public class UserDaoMysqlImpl implements UserDao {
    public void getUser() {
        System.out.println("通过MySQL获取数据");
    }
}

public class UserDaoOracleImpl implements UserDao{
    public void getUser() {
        System.out.println("从Oracle中获取数据");
    }
}

```

 3、UserService 业务接口

```java
public interface UserService {

    void getUser();
}
```

 4、UserServiceImpl 业务接口实现类

```java
public class UserServiceImpl implements UserService {

    // 使用组合
    private UserDao userDao = new UserDaoImpl();

    public void setUserDao(UserDao userDao) {
        this.userDao = userDao;
    }

    public void getUser() {
        userDao.getUser();
    }
}
```



在我们之前的业务中，用户的需求可能会影响我们原来的代码，我们需要根据用户的需求去修改原代码!如果程序代码量十分大，修改- -次的成本代价十分昂贵!|

我们使用一个set接口实现，已经发生了革命性的变化

```java
public class UserServiceImpl implements UserService {

    // 使用组合
    private UserDao userDao = new UserDaoImpl();

    public void setUserDao(UserDao userDao) {
        this.userDao = userDao;
    }

    public void getUser() {
        userDao.getUser();
    }
}
```

-   之前，程序是主动创建对象！控制权在程序员手上
-   使用set注入后，程序不再具有主动性，而是变成了被动的接受对象
-   这就是控制反转（IOC）

**这种思想，从本质上解决了问题，不用在去管理对象，系统的耦合性大大降低，可以更加专注在业务上**,

**这就是IOC的原型**

**[测试](##1、Spring简介)**

```java
import com.wlp.dao.UserDaoImpl;
import com.wlp.service.UserServiceImpl;
import com.wlp.service.UserService;

/**
 * 功能：
 *
 * @author 武乐萍
 * @modifier 武乐萍
 * @date 2021-03-09 14:27
 * @Version V1.0
 */
public class MyTest {

    public static void main(String[] args) {

        UserService userSercice = new UserServiceImpl();

        ((UserServiceImpl)userSercice).setUserDao(new UserDaoImpl());

        userSercice.getUser();
    }
}

```





#### **1、[I0C本质](##1、Spring简介)**

**控制反转**loC(Inversion of Control),是一种设计思想，DI(依赖注入)是实现IoC的一种方法，也有人认为DI只是IoC的另一种说法。没有IoC的程序中,我们使用面向对象编程,对象的创建与对象间的依赖关系完全硬编码在程序中，对象的创建由程序自己控制，控制反转后将对象的创建转移给第三方，个人认为所谓控制反转就是:获得依赖对象的方式反转了。



采用XML方式配置Bean的时候，Bean的定义信息是和实现分离的，而采用注解的方式可以把两者合为一体,Bean的定义信息直接以注解的形式定义在实现类中，从而达到了零配置的目的。



**控制反转是一种通过描述(XML或注解)并通过第三方去生产或获取特定对象的方式。在Spring中实现控制反转的是IoC容器，其实现方法是依赖注入(Dependency Injection,DI)。**



#### 2**、[hello Spring](##1、Spring简介)**

##### 1、xml文件配置

```xml
<?xml version="1.0" encoding="UTF-8"?>
<beans xmlns="http://www.springframework.org/schema/beans"
       xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
       xsi:schemaLocation="http://www.springframework.org/schema/beans
       http://www.springframework.org/schema/beans/spring-beans.xsd">

    <!-- 将创建对象的交给Spring来管理 -->
    <bean id="Impl" class="com.wlp.dao.UserDaoImpl" />
    <bean id="MysqlImpl" class="com.wlp.dao.UserDaoMysqlImpl" />
    <bean id="oracle" class="com.wlp.dao.UserDaoOracleImpl" />

    <!-- 创建业务层对象 -->
    <bean id="service" class="com.wlp.service.UserServiceImpl">
        <property name="userDao" ref="MysqlImpl"></property>
     </bean>
    <!--
        ref ：传入已经被Spring管理的beanid
        values：传入基本数据类型的值
     -->
</beans>
```

##### **2、[测试](##1、Spring简介)**

```java
import com.wlp.dao.UserDaoImpl;
import com.wlp.dao.UserDaoMysqlImpl;
import com.wlp.service.UserServiceImpl;
import com.wlp.service.UserService;
import org.springframework.context.ApplicationContext;
import org.springframework.context.support.ClassPathXmlApplicationContext;

/**
 * 功能：
 *
 * @author 武乐萍
 * @modifier 武乐萍
 * @date 2021-03-09 14:27
 * @Version V1.0
 */
public class MyTest {

    public static void main(String[] args) {

        // 获取ApplicationContext对象，拿到Spring容器
        ApplicationContext context = new ClassPathXmlApplicationContext("beans.xml");

        // 需要执行哪个业务实现就get哪个
        UserDaoMysqlImpl mysqlImpl = (UserDaoMysqlImpl) context.getBean("MysqlImpl");

        // 获取用户数据
        mysqlImpl.getUser();
    }
}

```



思考问题?

-   Hello对象是谁创建的?
-   hello对象是由Spring创建的
-   Hello对象的属性是怎么设置的?
-   hello对象的属性是由Spring容器设置的，



-   **这个过程就叫控制反转:**

    -   **控制**: 谁来控制对象的创建,传统应用程序的对象是由程序本身控制创建的,使用Spring后,对象是由Spring来创
        建的.
    -   **反转**: 程序本身不创建对象,而变成被动的接收对象.
    -   **依赖注入**: 就是利用set方法来进行注入的.
    -   **I0C是一种编程思想,由主动的编程变成被动的接收.**

    -   可以通过**new ClassPathXmlApplicationContext**去浏览一下底层源码 .

    

    **OK ,到了现在,我们彻底不用再程序中去改动了,要实现不同的操作,只需要在xmI配置文件中进行修改,所谓的**
    **loC,一句话搞定:对象由Spring来创建,管理, 装配!**



#### 3、[IOC创建对象的方法](##1、Spring简介)

**默认使用无参构造创建对象，默认**

##### 使用有参构造创建对象

​	**1、下标赋值**

```xml
<!-- 第一种：下标赋值！ -->
<bean id="user" class="com.wlp.pojo.user">
    <constructor-arg index="0" value="java" />
</bean>

<!-- 官方案例 -->
<bean id="exampleBean" class="examples.ExampleBean">
    <constructor-arg index="0" value="7500000"/>
    <constructor-arg index="1" value="42"/>
</bean>
```

​	**2、[类型](##1、Spring简介)**

```xml
<!-- 第二种方式：通过类型创建，如果参数为俩个且都是同一类型，就不好搞 -->
<bean id="user" class="com.wlp.pojo.user">
    <constructor-arg type="java.lang.String" value="java" />
</bean>

<!-- 官方案例 -->
<bean id="exampleBean" class="examples.ExampleBean">
    <constructor-arg type="int" value="7500000"/>
    <constructor-arg type="java.lang.String" value="42"/>
</bean>
```

​	**3、参数名**

```xml
<!-- 第三种：直接通过参数名来设置 -->
<bean id="user" class="com.wlp.pojo.user">
    <constructor-arg name="name" value="java" />
</bean>

<!-- 官方案例 -->
<!-- 当属性为一个对象时 -->
<beans>
    <bean id="beanOne" class="x.y.ThingOne">
        <constructor-arg ref="beanTwo"/>
        <constructor-arg ref="beanThree"/>
    </bean>

    <bean id="beanTwo" class="x.y.ThingTwo"/>
    <bean id="beanThree" class="x.y.ThingThree"/>
</beans>
```

```java
public class SimpleMovieLister {

    // the SimpleMovieLister has a dependency on a MovieFinder
    private MovieFinder movieFinder;

    // a constructor so that the Spring container can inject a MovieFinder
    public SimpleMovieLister(MovieFinder movieFinder) {
        this.movieFinder = movieFinder;
    }

    // business logic that actually uses the injected MovieFinder is omitted...
}
```



**总结：在配置文件加载的时候，容器（beans.xml）中管理的对象就已经初始化了**



## 3、[Spring配置](##1、Spring简介)

#### 1、别名

```xml
<!--别名，如果添加了别名，我们也可以使用别名获取到这个对象-->
<alias name="user" alias="userNew" />

```

#### 2、配置

```xml
<!--
        id: bean的唯一标识符，也就是相当于我们的学的对象名
        class：bean对象所对应的全限定名：包名 + 类型
        name：也是别名，而且name可以同时取多个别名可以用空格、分号、逗号隔开
        scope：作用域
     -->
<bean id="user" class="com.wlp.pojo.user" name="user2 u3,u4;u5">
    <constructor-arg name="name" value="java" />
</bean>

```

#### 3、[import](##1、Spring简介)

这个import，一般用于团队开发，他可以将多个配置文件，合成为一个

假设，现在项目中有多个开发，这三个人复制不同的类开发，不同的类需要

注册在不同的bean中，我们可以利用import将所有人的beans.xml和并为一个

-   **applicationContext.xml**

使用的时候，直接使用总的配置就可以了

```xml
<import resource="beans.xml"/>
<import resource="beans2.xml2 "/>
<import resource="beans3.xml3"/>
```

使用的时候，直接使用总的配置就可以了

**内容相同也会被合并 **



## 4、[DI依赖注入](##1、Spring简介)

![image-20210311180721444](G:\各科笔记\Spring笔记\Spring.assets\image-20210311180721444.png)

#### 1、[构造器注入](##1、Spring简介)

```xml
<bean id="user" class="com.wlp.pojo.user">
    <constructor-arg type="java.lang.String" value="java" />  => 需要提供有参构造方法
</bean>
```





#### 2、Set方式注入【重】

​	1、复杂类型

```java
public class  Address {
    private String address;

    public String getAddress() {
        return address;
    }

    public void setAddress(String address) {
        this.address = address;
    }
    
    @Override
    public String toString() {
        return "Address{" +
                "address='" + address + '\'' +
                '}';
    }
}
```

​	2、真实测试对象

```java
public class Student {

    private String name;
    private Address address;
    private String[] books;
    private List<String> hobbys;
    private Map<String,String> card;
    private Set<String> games;
    private String wife;
    private Properties info;
    
    // 省略所有的get与set方法
    
    @Override
    public String toString() {
        return "Student{" +
                "name='" + name + '\'' +
                ", address=" + address.toString() +
                ", books=" + Arrays.toString(books) +
                ", hobbys=" + hobbys +
                ", card=" + card +
                ", games=" + games +
                ", wife='" + wife + '\'' +
                ", info=" + info +
                '}';
    }
}
```

​	**3、Spring配置**

```java
<?xml version="1.0" encoding="UTF-8"?>
<beans xmlns="http://www.springframework.org/schema/beans"
       xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
       xsi:schemaLocation="http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans.xsd">

    <!-- 设置别名 -->
    <bean id="address" class="com.wlp.pojo.Address" />

    <bean id="student" class="com.wlp.pojo.Student">
        <!-- 第一种：普通注册 values -->
        <property name="name" value="wlp" />

        <!-- 第二种：Bean注入 ref -->
        <property name="address" ref="address" />

        <!-- 第三种：数组注入 ref -->
        <property name="books">
            <array>
                <value>new Game</value>
                <value>奇诺之旅</value>
                <value>喜洋洋</value>
            </array>
        </property>

        <!-- 第四种：list ref -->
        <property name="hobbys">
            <list>
                <value>听歌</value>
                <value>敲代码</value>
            </list>
        </property>

        <!-- 第五种：map ref -->
        <property name="card">
            <map>
                <entry key="分钟" value="213"></entry>
                <entry key="银行卡" value="sdf"></entry>
            </map>
        </property>

        <!-- 第六种：set ref -->
        <property name="games">
            <set>
                <value>猴子塔防</value>
                <value>cf</value>
            </set>
        </property>

        <!-- 第七种：null -->
        <property name="wife">
            <null></null>
        </property>

        <!-- 第八种：Properties  -->
        <property name="info">
            <props>
                <prop key="学号">201911000</prop>
                <prop key="性别">男</prop>
                <prop key="drive">oracle</prop>
            </props>
        </property>

     </bean>
</beans>
```

​	4、**test测试**

```java
import com.wlp.pojo.Student;
import org.springframework.context.ApplicationContext;
import org.springframework.context.support.ClassPathXmlApplicationContext;

/**
 * 功能：
 *
 * @author 武乐萍
 * @modifier 武乐萍
 * @date 2021-03-09 21:49
 * @Version V1.0
 */
public class myTest {

    public static void main(String[] args) {

        ApplicationContext context = new ClassPathXmlApplicationContext("beans.xml");

        Student student = (Student) context.getBean("student");
        System.out.println(student.toString());

    }
}

```



#### 3、[扩展方法注入](##1、Spring简介)

我们可以使用p命名空间和c命名空间进行注入

官方解释：

![image-20210310083018351](G:\各科笔记\Spring笔记\Spring.assets\image-20210310083018351.png)

**使用！**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<beans xmlns="http://www.springframework.org/schema/beans"
       xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
       xmlns:p="http://www.springframework.org/schema/p"
       xmlns:c="http://www.springframework.org/schema/c"
       xsi:schemaLocation="http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans.xsd">

    <!-- p命名空间注入，可以直接注入属性的值 property-->
    <bean id="user" class="com.wlp.pojo.User" p:name="神仙" p:age="19" />

    <!--
        c命名空间注入，通过构造器注入：construct-args
        其实体类必须有有参构造方法和无参构造方法
    -->
    <bean id="user2" class="com.wlp.pojo.User" c:age="18" c:name="神仙" />

</beans>
```

**测试**

```java
@Test
public void test2(){
	ApplicationContext context = new ClassPathXmlApplicationContext("beans.xml");
    User user = context.getBean("user2",User.class);
	System.out.println(user);
}
```

**【需要导入的xml约束】**

```xml
<!--
	xmlns:p="http://www.springframework.org/schema/p"
	xmlns:c="http://www.springframework.org/schema/c"
-->
```



#### 5、[Bean的作用域](##1、Spring简介)

![image-20210310090305504](G:\各科笔记\Spring笔记\Spring.assets\image-20210310090305504.png)



##### 1、单例模式（Spring默认机制）

```xml
<bean id="user2" class="com.wlp.pojo.User" c:age="18" c:name="神仙" scope="singleton"/>
```



##### 2、原型模式

**每次从容器中get的时候，都会产生一个新对象**

```xml
<bean id="accountService" class="com.something.DefaultAccountService" scope="prototype"/>
```



##### 3、其他

-   **request、session、application 这些只能在web开发中使用**



## 5、Bean的自动装配

-   自动装配是Spring满足bean依赖的一种方式
-   Spring会在上下文中自动寻找，并自动给bean装配属性！



在Spring中有三种自动装配方式

1.  在xml中显示的配置
2.  在java中显示的配置
3.  隐式的自动装配bean【重】



#### 1、测试

1.  环境搭建
    -   一个人有两个宠物

-   实体：

```java
public class Cat {
    public void shou(){
        System.out.println("喵");
    }
}

public class Dog {

    public void shou(){
        System.out.println("汪");
    }
}

public class People {

    private Cat cat;
    private Dog dog;
    private String name;
    
    public Cat getCat() {
        return cat;
    }

    public void setCat(Cat cat) {
        this.cat = cat;
    }

    public Dog getDog() {
        return dog;
    }

    public void setDog(Dog dog) {
        this.dog = dog;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    @Override
    public String toString() {
        return "People{" +
                "cat=" + cat +
                ", dog=" + dog +
                ", name='" + name + '\'' +
                '}';
    }
}

```

-   配置

```xml
<?xml version="1.0" encoding="UTF-8"?>
<beans xmlns="http://www.springframework.org/schema/beans"
       xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
       xsi:schemaLocation="http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans.xsd">

    <bean id="car" class="com.wlp.pojo.Cat" />
    <bean id="dog" class="com.wlp.pojo.Dog" />

    <bean id="people" class="com.wlp.pojo.People">
        <property name="name" value="神仙" />
        <property name="dog" ref="dog" />
        <property name="cat" ref="car" />
    </bean>
</beans>
```



#### 2、byName自动装配

```xml
<?xml version="1.0" encoding="UTF-8"?>
<beans xmlns="http://www.springframework.org/schema/beans"
       xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
       xsi:schemaLocation="http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans.xsd">

    <bean id="cat" class="com.wlp.pojo.Cat" />
    <bean id="dog" class="com.wlp.pojo.Dog" />


    <!--
        byName: 会自动在容器上下文中查找，和自己对象set方法后面的值对象的beanId
                如果beanId与set方法值不一致会出现空指针异常！
    -->
    <bean id="people" class="com.wlp.pojo.People" autowire="byName">
        <property name="name" value="神仙" />
    </bean>
</beans>
```

#### 3、byType自动装配

```xml
<?xml version="1.0" encoding="UTF-8"?>
<beans xmlns="http://www.springframework.org/schema/beans"
       xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
       xsi:schemaLocation="http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans.xsd">

    <bean id="cat" class="com.wlp.pojo.Cat" />
    <bean id="dog" class="com.wlp.pojo.Dog" />


    <!--
        byName: 会自动在容器上下文中查找，和自己对象set方法后面的值对象的beanId
                如果beanId与set方法值不一致会出现空指针异常！

		byType: 会自动在容器上下文中查找，和自己对象属性类型相同的bean！
				必须保证此类型全局唯一，且不写beanId也可以直接运行
				出现两个类型一致beanId不同的bean会报错！
    -->
    <bean id="people" class="com.wlp.pojo.People" autowire="byType">
        <property name="name" value="神仙" />
    </bean>
</beans>
```

[dsgds](https://translate.google.com/?hl=zh-CN&sl=auto&tl=zh-CN&op=translate)

**小结：**

-   byName的时候，需要保证所有**bean的id唯一**，并且此bean需要和
    -   自动注入的属性的set方法的值一致
-   byType的时候，需要保证所有**bean的class唯一**
    -   并且这个bean需要和自动注入的属性类型一致



## 6、注解实现自动装配

**官方文档位置**

![image-20210311203936956](G:\各科笔记\Spring笔记\Spring.assets\image-20210311203936956.png)



**Jdk1.5支持注解，Spring2.5支持注解！**

#### 0、Spring注解介绍

>   **Spring是轻代码而重配置的框架，配置比较繁重，影响开发效率，所有注解开发是一种趋势，注解代理xml配置文件可以简化配置，提高开发效率	**



#### 1、准备工作

-   导入约束

>   xmlns:context="http://www.springframework.org/schema/context"  **=>** **context约束**
>
>   xsi:schemaLocation="http://www.springframework.org/schema/beans
>           https://www.springframework.org/schema/beans/spring-beans.xsd
>           http://www.springframework.org/schema/context
>           https://www.springframework.org/schema/context/spring-context.xsd"  **=> context约束支持**

-   配置注解支持

```xml
<?xml version="1.0" encoding="UTF-8"?>
<beans xmlns="http://www.springframework.org/schema/beans"
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
    xmlns:context="http://www.springframework.org/schema/context"
    xsi:schemaLocation="http://www.springframework.org/schema/beans
        https://www.springframework.org/schema/beans/spring-beans.xsd
        http://www.springframework.org/schema/context
        https://www.springframework.org/schema/context/spring-context.xsd">

    <!-- 开启注解支持，没开注解无效！ -->
    <context:annotation-config/>

</beans>
```



#### **2、@Autowired的使用**

**直接在属性上使用即可！ 也可以在set方法上使用**

-   **使用Autowired之后可以 不用编写Set方法，前提是这个自动装配的属性在IOC（Spring）**

-   **容器中存在，且符合名字ByName**

```java
package com.wlp.pojo;

import org.springframework.beans.factory.annotation.Autowired;

/**
 * 功能： 人
 *
 * @author 武乐萍
 * @modifier 武乐萍
 * @date 2021-03-10 10:04
 * @Version V1.0
 */
public class People {

    @Autowired
    private Cat cat;
    @Autowired
    private Dog dog;
    private String name;

    public Cat getCat() {
        return cat;
    }

    @Autowired
    public void setCat(Cat cat) {
        this.cat = cat;
    }

    public Dog getDog() {
        return dog;
    }

    @Autowired
    public void setDog(Dog dog) {
        this.dog = dog;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    @Override
    public String toString() {
        return "People{" +
                "cat=" + cat +
                ", dog=" + dog +
                ", name='" + name + '\'' +
                '}';
    }
}

```

##### **科普**

**@Nullable  字段标签了这个注解，说明这个字段可以为null**

```java
import org.springframework.lang.Nullable;
public class People {

    // 如果显示的定义了Autowired的require为false，说明这个对象可以为null，
    // 否则不允许为空
    @Autowired(required = false)
    private Cat cat;
    
     @Autowired
    public void setCat(@Nullable Cat cat) {
        this.cat = cat;
    }
}
```

>   如果@Autowired自动装配环境比较复杂，自动装配无法通过一个注解【@Autowired】完成的时候，
>
>   我们可以使用@Qualifier(value = "beanId")去配合@Autowired的使用，指定一个唯一的bean对象注入！

```java

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
public class People {    
	@Autowired(required = false)
    private Cat cat;
    @Autowired
    @Qualifier(value = "dog")
    private Dog dog;
}
```

**@Resourse注解  拥有Auotwired和Qualifier的功能**  会根据beanId去自动装配，beanid无效然后根据class装配

```java
public class People {
	
    // 如果显示的定义了Autowired的require为false，
    // 说明这个对象可以为null，否则不允许为空
    @Resource(name = "cat")
    private Cat cat;
    @Autowired
    @Qualifier(value = "dog")
    private Dog dog;
    private String name;·
}
```



**小结：**

-   @Resource和@ Autowired的区别:

    -   都是用来自动装配的，都可以放在属性字段上

    -   @Autowired通过byType的方式实现，而且必须要求这个对象存在！【常用】

    -   @Resource 默认通过byname的方式实现，如果找不到名字，则通过byType实现!

        如果两个都找不到的情况下，就报错!

    -   **执行顺序：@Autowired通过byType的方式实现，@Resource 默认通过byname的方式实现**



## 7、注解开发

#### 1、在spring4之后，使用注解开发，必须要保证aop包的导入

![image-20210311214236281](G:\各科笔记\Spring笔记\Spring.assets\image-20210311214236281.png)



#### 2、导入context约束，增加注解支持

​		

#### 3、编写bean

#### 4、属性如何注入

```java
// 等价于   <bean id="user" class="com.wlp.pojo.User"/>
    //@Component 组件
@Component
public class User {

    public String name = "神仙";

    // 相当于 <property name="name" value="神仙" />
    @Value("神仙")
    public void setName(String name) {
        this.name = name;
    }
}
```



##### 1、衍生的注解

@Component的衍生注解，在web中会按照mvc三层结构分层

-   dao 【@Repository】
-   service 【@Service】
-   controller 【@Controller】

功能都是一样的，都是代表将某个类注册到Spring中，装配bean

##### 2、自动配置配置

>   @Autowired：自动装配通过类型，名字
>
>   ​	如果Autowired不能唯一自动装配上属性，则需要通过@Qualifier
>
>   @Nullable：作用于字段上，说明这个字段可以为null
>
>   @Recource：自动装配通过名字，类型

##### 3、作用域

```java
@Component
@Scope("singleton")
public class User {
    
}
```



#### **4、小结**

​	xml.与注解: 

-   ​	
    -   xml 更加万能，适用于任何场合!维护简单方便
    -   注解不是自己类使用不了，维护相对复杂!

     xml与注解最佳实践:

    -   xml用来管理bean;
    -   注解只负责完成属性的注入;
    -   在使用的过程中，只需要注意一个问题: 必须让注解生效,就需要开启注解的支持





## 8、完全使用java配置Spring

**完全不使用Spring的xml配置，全权交给Java来做**

![](G:\各科笔记\Spring笔记\Spring.assets\image-20210312092409880.png)



#### 1、编写实体测试类

```java
package com.wlp.pojo;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * 功能：
 *
 * @author 武乐萍
 * @modifier 武乐萍
 * @date 2021-03-12 10:24
 * @Version V1.0
 */
// 这个注解的用意：说明这个类被Spring接管了，注册到容器中了
@Component
public class User {
    private String name;

    public String getName() {
        return name;
    }

    @Value("shenxian") // 属性注入值
    public void setName(String name) {
        this.name = name;
    }

    @Override
    public String toString() {
        return "User{" +
                "name='" + name + '\'' +
                '}';
    }
}

```

#### 2、编写配置类

```java
package com.wlp.config;

import com.wlp.pojo.User;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

/**
 * 功能：
 *
 * @author 武乐萍
 * @modifier 武乐萍
 * @date 2021-03-12 10:22
 * @Version V1.0
 */
    // 这个注解作用的类也会被Spring容器托管，它原本为一个@Component
    // @Configuration 代表这是一个配置类，就和beans.xml差不多
@Configuration
@ComponentScan("com.wlp") // 扫描包注册
@Import(wlpConfig2.class) // 使用import导入多个配置类 
public class wlpConfig {

    @Bean
    // 注册一个bean，就相当于xml中的bean标签
    // 这个方法的名称，就相当于bean标签中的id
    // 这个方法的返回值，就相当于bean标签中的class属性
    public User getUser(){
        return new User(); // 这是返回注入的到bean的对象
    }
}

```

### 3、[测试类](##1、Spring简介)

```java
public class myTest5 {
    public static void main(String[] args) {

        // 通过配置类获取应用程序上下文对象，只能通过AnnotationConfig
        // 上下文来获取容器，通知配置类的class对象加载
        ApplicationContext context = new AnnotationConfigApplicationContext(wlpConfig.class);

        // 获取的getbean名称为配置类中的方法名称
        User getUser = (User) context.getBean("getUser");

        System.out.println(getUser.getName());
    }
}
```

**纯java配置方式，在SpringBoot中随处可见！**



## 9、代理模式

-   为什么要学习代理模式
    -   因为这就是SpringAOP的底层
-   代理分为
    -   静态代理
    -   动态代理

![image-20210312143821006](G:\各科笔记\Spring笔记\Spring.assets\image-20210312143821006.png)



#### 1、静态代理

**角色分析**

-   抽象角色：一般会使用接口或者抽象类来解决
-   真实角色：被代理的角色
-   代理角色：代理真实角色，代理真实角色后，一般做附属操作
-   客户：访问代理对象的人



代码不再：

	1. 业务接口
	2. 真实角色 
	3. 代理角色
	4. 客户端访问代理角色



**好处：**

-   可以使真实对象的操作更加纯粹，不用去关注一下公共的业务
-   公共的业务全部交给代理角色，实现了业务的分工
-   公共业务发生扩展的时候，方便集中管理



**缺点：**

-   一个真实对象就会产生一个代理角色，如果存在多个真实对象，就需要多个代理
    -   代码量会翻倍，降低开发速度



#### 2、加深理解

案例：Spring-04-proxy- dome2



**AOP面向切面编程图**

![image-20210312170233818](G:\各科笔记\Spring笔记\Spring.assets\image-20210312170233818.png)



#### 3、动态代理

-   动态代理和静态代理角色一样
-   动态代理的代理类是动态生成的，不是自己直接写好的! 
-   态代理分为两大类：基于接口的动态代理、基于类的动态代理
    -   基于接口--- jDK动态代理 【学习这个】
    -   基于类: cglib
    -   java字节码实现: javasist

**需要了解俩个类** 

-   Proxy：提供了创建动态代理类和实例的静态方法

    ![image-20210312172435044](G:\各科笔记\Spring笔记\Spring.assets\image-20210312172435044.png)

-   InvocationHandler 是个接口（调用处理程序）

![image-20210312172052599](G:\各科笔记\Spring笔记\Spring.assets\image-20210312172052599.png)

![image-20210312172030748](G:\各科笔记\Spring笔记\Spring.assets\image-20210312172030748.png)

加载类在哪个位置

表示这个要代理的接口是哪个



**案例**

1、真实对象

```java
package com.wlp.domeTow;

/**
 * 功能：
 *
 * @author 花子June
 * @modifier 花子June
 * @date 2021-03-12 15:56
 * @Version V1.0
 */
public class UserServiceImpl implements UserService{
    @Override
    public void add() {
        System.out.println("添加一个用户");
    }

    @Override
    public void delete() {
        System.out.println("删除一个用户");
    }

    @Override
    public void update() {
        System.out.println("更新一个用户");
    }

    @Override
    public void query() {
        System.out.println("查询一个用户");
    }
}

```

2、生成代理类对象

```java
package com.wlp.DomeFour;

import com.wlp.domeThree.Rent;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;

/**
 * 功能： 可通过这个类自动生成代理类
 *
 * @author 花子June
 * @modifier 花子June
 * @date 2021-03-12 17:43
 * @Version V1.0
 */
public class ProxyInvocationHandler implements InvocationHandler {

    /**
     * 生成代理类需要得到：代理的类在哪个位置，代理的接口是哪个，InvocationHandler的位置
     */

    // 被代理的接口
    private Object target;

    public void setTarget(Object target) {
        this.target = target;
    }

    // 生成得到代理类对象
    public Object getProxy(){
        return Proxy.newProxyInstance(this.getClass().getClassLoader(),
                target.getClass().getInterfaces(),this);
    }

    @Override
    // 处理代理实例，并返回结果
    public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {

        // 获取执行方法名称
        log(method.getName());
        // 动态代理的本质，就是使用反射机制实现
        Object result = method.invoke(target, args);

        return result;
    }

    public void log(String msg){
        System.out.println("执行了"+msg+"方法");
    }
}

```

3、客户端

```java
package com.wlp.DomeFour;

import com.wlp.domeTow.UserService;
import com.wlp.domeTow.UserServiceImpl;

/**
 * 功能：
 *
 * @author 武乐萍
 * @modifier 武乐萍
 * @date 2021-03-12 18:06
 * @Version V1.0
 */
public class Client {
    public static void main(String[] args) {
        /*
            1.真实角色
            2.代理角色（不存在）
                3.设置要代理的对象
                4.动态生成代理类
            5.执行方法
        */

        // 真实对象
        UserServiceImpl userService = new UserServiceImpl();

        // 获取一个动态生成代理类对象
        ProxyInvocationHandler pih = new ProxyInvocationHandler();

        // 设置真实对象
        pih.setTarget(userService);

        // 动态生成代理类
        UserService proxy = (UserService) pih.getProxy();

        // 执行方法
        proxy.add();
    }
}

```





**动态代理的好处**

-   可以使真实对象的操作更加纯粹，不用去关注一下公共的业务
-   公共的业务全部交给代理角色，实现了业务的分工
-   公共业务发生扩展的时候，方便集中管理
-   一个动态代理类代理的是一个接口，一般就是对应一类业务
-   一个动态代理类可以代理多个类，只要是实现了同一个接口即可



## 10、AOP

#### 1、AOP介绍

>   AOP：(Aspect Oriented Programming)
>
>   称为：**面向切面编程**，通过**预编译方式**和**运行期**动态**代理实现**程序功能的**统一维护**的一种技术
>
>   **AOP是OOP的延续**，是软件开发中的一个热点，也是Spring框架中的一个重要内容，**是函数式编程的**
>
>   **一种衍生范型**，利用AOP可以**对业务逻辑**的**各个部分**进行**隔离**，从而**使得业务逻辑部分之间的耦合度降低**
>
>   **提高**程序的**重用性**，同时**提高**了**开发**的**效率**

![image-20210313102342684](G:\各科笔记\Spring笔记\Spring.assets\image-20210313102342684.png)

#### 2、AOP在Spring中作用

==提供声明事务；允许用户自定义切面==

-   横切关注点：跨越应用程序多个模块的方法过功能，即使与业务逻辑无关的，需要关注的部分即使横切关注点
    -   如：日志，安全，缓存，事务
-   切面 (ASPECT)：横切关注点被模块化的特殊对象，它是一个类
-   通知（Advice）：切面必须要完成的工作，它是类中的一个方法
-   目标（Target）：被通知的对象
-   代理（Proxy）：向目标对象应用通知之后创建的对象
-   切入点（PointCut）：切面通知执行的地点的定义
-   连接点（JoinPoint）：与切入点匹配的执行点

![image-20210313103227902](G:\各科笔记\Spring笔记\Spring.assets\image-20210313103227902.png)



#### 3、使用Spring实现Aop

==需要导入AOP织入，导入依赖==

```xml
<!-- https ://mvnrepository. com/artifact/org. aspectj/aspectjweaver -->
<dependency>
    <groupId>org.aspectj</groupId>
    <artifactId>aspectjweaver</artifactId>
    <version>1.9.4</version>
</dependency>

```



##### 3.1、使用Spring中api接口

-   方式一：使用Spring的API接口【主要SpringAPI接口实现】
-   方式二：自定义来实现AOP【主要是切面定义】
-   方式三：使用注解实现！

**案例**

**1、服务类**

```java
public interface UserService {
    void add();
    void delete();
    void update();
    void select();
}

public class UserServiceImpl implements UserService{
    @Override
    public void add() {
        System.out.println("添加一个用户");
    }

    @Override
    public void delete() {
        System.out.println("删除一个用户");
    }

    @Override
    public void update() {
        System.out.println("更新一个用户");
    }

    @Override
    public void select() {
        System.out.println("查询一个用户");
    }
}
```

**2、前置日志和后置日志**

```java
import org.springframework.aop.MethodBeforeAdvice;
import java.lang.reflect.Method;
public class log implements MethodBeforeAdvice {
    @Override
    // method：要执行的目标对象的方法
    // args：参数
    // target：目标对象
    public void before(Method method, Object[] args, Object target) throws Throwable {
        System.out.println(target.getClass().getName()+"的"+method.getName()+"被执行了");
    }
}

import org.springframework.aop.AfterReturningAdvice;
import java.lang.reflect.Method;
public class AfterLog implements AfterReturningAdvice {
    @Override
    // 相比于前置log多了一个 returnValue
    public void afterReturning(Object returnValue, Method method, Object[] args, Object target) throws Throwable {
        System.out.println("执行了"+method.getName()+"方法 返回值的结果为：" +returnValue);
    }
}
```

**3、自定义**

```java
public class diyPointCut {

    public void before(){
        System.out.println("====方法执行前====");
    }

    public void after(){
        System.out.println("======方法执行后=====");
    }
}

```

**4、Spring注册bean**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<beans xmlns="http://www.springframework.org/schema/beans"
       xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
       xmlns:aop="http://www.springframework.org/schema/aop"
       xsi:schemaLocation="http://www.springframework.org/schema/beans
       https://www.springframework.org/schema/beans/spring-beans.xsd
       http://www.springframework.org/schema/aop
       https://www.springframework.org/schema/aop/spring-aop.xsd"

    >

    <!-- 注册bean -->
    <bean id="UserServiceImpl" class="com.wlp.service.UserServiceImpl"/>
    <bean id="log" class="com.wlp.log.log"/>
    <bean id="afterLog" class="com.wlp.log.AfterLog"/>

    <!-- 方式一：使用原生Spring API接口 -->
    <!-- 配置aop：需要导入aop的约束 -->
    <aop:config>
        <!--
            切入点：
            expression：表达式
            execution(): 内部参数顺序为：修饰词  返回值 类名 方法名 参数
        -->
        <!-- 表达式为： 任意修饰符  com.wlp.service.UserServiceImpl类下的所有方法中的任意参数-->
        <aop:pointcut id="pointcut" expression="execution(* com.wlp.service.UserServiceImpl.*(..))"/>

        <!-- 执行环绕增加！ -->
        <aop:advisor advice-ref="log" pointcut-ref="pointcut"/>
        <aop:advisor advice-ref="afterLog" pointcut-ref="pointcut"/>
    </aop:config>

    <!-- 第二种方式： diy -->
    <bean id="diy" class="com.wlp.diy.diyPointCut"/>

    <aop:config>
        <!-- 自定义切面 ref：要引用的类 -->
        <aop:aspect ref="diy">
            <aop:pointcut id="point" expression="execution(* com.wlp.service.UserServiceImpl.*(..))"/>
            <!-- 切入点 -->
            <aop:before method="before" pointcut-ref="point"/>
            <aop:after method="after" pointcut-ref="point"/>
        </aop:aspect>

    </aop:config>

</beans>
```

**5、注解实现**

```java
package com.wlp.diy;

import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.Signature;
import org.aspectj.lang.annotation.After;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;

/**
 * 功能：
 *
 * @author 花子June
 * @modifier 花子June
 * @date 2021-03-13 14:08
 * @Version V1.0
 */
@Aspect  // 标注这个类是一个切面
public class AnnotationPointCut {

    @Before("execution(* com.wlp.service.UserServiceImpl.*(..))")
    public void before(){
        System.out.println("====方法前=====");
    }

    @After("execution(* com.wlp.service.UserServiceImpl.*(..))")
    public void after(){
        System.out.println("====方法后=====");
    }

    // 在环绕增强中，我们可以给定一个参数，代表我们要获取处理的切入点
    @Around("execution(* com.wlp.service.UserServiceImpl.*(..))")
    public void around(ProceedingJoinPoint jp) throws Throwable {
        System.out.println("环绕前");

        // 获取签名
        Signature signature = jp.getSignature();
        System.out.println(signature);

        // 执行方法
        Object proceed = jp.proceed();

        System.out.println("环绕后");
    }
}

```

**6、xml配置**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<beans xmlns="http://www.springframework.org/schema/beans"
       xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
       xmlns:aop="http://www.springframework.org/schema/aop"
       xsi:schemaLocation="http://www.springframework.org/schema/beans
                           http://www.springframework.org/schema/beans/spring-beans.xsd
                           http://www.springframework.org/schema/aop
                           http://www.springframework.org/schema/aop/spring-aop.xsd"

       >

    <!-- 注册bean -->
    <bean id="UserService" class="com.wlp.service.UserServiceImpl"/>
    <bean id="log" class="com.wlp.log.log"/>
    <bean id="afterLog" class="com.wlp.log.AfterLog"/>
    <!-- 第三种方式 -->
    <bean id="annotationPointCut" class="com.wlp.diy.AnnotationPointCut"/>
    <!-- 开启注解支持
        代理模式实现有俩种方式，基于接口（JDK）和基于类（cglib）
        默认基于接口实现
		proxy-target-class="true"  基于类实现
		proxy-target-class="false" 基于接口实现
    -->
    <aop:aspectj-autoproxy/>
</beans>
```





**7、测试**

```java
import org.springframework.context.ApplicationContext;
import org.springframework.context.support.ClassPathXmlApplicationContext;
public class Mytext8 {
    public static void main(String[] args) {
        // 获取Spring容器对象
        ApplicationContext context = new ClassPathXmlApplicationContext("applicationContext.xml");

        // 动态代理返回的是一个接口对象，不能写其实现类
        UserService userService = context.getBean("UserServiceImpl", UserService.class);

        userService.add();
    }
}
```





## 11、整合Mybatis

步骤：

-   导入相关jar包

    -   **c3po**

    ```xml
    <dependency>
        <groupId>c3p0</groupId>
        <artifactId>c3p0</artifactId>
        <version>0.9.1.2</version>
    </dependency>
    
    //创建数据源
    <!-- ComboPooLedDataSource dataSource = new ComboPooLedDataSource(); -->
    
    ```

    

    -   **junit**

    ```xml
    <dependency>
        <groupId>junit</groupId>
        <artifactId>junit</artifactId>
        <version>4.12</version>
    </dependency>
    ```

    -   **Mybatis**

    ```xml
    <dependency>
        <groupId>org.mybatis</groupId>
        <artifactId>mybatis</artifactId>
        <version>3.5.3</version>
    </dependency>
    ```

    -   **mysql数据库（oracle数据库）**

    ```xml
    <dependency>
        <groupId>mysql</groupId>
        <artifactId>mysql-connector-java</artifactId>
        <version>5.1.47</version>
    </dependency>
    ```

    -   **Spring相关**

    ```xml
    <dependency>
        <groupId>org.springframework</groupId>
        <artifactId>spring-webmvc</artifactId>
        <version>5.2.0.RELEASE</version>
    </dependency>
    
    <!-- spring操作数据库的包 -->
    <dependency>
        <groupId>org.springframework</groupId>
        <artifactId>spring-jdbc</artifactId>
        <version>5.2.0.RELEASE</version>
    </dependency>
    ```

    -   **aop织入**

    ```xml
    <!-- aop织入包-->
    <dependency>
        <groupId>org.aspectj</groupId>
        <artifactId>aspectjweaver</artifactId>
        <version>1.9.4</version>
    </dependency>
    ```

    -   **Mybatis-spring 【新】**

    ```xml
    <!-- https://mvnrepository.com/artifact/org.mybatis/mybatis-spring -->
    <dependency>
        <groupId>org.mybatis</groupId>
        <artifactId>mybatis-spring</artifactId>
        <version>2.0.2</version>
    </dependency>
    ```

-   编写配置文件

-   测试

**mybatis编写步骤**

1.  编写实体类 
2.  编写核心配置文件
3.  编写接口
4.  编写Mapper.xml
5.  测试

#### **1、整合方式一**

**Spring配置**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<beans xmlns="http://www.springframework.org/schema/beans"
       xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
       xsi:schemaLocation="http://www.springframework.org/schema/beans
       http://www.springframework.org/schema/beans/spring-beans.xsd">

    <!--
        DataSource： 使用Spring的数据源替换Mybatis的配置    c3p0 dbcp druid
        这里使用Spring提供的JDBC：
    -->
    <bean id="dataSource" class="org.springframework.jdbc.datasource.DriverManagerDataSource">
        <!-- 配置 url driver user pass -->
        <property name="driverClassName" value="com.mysql.jdbc.Driver"/>
        <property name="url" value="jdbc:mysql://localhost:3306"/>
        <property name="username" value="root"/>
        <property name="password" value="8888"/>
     </bean>

    <!-- 配置SQLSessionFactory 工厂  用于获取sqlSession-->
    <bean id="sqlSessionFactory" class="org.mybatis.spring.SqlSessionFactoryBean">
        <!-- 配置数据源 -->
        <property name="dataSource" ref="dataSource"/>
        <!-- 绑定Mybatis配置文件，（也可以不绑定） -->
        <!-- 绑定Mybatis核心配置文件 -->
        <property name="configLocation" value="classpath:Mybatis-config.xml"/>
        <!-- 绑定mapper文件 -->
        <property name="mapperLocations" value="classpath:com/wlp/mapper/*.xml"/>
    </bean>

    <!--
        配置获取sqlSessionTemplate （也就是Mybatis中的sqlSession）
        俩者是同一个东西，但名称不同
    -->
    <bean id="sqlSession" class="org.mybatis.spring.SqlSessionTemplate">
        <!-- 获取sqlSession有一个参数，需要设置sqlSessionFactory -->
        <!-- 其类中没有set方法，只能通过构造注入SQLSessionFactory  -->
        <constructor-arg index="0" ref="sqlSessionFactory"/>
    </bean>

    <bean id="userTabMapperImpl" class="com.wlp.mapper.userTabMapperImpl">
        <property name="sqlSession" ref="sqlSession"/>
    </bean>

</beans>
```



1.  **编写数据源配置**

    ```xml
    <!--
            DataSource： 使用Spring的数据源替换Mybatis的配置    c3p0 dbcp druid
            这里使用Spring提供的JDBC：
        -->
    <bean id="dataSource" class="org.springframework.jdbc.datasource.DriverManagerDataSource">
        <!-- 配置 url driver user pass -->
        <property name="driverClassName" value="com.mysql.jdbc.Driver"/>
        <property name="url" value="jdbc:mysql://localhost:3306"/>
        <property name="username" value="root"/>
        <property name="password" value="8888"/>
    </bean>
    ```

2.  **获得sqlSessionFactory**

    ```xml
    <!-- 配置SQLSessionFactory 工厂  用于获取sqlSession-->
    <bean id="sqlSessionFactory" class="org.mybatis.spring.SqlSessionFactoryBean">
        <!-- 配置数据源 -->
        <property name="dataSource" ref="dataSource"/>
        <!-- 绑定Mybatis配置文件，（也可以不绑定） -->
        <!-- 绑定Mybatis核心配置文件 -->
        <property name="configLocation" value="classpath:Mybatis-config.xml"/>
        <!-- 绑定mapper文件 -->
        <property name="mapperLocations" value="classpath:com/wlp/mapper/*.xml"/>
    </bean>
    ```

3.  **获得sqlSessionTemplate（sqlSession）**

    ```xml
    <!--
            配置获取sqlSessionTemplate （也就是Mybatis中的sqlSession）
            俩者是同一个东西，但名称不同
        -->
    <bean id="sqlSession" class="org.mybatis.spring.SqlSessionTemplate">
        <!-- 获取sqlSession有一个参数，需要设置sqlSessionFactory -->
        <!-- 其类中没有set方法，只能通过构造注入SQLSessionFactory  -->
        <constructor-arg index="0" ref="sqlSessionFactory"/>
    </bean>
    
    ```

4.  **需要给接口加实现类**

    ```java
    public interface userTabMapper {
    
        List<userTab> getUserTab();
    }
    
    
    
    
    import org.mybatis.spring.SqlSessionTemplate;
    
    /**
     * @author 武乐萍
     * @modifier 武乐萍
     * @date 2021-03-14 11:29
     * @Version V1.0
     */
    public class userTabMapperImpl implements userTabMapper{
    
        /*
            使用组合
            在Mybatis中我们所有的操作都使用sqlSession来执行
            现在整合Mybatis后我们所有的操作都使用SQLSessionTemplate来完成
        */
        private SqlSessionTemplate sqlSession;
    
        // 提供set注入方法
        public void setSqlSession(SqlSessionTemplate sqlSession) {
            this.sqlSession = sqlSession;
        }
    
        @Override
        public List<userTab> getUserTab() {
            return sqlSession.getMapper(userTabMapper.class).getUserTab();
        }
    }
    
    ```

    ```xml
    <?xml version="1.0" encoding="UTF-8" ?>
    <!DOCTYPE mapper
            PUBLIC "-//mybatis.org//DTD Config 3.0//EN"
            "http://mybatis.org/dtd/mybatis-3-mapper.dtd">
    <mapper namespace="com.wlp.mapper.userTabMapper">
    
        <select id="getUserTab" resultType="com.wlp.pojo.userTab">
            select * from db_wlp.user_tab;
        </select>
    
    </mapper>
    ```

5.  **将自己写的实现类，注入到Spring中**

    ```xml
    <bean id="userTabMapperImpl" class="com.wlp.mapper.userTabMapperImpl">
        <property name="sqlSession" ref="sqlSession"/>
    </bean>
    ```

6.  **测试使用**

    ```java
    @Test
    public void text2(){
    
        ApplicationContext context = new ClassPathXmlApplicationContext("spring-config.xml");
    
        userTabMapper user = context.getBean("userTabMapperImpl", userTabMapper.class);
    
        for (userTab userTab : user.getUserTab()) {
            System.out.println(userTab);
        }
    
    }
    ```

#### 2、整合方式二

**1、编写数据源于sqlSessionFactory**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<beans xmlns="http://www.springframework.org/schema/beans"
       xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
       xsi:schemaLocation="http://www.springframework.org/schema/beans
       http://www.springframework.org/schema/beans/spring-beans.xsd">

    <!--
        DataSource： 使用Spring的数据源替换Mybatis的配置    c3p0 dbcp druid
        这里使用Spring提供的JDBC：
    -->
    <bean id="dataSource" class="org.springframework.jdbc.datasource.DriverManagerDataSource">
        <!-- 配置 url driver user pass -->
        <property name="driverClassName" value="com.mysql.jdbc.Driver"/>
        <property name="url" value="jdbc:mysql://localhost:3306"/>
        <property name="username" value="root"/>
        <property name="password" value="8888"/>
     </bean>

    <!-- 配置SQLSessionFactory 工厂  用于获取sqlSession-->
    <bean id="sqlSessionFactory" class="org.mybatis.spring.SqlSessionFactoryBean">
        <!-- 配置数据源 -->
        <property name="dataSource" ref="dataSource"/>
        <!-- 绑定Mybatis配置文件，（也可以不绑定） -->
        <!-- 绑定Mybatis核心配置文件 -->
        <property name="configLocation" value="classpath:Mybatis-config.xml"/>
        <!-- 绑定mapper文件 -->
        <property name="mapperLocations" value="classpath:com/wlp/mapper/*.xml"/>
    </bean>
</beans>
```

**2、编写实现类**

```java

import org.mybatis.spring.SqlSessionTemplate;
import org.mybatis.spring.support.SqlSessionDaoSupport;

/**
 * @author 武乐萍
 * @date 2021-03-14 12:58
 * @Version V1.0
 */
public class userTabMapperImpl2 extends SqlSessionDaoSupport implements userTabMapper{

    /*
    * SqlSessionDaoSupport 是一个抽象的支持类，用来为你提供 SqlSession
    * 用 getSqlSession() 方法你会得到一个 SqlSessionTemplate，之后可以用于执行 SQL 方法
    * 使用这种方式可以不需要配置SqlSession（sqlSessionTemplate） 值需要配置sqlSessionFactory
    * 因为继承了SqlSessionDaoSupport它直接提供了一个SqlSession（sqlSessionTemplate）
    * */
    @Override
    public List<userTab> getUserTab() {
        return getSqlSession().getMapper(userTabMapper.class).getUserTab();
    }
}

```

**3、注册bean**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<beans xmlns="http://www.springframework.org/schema/beans"
       xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
       xsi:schemaLocation="http://www.springframework.org/schema/beans
       http://www.springframework.org/schema/beans/spring-beans.xsd">

    <!-- 专注配置bean -->
    <import resource="spring-config.xml"/>

    <!-- 专注生成bean -->
    <bean id="userTabMapperImpl" class="com.wlp.mapper.userTabMapperImpl">
        <property name="sqlSession" ref="sqlSessionTemplate"/>
    </bean>

    <!--  -->
    <bean id="userTabMapperImpl2" class="com.wlp.mapper.userTabMapperImpl2">
        <!-- 此时这个类以及不需要sqlSession，但它的父类需要一个SQLSessionFactory -->
        <property name="sqlSessionFactory" ref="sqlSessionFactory"/>
    </bean>
</beans>
```

**4、测试**

```java
@Test
public void text3(){

    ApplicationContext context = new ClassPathXmlApplicationContext("applicationContext.xml");

    userTabMapper user = context.getBean("userTabMapperImpl2", userTabMapper.class);

    for (userTab userTab : user.getUserTab()) {
        System.out.println(userTab);
    }

}

```



## 12、声明式事务

#### 1、回顾事务

-   什么是事务？
    -   简单来说：把一组业务当成一个业务来做，要么都成功要么都失败
-   事务在项目开发中，十分重要，涉及到数据的一致性问题
-   需要确保完整性和一致性



**事务的ACID原则**

-   原子性：不可再分
-   一致性：数据的一致性
-   隔离性：并发
    -   多个业务可能操作同一个资源，
-   持久性
    -   事务一旦提交，无论系统发生什么问题，结果都不会在被影响，被持久化的写到存储器中



#### 2、Spring中的事务管理

**Spring中事务分为俩种**

-   声明式事务：使用AOP织入.

    ```xml
    <?xml version="1.0" encoding="UTF-8"?>
    <beans xmlns="http://www.springframework.org/schema/beans"
           xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
           xmlns:tx="http://www.springframework.org/schema/tx"
           xmlns:aop="http://www.springframework.org/schema/aop"
           xsi:schemaLocation="http://www.springframework.org/schema/beans
           http://www.springframework.org/schema/beans/spring-beans.xsd
           http://www.springframework.org/schema/tx
           http://www.springframework.org/schema/tx/spring-tx.xsd
           http://www.springframework.org/schema/aop
           http://www.springframework.org/schema/aop/spring-aop.xsd">
    
        <!--
            DataSource： 使用Spring的数据源替换Mybatis的配置    c3p0 dbcp druid
            这里使用Spring提供的JDBC：
        -->
        <bean id="dataSource" class="org.springframework.jdbc.datasource.DriverManagerDataSource">
            <!-- 配置 url driver user pass -->
            <property name="driverClassName" value="com.mysql.jdbc.Driver"/>
            <property name="url" value="jdbc:mysql://localhost:3306"/>
            <property name="username" value="root"/>
            <property name="password" value="8888"/>
         </bean>
    
        <!-- 配置SQLSessionFactory 工厂  用于获取sqlSession-->
        <bean id="sqlSessionFactory" class="org.mybatis.spring.SqlSessionFactoryBean">
            <!-- 配置数据源 -->
            <property name="dataSource" ref="dataSource"/>
            <!-- 绑定Mybatis配置文件，（也可以不绑定） -->
            <!-- 绑定Mybatis核心配置文件 -->
            <property name="configLocation" value="classpath:Mybatis-config.xml"/>
            <!-- 绑定mapper文件 -->
            <property name="mapperLocations" value="classpath:com/wlp/mapper/*.xml"/>
        </bean>
    
        <!--
            配置获取sqlSessionTemplate （也就是Mybatis中的sqlSession）
            俩者是同一个东西，但名称不同
        -->
        <bean id="sqlSessionTemplate" class="org.mybatis.spring.SqlSessionTemplate">
            <!-- 获取sqlSession有一个参数，需要设置sqlSessionFactory -->
            <!-- 其类中没有set方法，只能通过构造注入SQLSessionFactory  -->
            <constructor-arg index="0" ref="sqlSessionFactory"/>
        </bean>
    
        <!-- 配置声明式事务 -->
        <bean id="transactionManager" class="org.springframework.jdbc.datasource.DataSourceTransactionManager">
            <property name="dataSource" ref="dataSource"/>
        </bean>
    
        <!-- 结合AOP实现事务的织入 -->
        <!-- 配置事务的通知 -->
        <tx:advice id="txAdvice" transaction-manager="transactionManager">
            <!-- 给方法配置事务 -->
            <!-- 配置事务的传播特性 -->
            <tx:attributes>
                <tx:method name="add" propagation="REQUIRED"/>
                <tx:method name="delete" propagation="REQUIRED"/>
                <tx:method name="update" propagation="REQUIRED"/>
                <tx:method name="query" read-only="true"/> <!-- 设置只读 -->
                <tx:method name="*" propagation="REQUIRED"/> <!-- 设置所有类型都开启事务 -->
            </tx:attributes>
        </tx:advice>
    
        <!-- 配置事务切入 -->
        <aop:config>
            <aop:pointcut id="txPointCut" expression="execution(* com.wlp.mapper.*.*(..))"/>
            <aop:advisor advice-ref="txAdvice" pointcut-ref="txPointCut"/>
        </aop:config>
    </beans>
    ```

    

-   编程式事务：需要在代码中进行

    ```java
    public class UserService {
      private final PlatformTransactionManager transactionManager;
      public UserService(PlatformTransactionManager transactionManager) {
        this.transactionManager = transactionManager;
      }
      public void createUser() {
        TransactionStatus txStatus =
            transactionManager.getTransaction(new DefaultTransactionDefinition());
        try {
          userMapper.insertUser(user);
        } catch (Exception e) {
          transactionManager.rollback(txStatus);
          throw e;
        }
        transactionManager.commit(txStatus);
      }
    }
    ```

    

思考:
为什么需要事务?

-   如果不配置事务，可能存在数据提交不一致的情况下;
-   如果我们不在SPRING中去配置声明式事务，我们就需要在代码中手动配置事务!
-   事务在项目的开发中十分重要,设计到数据的一致性和完整性问题，不容马虎!





![image-20210314140857936](G:\各科笔记\Spring笔记\Spring.assets\image-20210314140857936.png)