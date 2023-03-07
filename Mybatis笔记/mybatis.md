

[TOC]



## **0.前言**

#### 2.什么是持久层.

```
?useUnicode=true&characterEncoding=utf-8&useSSL=false
```

> ​	数据持久化

​	持久化就是将程序的数据在持久状态和瞬时状态转化的过程

- [ ] ​	数据库是一种持久化，可以通过jdbc使其持久化，io处理文件也可以使其持久化

    **ORM(对象关系映射）**

    object - ralation - map

    
    
    **为什么需要持久化**？
    
    因为有些数据需求永久存储也就是持久化

#### 3.**什么是持久层**？

> ​	完成持久化工作的代码块叫做持久层

#### 4.**为什么需要Mybatis**？

> **帮助程序员将数据存入到数据库中**
>
> **方便**
>
> **传统的JDBC代码太复杂了，简化**
>
> 优点：
>
> - 简单易学
> - 灵活
> - sql和代码分离，提高了可维护性
> - 提供映射标签，支持对象与数据库的orm字段关系映射
> - 提供对象关系映射标签，支持对象关系组建维护
> - 提供xml标签，支持编写动态sql

#### **5.Mybatis下载**

> 官网[https://github.com/mybatis/mybatis-3/releases]
>
> 中文文档[https://mybatis.org/mybatis-3/zh/index.html]
>
> Maven仓库:
>
> ```xml
> <!-- https://mvnrepository.com/artifact/org.mybatis/mybatis -->
> <dependency>
> <groupId>org.mybatis</groupId>
> <artifactId>mybatis</artifactId>
> <version>3.5.2</version>
> </dependency>
> 
> ```
>
> ```properties
> driver=oracle.jdbc.driver.OracleDriver
> url=jdbc:oracle:thin:@127.0.0.1:1521:orcl
> username=wlp
> password=888888
> 
> mysql
> jdbc.driver=com.mysql.jdbc.Driver
> jdbc.url=jdbc:mysql://localhost:3306/?useUnicode=true&characterEncoding=utf8&serverTimezone=Asia/Shanghai&useSSL=false
> jdbc.user=root
> jdbc.pwd=root
> ```
>
> 
>
> ![image-20210206105100397](G:\各科笔记\Mybatis笔记\mybatis.assets\image-20210206105100397.png)

## **1.配置Mybatis核心文件**

```xml
<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE configuration
  PUBLIC "-//mybatis.org//DTD Config 3.0//EN"
  "http://mybatis.org/dtd/mybatis-3-config.dtd">
<configuration>
  <environments default="development">
    <environment id="development">
      <transactionManager type="JDBC"/>
      <dataSource type="POOLED">
        <property name="driver" value="${driver}"/>
        <property name="url" value="${url}"/>
        <property name="username" value="${username}"/>
        <property name="password" value="${password}"/>
      </dataSource>
    </environment>
  </environments>
  <mappers>
    <mapper resource="org/mybatis/example/BlogMapper.xml"/>
  </mappers>
</configuration>


<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE configuration
        PUBLIC "-//mybatis.org//DTD Config 3.0//EN"
        "http://mybatis.org/dtd/mybatis-3-config.dtd">
<!-- 核心配置文件 -->
<configuration>
    <environments default="development">
        <environment id="development">
            <transactionManager type="JDBC"/>
            <dataSource type="POOLED">
                <property name="driver" value="oracle.jdbc.driver.OracleDriver"/>
                <property name="url" value="jdbc:oracle:thin:@127.0.0.1:1521:orcl?useSSL=true&amp;useUnicode=true&amp;characterEncoding=UTF-8"/>
                <property name="username" value="wlp"/>
                <property name="password" value="000000"/>
            </dataSource>
        </environment>
    </environments>
    <mappers>
        <mapper resource="pojo/testOneMapper.xml" />
    </mappers>
</configuration>
```

## **2.编写Mybatis工具类**

```java
import org.apache.ibatis.io.Resources;
import org.apache.ibatis.session.SqlSession;
import org.apache.ibatis.session.SqlSessionFactory;
import org.apache.ibatis.session.SqlSessionFactoryBuilder;

import java.io.IOException;
import java.io.InputStream;

/**
 * 功能：
 *
 * @author 武乐萍
 * @modifier 武乐萍
 * @date 2021-02-19 9:43
 * @Version V1.0
 */
public class utils {

    private static SqlSessionFactory sqlSessionFactory;

    static {
        String resource = "mybatis-config.xml";
        InputStream inputStream = null;
        try {
            inputStream = Resources.getResourceAsStream(resource);
            sqlSessionFactory = new SqlSessionFactoryBuilder().build(inputStream);

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * 既然有了SqlSessionFactory，就可以获取SqlSession实例
     * SqlSession完全包含了面向数据库执行sql命令所需的所有方法
     * @return
     */
    public static SqlSession getSqlSession(){
        return sqlSessionFactory.openSession();
    }
}


```

#### **3.编写dao类**

```java
package pojo;

import java.util.List;

/**
 * 功能：
 *
 * @author 武乐萍
 * @modifier 武乐萍
 * @date 2021-02-20 9:37
 * @Version V1.0
 */
public interface testOneDao {

    List<testOne> getTestOne();
}

```

#### **4.编写测试类**

```java
import org.apache.ibatis.session.SqlSession;
import org.junit.Test;
import pojo.testOne;
import pojo.testOneDao;

import java.util.List;

/**
 * 功能：
 *
 * @author 武乐萍
 * @modifier 武乐萍
 * @date 2021-02-20 10:29
 * @Version V1.0
 */
public class test {

  @Test
  public void test(){

    // 第一步 获取SQLSession对象
    SqlSession sqlSession = utils.getSqlSession();

    // 方式一： 通过getMapper方法执行sql语句
    testOneDao mapper = sqlSession.getMapper(testOneDao.class);

    List<testOne> testOne = mapper.getTestOne();

    for (pojo.testOne one : testOne) {
      System.out.println(one);
    }
  }
}

```

##### **5.可能遇到的问题**

![image-20210220101559776](G:\各科笔记\Mybatis笔记\mybatis.assets\image-20210220101559776.png)

## **3.CRUD(添删改查)**

#### **1.namespace**

namespace中的包名要和 DAO/mapper 接口的包名一致！

#### **2.select**

选择，查询语句

- ​	id：就是对象的namespace中的方法名

- ​	resultType：Sql语句执行的返回值！

- ​	parameterType：参数类型



1. 编写接口
2. 编写对应的mapper中的sql语句
3. 测试

```java 
public interface testOneDao {
  // 查询表中所有数据
    List<testOne> getTestOne();
}
```

```xml
<select id="getTestOne" resultType="pojo.testOne">
  select * from testTable
</select>
```

```java
// 第一步 获取SQLSession对象
SqlSession sqlSession = utils.getSqlSession();

// 方式一： 通过getMapper方法执行sql语句
testOneDao mapper = sqlSession.getMapper(testOneDao.class);

List<testOne> testOne = mapper.getTestOne();

for (pojo.testOne one : testOne) {
  System.out.println(one);
}
```





#### **3.Insert**



#### **4.update**



#### **5.Delete**

```xml
<delete id="getTestOne" parameterType="int">
  delete from testTable where id = #{id}
</delete>
```



#### **6.map模糊查询**

```xml
<select id="getTestOne" resultType="map" resultType="com.kuang.pojo.User">
  select * from testTable where id = #{id} and name = #{name}
</select>
```

**测试**

```java
@Test
    public void test2(){

        // 第一步 获取SQLSession对象
        SqlSession sqlSession = utils.getSqlSession();

        testOneDao mapper = sqlSession.getMapper(testOneDao.class);

        Map<String,Object> map = new HashMap<>();

        map.put("id",1);
        map.put("name","sfd");

        mapper.getTestOne(map);
        
        sqlSession.close();

    }
```

> Map传递参数，直接在sql中取出key即可		parameterType = 'map'
>
> 对象传递参数，直接在sql中取对象的属性即可	parameterType = '对象'
>
> 只有一个基本类型参数的情况下，可以直接在sql中取到	

#### **7.模糊查询**

1. java代码执行的时候，传递通配符%%

   ```java
   List<User> userList = mapper.getUserLike("%里%")
   ```

2. 在sql拼接中使用通配符

   ```sql
   select * from user where name like "%#{value}%"
   ```



#### **8.分析错误**

- 标签不要匹配错
- resource绑定mapper，需要使用路径
- 程序配置文件必须符合规范
- NullPointerExecption 没有注册到资源
- 输出的xml文件中存在中午乱码
- maven资源没有导出问题



#### **9.注意**





## **4.配置解析**

#### **1. 配置文件**

```xml
properties（属性）
settings（设置）
typeAliases（类型别名）
typeHandlers（类型处理器）
objectFactory（对象工厂）
plugins（插件）
environments（环境配置）
environment（环境变量）
transactionManager（事务管理器）
dataSource（数据源）
databaseIdProvider（数据库厂商标识）
mappers（映射器）
```

#### **2.环境配置（**environments ）**

> **environments 环境配置**  => 默认只能选择一个环境
>
> **transactionManager 事务管理器**   => Mybatis中只有俩种事务管理器  **JDBC(默认) 、managed**
>
> - JDBC – 这个配置直接使用了 JDBC 的提交和回滚设施，它依赖从数据源获得的连接来管理事务作用域。
> - MANAGED – 这个配置几乎没做什么。它从不提交或回滚一个连接，而是让容器来管理事务的整个生命周期
>
> **dataSource 数据源**  => 连接数据库   **UNPOOLED(没有连接池)、POOLED(池子)、JNDI**
>
> - **dataSource** 元素使用标准的 JDBC 数据源接口来配置 JDBC 连接对象的资源
> - **UNPOOLED**– 这个数据源的实现会每次请求时打开和关闭连接
> - **POOLED**– 这种数据源的实现利用“池”的概念将 JDBC 连接对象组织起来  **<=默认配置是这个**
> - 有池子可以让web响应更加快



```xml
<environments default="text">
        <environment id="development">
            <transactionManager type="JDBC"/>
            <dataSource type="POOLED">
                <property name="driver" value="oracle.jdbc.driver.OracleDriver"/>
                <property name="url" value="jdbc:oracle:thin:@127.0.0.1:1521:orcl" />
                <property name="username" value="java2019"/>
                <property name="password" value="888888"/>
            </dataSource>
        </environment>
        <environment id="text">
            <transactionManager type="JDBC"/>
            <dataSource type="POOLED">
                <property name="driver" value="oracle.jdbc.driver.OracleDriver"/>
                <property name="url" value="jdbc:oracle:thin:@127.0.0.1:1521:orcl" />
                <property name="username" value="java2019"/>
                <property name="password" value="888888"/>
            </dataSource>
        </environment>
    </environments>
```

#### **3.属性（properties）**

**编写一个配置文件**

```properties
driver=com.mysql.jdbc.Driver
url=jdbc:mysql://localhost:3306/db_test_wlp?usessL=true&useunicode=true&characterEncoding=UTF-8
username=root
password=8888

```

```properties
driver=oracle.jdbc.driver.OracleDriver
url=jdbc:oracle:thin:@127.0.0.1:1521:orcl?usessL=true&useunicode=true&characterEncoding=UTF-8
username=java2019
password=888888
```

**在核心配置文件中引入**

```xml
 <!-- 导入外部配置文件 -->
    <properties resource="db.properties">
        <property name="username" value="wlp"/>
        <property name="pwd" value="888888"/>
    </properties>
```

- 可以直接引入外部文件
- 可以在其中增加一些属性配置
- **如果两个文件有同一个字段，优先使用外部配置文件**

#### **4、类型别名**

- 类型别名是为java类型设置一个短的名

- 存在的意义在于用在减少类完全限定的沉余

  ```xml
  <!--可以给实体 类起别名--> 
  <typeAliases>
    	<typeAlias type="com.kuang.pojo.user" alias="user"/>
  </typeAliases>
  
  ```

  

  也可以指定一个包名，Mybatis会在包名下面搜索需要的java Bean

  扫描实体类的包，它的默认别名就为这个类的类名首字母小写

```xml
<!--可以给包起别名--> 
<typeAliases>
  	<package name="com.kuang.pojo.user"/>
</typeAliases>
```



第一种可以DIY别名，第二种则不行，如果非要改，需要在实体上增加注解

```java
@Alias("user")
public class user{}
```

#### **5.设置（setting）**

这是 MyBatis 中极为重要的调整设置，它们会改变 MyBatis 的运行时行为。 下表描述了设置中各项设置的含义、默认值等。

![image-20210221103309659](G:\各科笔记\Mybatis笔记\mybatis.assets\image-20210221103309659.png)

![image-20210221103335515](G:\各科笔记\Mybatis笔记\mybatis.assets\image-20210221103335515.png)

![image-20210225160153816](G:\各科笔记\Mybatis笔记\mybatis.assets\image-20210225160153816.png)

#### **6、其他**

- [typeHandlers（类型处理器）](https://mybatis.org/mybatis-3/zh/configuration.html#typeHandlers)
- [objectFactory（对象工厂）](https://mybatis.org/mybatis-3/zh/configuration.html#objectFactory)
- [plugins（插件）](https://mybatis.org/mybatis-3/zh/configuration.html#plugins)
  - Mybatis-generator-core
  - Mybatis-plus
  - 通用mapper

#### **7、映射器（mappers）**

MapperRegistry：注册绑定我们的mapper文件

**方式一：【推荐使用】**

```xml
<!-- 每一个Mapper.xml都需要在Mybatis核心配置文件中注册 -->
    <mappers>
        <mapper resource="pojo/testOneMapper.xml" />
    </mappers>
```

方式二：使用class文件绑定

```xml
<!-- 每一个Mapper.xml都需要在Mybatis核心配置文件中注册 -->
    <mappers>
        <mapper class="pojo/testOneMapper" />  => interface接口名
    </mappers>
```

**注意点**

- 接口和他的Mapper配置文件必须同名
- 接口和他的Mapper配置文件必须在同一个包下



方式三：

```xml
<!-- 每一个Mapper.xml都需要在Mybatis核心配置文件中注册 -->
    <mappers>
        <package name="pojo/包名" />  
    </mappers>
```

- 接口和他的Mapper配置文件必须同名
- 接口和他的Mapper配置文件必须在同一个包下



#### **8、声明周期和作用域**

![image-20210222094830626](G:\各科笔记\Mybatis笔记\mybatis.assets\image-20210222094830626.png)

作用域、生命周期是至关重要的，因为错误的使用会导致非常严重的**并发问题**。

 **SqlSessionFactoryBuilder**：

- 一旦创建了 SqlSessionFactory，就不再需要它了
- 局部变量

**SqlSessionFactory**

- 说白了就是可以想象为：数据库连接池
- SqlSessionFactory 一旦被创建就应该在应用的运行期间一直存在，没有任何理由丢弃它或重新创建另一个实例
- 因此 SqlSessionFactory 的最佳作用域是**应用作用域**
- 最简单的就是使用**单例模式**或者**静态单例模式**

**SqlSession**

- 连接到连接池的一个请求
- SqlSession 的实例不是线程安全的，因此是不能被共享的，所以它的最佳的作用域是请求或方法作用域
- 用完之后需要赶紧关闭，否则会资源占用！

![image-20210222095801707](G:\各科笔记\Mybatis笔记\mybatis.assets\image-20210222095801707.png)

这里面的每一个mapper，就代表一个具体的业务



## 5、解决属性名与字段名不一致的问题

#### **1、起别名**

在sql语句中 select id as userid from student

#### **2、resultMap结果集映射**

> - resultMap 元素是 MyBatis 中最重要最强大的元素
> - ResultMap 的设计思想是，对简单的语句做到零配置，对于复杂一点的语句，只需要描述语句之间的关系就行了。
> - ResultMap` 的优秀之处——你完全可以不用显式地配置它们。 虽然上面的例子不用显式配置 `ResultMap

- [ ] 将user表中的属性id、name、pwd映射成为id、name、password去接收结果集中的数据

```xml
<!--结果集映射-->
<resultMap id="UserMap" type="user">
   <!--co1umn数据库中的字段，property实体类中的属性-->
   <result column="id" property="id"/>
   <result column="name" property="name"/>
   <resu1t column=" pwd" property="password"/>
</resultMap>
<select id="getUserById" resultMap="userMap">
   select * from mybatis.user where id = #{id}
</select>

```



## 6、日志

#### **1、日志工厂**

![image-20210221103335515](G:\各科笔记\Mybatis笔记\mybatis.assets\image-20210221103335515.png)



-  **SLF4J**   
  -  **LOG4J** 【掌握】
-  **LOG4J2** 
-  **JDK_LOGGING** 	java自带日志
-  **COMMONS_LOGGING** 
  -  **STDOUT_LOGGING**	【掌握】标准日志输出
-  **NO_LOGGING**



> **在Mybatis中具体事宜哪一个日志实现，在设置中设定**

**STDOUT_LOGGING**	

在Mybatis核心配置文件中，配置我们的日志

```xml
<settings>
  <setting name="logImpl" value="STDOUT_LOGGING" />
</settings>

```



![image-20210222104344747](G:\各科笔记\Mybatis笔记\mybatis.assets\image-20210222104344747.png)



#### **2、Log4j**

**什么是Log4j?**

- Log4j是Apache的一个开源项目，通过使用Log4j,我们可以控制日志信息输送的目的地是控制台、文件、GU|组件
- 我们也可以控制每一条日志的输出格式
- 通过定义每一 条日志信息的级别,我们能够更加细致地控制日志的生成过程
- 通过一个配置文件来灵活地进行配置,而不需要修改应用的代码。



步骤：

1. ​	先导入包 导入依赖

   ```xml
   <!-- https://mvnrepository.com/artifact/log4j/log4j -->
   <dependency>
       <groupId>log4j</groupId>
       <artifactId>log4j</artifactId>
       <version>1.2.17</version>
   </dependency>
   
   ```

   

2. 配置log4jproperties文件

   ```properties
   roperties
   #将等级为DEBUG的日志信息输出到console和file这两个目的地，console 利file的定义在下面的代码
   1og4j.rootLogger-DEBUG , console , file			=> 输出日志级别
   #控制台输出的相关设置
   1og4j . 5.console = org . apache .1og4j .ConsoleAppender		=> 控制台的输出使用log4j输出
   1og4j . appender.console.Target = System. out
   1og4j . appender.console.Threshcld=DEBUG	
   1og4j . appender.console.layout = org.apache.1og4j.PatternLayout
   1og4j . appender.console.layout.Convers ionPattern= [%c]-%m%n		=> 日志的格式
   #文件输出的相关设置
   1og4j . appender.file = org.apache.1og4j.RollingFileAppender
   1og4j . appender.file.File= ./1og/kuang.1og			=> 日志输出文件地址  ./ 输出到当前目录下
   1og4j . appender.file.MaxFileSize=10mb						=> 文件最大的大小  超过10m在重新生成一个新的文件
   1og4j . appender.file.Threshold=DEBUG
   1og4j . appender.file.layout=org . apache .1og4j. PatternLayout
   1og4j . appender.file.layout.ConversionPattern=[%p] [%d{yy-MM-dd}] [%c ]%m%n  => 日志输出格式，玩不坏
   
   #日志输出级别
   1og4j . logger.org.mybatis=DEBUG
   1og4j . logger.java.sq1=DEBUG
   1og4j . logger.java.sql.Statement=DEBUG
   1og4j . logger.java.sq1.ResultSet=DEBUG
   1og4j . logger.java.sq1.PreparedStatement=DEBUG
   
   ```

   

3. 配置log4j为日志的实现

   ```xml
   <settings>
     <setting name="logImpl" value="log4j" />
   <settings>
   ```

   

4. 执行sql语句



## **7、注解开发**

#### 8.1、面向接口编程

> -大家之前都学过面向对象编程，也学习过接口，但在真正的开发中，很多时候我们会选择面向接口编程
> **根本原因**:**=解耦=,可拓展,提高复用,分层开发中,上层不用管具体的实现,大家都遵守共同的标准,使得**
> **开发变得容易,规范性更好**
> . 在-一个面向对象的系统中，系统的各种功能是由许许多多的不同对象协作完成的。在这种情况下，各个对象内	部是如何实现自己的，对系统设计人员来讲就不那么重要了;
> -而各个对象之间的协作关系则成为系统设计的关键。小到不同类之间的通信，大到各模块之间的交互，在系统设
> 计之初都是要着重考虑的，这也是系统设计的主要工作内容。面向接口编程就是指按照这种思想来编程。



#### 关于接口的理解

-接口从更深层次的理解，应是定义(规范，约束)与实现(名实分离的原则)的分离。
-**接口的本身反映了系统设计人员对系统的抽象理解**。
-接口应有两类:
	-第一类是对一个个体的抽象，它可对应为一个抽象体(abstract class);
	-第二类是对一个个体某一方面的抽象，即形成一个抽象面(interface) ;
-个体有可能有多个抽象面。抽象体与抽象面是有区别的。



**三个面向区别**
-面向对象是指，我们考虑问题时，以对象为单位，考虑它的属性及方法.
-面向过程是指，我们考虑问题时，以-一个具体的流程(事务过程)为单位,考虑它的实现.
-接口设计与非接口设计是针对复用技术而言的，与面向对象(过程)不是一个问题.更多的体现就是对系统整体的
架构



#### **1、注解**

> **1、底层主要应用反射**
>
> **2、使用前需要在核心配置文件中绑定接口**
>
> ```xml
> <mappers>
>   <mapper class="接口全路径">
> <mappers>
> ```
>
> 

#### **2、Mybatis执行流程**

> - **1、resources获取加载全局配置文件**
> - **2、实例化SqlSessionFactoryBuilder构造器**
> - **3、解析配置文件流XMLConfigBuilder**
> - **4、Configuration所有的配置文件信息**
> - **5、SqlSessionFactory实例化**
> - **6、transactional事务管理器**
> - **7、创建executor执行 （用于执行mapper**
> - **8、创建SqlSession**
> - **9、实现CRUD(添删改查)**
> - **10、查看执行是否成功  失败返回第6步**
> - **11、提交事务**
> - **12、关闭SqlSession**

#### **3、案例**

![image-20210225105840362](G:\各科笔记\Mybatis笔记\mybatis.assets\image-20210225105840362.png)

![image-20210223112314817](G:\各科笔记\Mybatis笔记\mybatis.assets\image-20210223112314817.png)

**【注意】：必须将我们的接口在核心配置文件中注册！**

```java
// 关于@Param注解
	1、基本类型的参数或者String类型需要加上
	2、引用类型不需要加
	3、如果只有一个基本数据类型，可以忽略，但是建议加上
  4、我们再sql中引用的就是我们这里的@Param()中设置定的属性
```

`#{}` 与  `${}` 的区别就是一个能防止**sql注入**一个不能  



## 8、Lombok

- Lombok是java 库（library）
- 插件（plugs）
- build tools 构建工具
- 不用写get与set方法等相同的方法，直接使用注解就行



#### 1、使用步骤

- 在IDEA中在setting中找到plugins中搜索Lombok

- 在项目中导入jar包
  
  - maven仓库地址
  
  - ```xml
      <!-- https://mvnrepository.com/artifact/org.projectlombok/lombok -->
      <dependency>
          <groupId>org.projectlombok</groupId>
          <artifactId>lombok</artifactId>
          <version>1.18.12</version>
          <scope>provided</scope>  => 去掉等于用于所有环境
      </dependency>
      
      ```
  
  - 
  
- ```
    @Getter and @Setter
    @FieldNameConstants
    @ToString
    @EqualsAndHashCode
    @AllArgsConstructor, @RequiredArgsConstructor and @NoArgsConstructor
    @Log, @Log4j, @Log4j2, @Slf4j, @XSlf4j, @CommonsLog, @JBossLog, @Flogger, @CustomLog
    @Data
    @Builder
    @SuperBuilder
    @Singular
    @Delegate
    @Value
    @Accessors
    @Wither
    @With
    @SneakyThrows
    @val
    @var
    experimental @var
    @UtilityClass
    Lombok config system
    ```

- ![image-20210225104755269](G:\各科笔记\Mybatis笔记\mybatis.assets\image-20210225104755269.png)

@Data：无参构造，get、set、toString、hashcode、equals





## 9、多对一

**0、多对一使用 association**

#### **1、按照查询嵌套处理**

```xml
<!--
	思路:
	1.查询所有的学生信息
	2.根据查询出来的学生的tid,寻找对应的老师!子查询!
	association: 用于对象
	collection：用于集合
	javaType：指定属性的类型
-->
<select id="getstudent" resu1tMap="studentTeacher">
    select * from student
</select>

<resultMap id="studentTeacher" type="Student">
    <result property="id" column="id"/>
    <resu1t property="name" column="name"/>
    <!--复杂的属性，我们需要单独处理对象: association 集合: collection -->
    <association property="teacher" co1umn="ti d" javaType="Teacher" select="getTeacher"/>
</resultMap>

<select id="getTeacher" resultType="Teacher">
    select * from teacher where id = #{id}
</select>

```

#### **2、按照结果集嵌套查询**

```xml

<!--按照结果嵌套处理-->
<select id="getStudent2" resultMap="StudentTeacher2">
    select s.id sid,s. name sname, t. name tname
    from student s, teacher t
    where s.tid = t.id;
</select>

<!--
	resultMap：结果集映射
 	property: 表单java属性
	column：对应sql语句字段名
 -->
<resultMap id="StudentTeacher2" type="Student">
    <result property="id" column="sid"/>
    <result property="name" column="sname"/>
    <association property= "teacher" javaType= "Teacher">
        <result property="name" column="tname" />
    </association>
</resultMap>

```



## 10、一对多

#### **0、一对多使用collection**

#### 1、实体

```java
@Data
pub1ic class Student {
    private int id;
    private string name ;
    private int tid;
}

@Data
public class Teacher {
    private int id;
    private string name;
    //一个老师拥有多个学生
    private List<Student> students ;
}

@Test
// 测试
public void test(){
    SqlSession sq1Session = MybatisUtils . getSqlSession();
    for (Teacher teacher : sqlSession. getMapper(TeacherMapper . class). getTeacher()) {
        System. out . println(teacher);
    }
    sqlSession. close();
}

```



```xml

<mapper namespace="com.kuang.dao.TeacherMapper">
    
    
    <!--按结果嵌套查询-->
    <select id="getTeacher" resultMap="TeacherStudent" >
        select s.id sid, s.name sname, t.name tname,t.id tid
        from student s,teacher t
        where s.tid = t.id and t.id = #{tid}
    </select>
    <resultMap id="TeacherStudent" type="Teacher">
        <result property="id" column="tid"/>
        <result property=" name" column="tname"/>
        <!--
			复杂的属性。我们需要中独处理对象: association 集合: collection
			javaType=""	指定属性的类型!
            集合中的泛型信息，我们使ofType 获取
		-->
        <collection property="students" ofType-="Student">
            <result property="id" column="sid"/>
            <result property="name" column="sname"/>
            <result property="tid" column="tid"/>
        </collection>
    </resultMap>
    
    
    
    <!-- 按照查询嵌套处理 -->
    <select id="getTeacher2" resultmap="Teacherstudent2">
        select * from mybatis. teacher where id = #{tid}
    </select>
    
    <resultMap id="Teacherstudent2" type= "Teacher">
        <collection property="students" javaType="ArrayList" ofType="student"
                    select="getstudentByeacherId" column="id"/>
    </resultMap>
    
    <select id="getstudentByTeacherId" resultType="Student">
        select * from mybatis. student where tid = #{tid}
    </select>

</mapper>

```



```java
@Test
public void test(){
    SqlSession sqlSession = MybatisUtils.getSqlSession();
    TeacherMapper mapper. = sqlSession.getMapper(TeacherMapper.class);
    Teacher teacher = mapper.getTeacher(1);
    System.out.println(teacher);
    sqlSession.close();
}

```

**小结**

-   关联 - association
-   集合 - collection
-   javaType  & ofType
    -   javaType 用来指定实体类中属性的类型
    -   ofType 用来指定映射到LIst或者集合中的实体类型，也就是泛型中的约束类型



## 11、动态Sql

>   **什么是动态Sql：动态sql就是根据不同的条件生成不同的sql语句**

`动态 SQL 是 MyBatis 的强大特性之一。如果你使用过 JDBC 或其它类似的框架，你应该能理解根据不同条件拼接 SQL 语句有多痛苦，例如拼接时要确保不能忘记添加必要的空格，还要注意去掉列表最后一个列名的逗号。利用动态 SQL，可以彻底摆脱这种痛苦。`

#### **trim（where，set）**

>   trim是where总的标签
>
>   *where* 元素只会在子元素返回任何内容的情况下才插入 “WHERE” 子句。而且，若子句的开头为 “AND” 或 “OR”，*where* 元素也会将它们去除。
>
>   *set* 元素会动态地在行首插入 SET 关键字，并会删掉额外的逗号

```xml
select * from mybatis.blog
<where>
    <if test="title != nu11">
        title = #{tit1e}
    </if>
    <if test="author != nu11">
        and author = #{author}
    </if>
</where>

<update id="updateAuthorIfNecessary">
  update Author
    <set>
      <if test="username != null">username=#{username},</if>
      <if test="password != null">password=#{password},</if>
      <if test="email != null">email=#{email},</if>
      <if test="bio != null">bio=#{bio}</if>
    </set>
  where id=#{id}
</update>

<trim prefix="SET" suffixOverrides=",">
  ...
</trim>

<trim prefix="WHERE" prefixOverrides="AND |OR ">
  ...
</trim>
```

####**choose、when、otherwise**

```xml
<select id="queryBlogChoose" parameterType="map" resultType="b1og">
    select * from mybatis. b7og
    <where>
        <choose>
            <when test="title != nu11">
                title = #{tit1e}
            </when>
            <when test="author != nu11">
                and author = #{author}
            </when>
            <otherwise>
                and views = #{views}
            </otherwise>
        </choose>
    </where>
</select>使用

```

>   =**所谓的动态SQL，本质还是SQL语句，只是我们可以在SQL层面，去执行一个逻辑代码**=



#### SQL片段

**把sql中相同的部分抽取出来，方便复用，使用sql标签设置一个id，在需要引用时使用include标签**

1.  使用Sql标签抽取公共部分

    ```xml
    <sq1 id="if-title-author">
        <if test="title != nu11">
            title = #{tit1e}
        </if>
        <if test="author != nu11">
            and author = #{author}
        </if>
    </sq1>
    
    ```

2.  在需要使用的地方使用用include标签引用

    ```xml
    <select id="queryB 1ogIF" parameterType="map" resu1tType="b1og">
        select * from mybatis.b1og
        <where>
            <include refi d="if-title-author"></include>
        </where>
    </select>
    
    ```

    **注意**

    -   最后基于单表定义sql片段
    -   不要存在where标签

#### **foreach**

![image-20210225205515684](G:\各科笔记\Mybatis笔记\mybatis.assets\image-20210225205515684.png)

```xml
<!--
	select * from mybatis.b1og where 1=1 and (id=1 or id = 2 or id=3) 
	我们现在传递一个万能的map，这map中可以存在一 - 个集合!
-->
<select id="queryB1ogForeach" parameterType= "map" resu1tType="b1og">
    select * from mybatis.blog
    <where>
        <foreach co1lection="ids" item-="id" open="and (" close=")" separator="or">
            id = #{id}
        </foreach>
    </where>
</select>
```

**面试高频**
 ●  Mysq引擎
 ●  InndDB底层原理
 ●  索引.
 ●  索引优化!



## 12、缓存

#### **1、什么是缓存**

1.  什么是缓存[ **Cache** ]?
    -   存在内存中的临时数据。
    -   将用户经常查询的数据放在缓存(内存) 中，用户去查询数据就不用从磁盘上(关系型数据库数据文件)查询，从缓存中查询,从而提高查询效率，解决了高并发系统的性能问题。
2.  为什么使用缓存?
    -   减少和数据库的交互次数，减少系统开销,提高系统效率。
3.  什么样的数据能使用缓存?
    -   **经常查询并且不经常改变的数据可以使用缓存**。

#### **2、Mybatis缓存**

-   MyBatis包含一个非常强大的查询缓存特性, 它可以非常方便地定制和配置缓存。缓存可以极大的提升查询效
    率。
-   MyBatis系统中默认定义了两级缓存: **一级缓存和二级缓存**
    -   默认情况下，只有一级缓存开启。 (**SqlSession级别的缓存， 也称为本地缓存**)
    -   二级缓存需要手动开启和配置，他是基于**namespace级别的缓存**。
    -   为了提高扩展性，MyBatis定义了缓存接口Cache。我们可以通过实现Cache接口来自定义二级缓存

#### **3、一级缓存**

-   一级缓存也叫本地缓存: SqISession
    -   与数据库同一次会话期间查询到的数据会放在本地缓存中。
    -   以后如果需要获取相同的数据，直接从缓存中拿,没必须再去查询数据库;

测试步骤

1.  开启日志

2.  测试在一个Session中查询两次相同记录

3.  查看日志输出

    ![image-20210226153556005](G:\各科笔记\Mybatis笔记\mybatis.assets\image-20210226153556005.png)

**缓存失效情况**

1.  查询不同的东西

2.  增删改操作，可能会改变原来的数据，所以必定会刷新缓存

3.  查询不同的Mapper.xml

4.  手动清理缓存 

    ![image-20210226154426282](G:\各科笔记\Mybatis笔记\mybatis.assets\image-20210226154426282.png)

>   -   映射语句文件中的**所有 select 语句的结果将会被缓存**。
>   -   映射语句文件中的**所有 insert、update 和 delete 语句会刷新缓存**。
>   -   缓存会使用最近最少使用算法（LRU, Least Recently Used）**算法来清除不需要的缓存**。
>   -   缓存**不会定时进行刷新**（也就是说，没有刷新间隔）。
>   -   缓存会**保存列表或对象**（无论查询方法返回哪种）的 1024 个引用。
>   -   **缓存会被视为读/写缓存**，这意味着获取到的对象并不是共享的，可以安全地被调用者修改，而不干扰其他调用者或线程所做的潜在修改。

##### **小结：一级缓存默认是开启的，只在一次SqlSession中有效，也就是拿到连接到关闭连接这个区间，一级缓存就是一个Map**



#### **4、二级缓存**

-   二级缓存也叫全局缓存，- -级缓存作用域太低了，所以诞生了二级缓存
-   基于namespace级别的缓存，-个名称空间,对应一个二级缓存;
-   工作机制
    -   一个会话查询一条数据，这个数据就会被放在当前会话的一级缓存中;
    -   **如果当前会话关闭了，这个会话对应的一-级缓存就没了;但是我们想要的是，会话关闭了，一级缓存中的**
        **数据被保存到二级缓存中;**
    -   新的会话查询信息，就可以从二级缓存中获取内容;

```xml
<!-- 
	创建了一个 FIFO 缓存，每隔 60 秒刷新，最多可以存储结果对象或列表的 
	512 个引用，而且返回的对象被认为是只读的 -->
<!-- 在要使用二级缓存的Mapper.xml写入 -->
<cache />  => 开启二级缓存

<!-- 自定义缓存-->
<cache
  eviction="FIFO"
  flushInterval="60000"
  size="512"
  readOnly="true"/>
 

```

>   **LRU – 最近最少使用**：移除最长时间不被使用的对象。**【默认】**
>   **FIFO – 先进先出**：按对象进入缓存的顺序来移除它们。
>   **SOFT – 软引用**：基于垃圾回收器状态和软引用规则移除对象。
>   **WEAK – 弱引用**：更积极地基于垃圾收集器状态和弱引用规则移除对象。

步骤：

1.  开启全局缓存

    ```xml
    <settings>
        <!--标准的日志工实现-->
        <setting name="logImp1" value="STDOUT_ _LOGGING"/>
        <!--显示的开启全局缓存-->
        <setting name="cacheEnabled" value= "true"/>
    </settings>
    
    ```

    

    ![image-20210226155205589](G:\各科笔记\Mybatis笔记\mybatis.assets\image-20210226155205589.png)

2.  测试问题

    1.  实体类需要序列化

        ![image-20210226160505198](G:\各科笔记\Mybatis笔记\mybatis.assets\image-20210226160505198.png)



**小结**

-   只要开启了二级缓存，在同一个Mapper下就有效
-   所有的数据都会先放在一 级缓存中;
-   只有当会话提交,或者关闭的时候，才会提交到二级缓冲中!
  

#### **5、缓存原理**

**也可以指定查询语句在执行时禁止刷新缓存或开启缓存**

![image-20210226161700570](G:\各科笔记\Mybatis笔记\mybatis.assets\image-20210226161700570.png)

**缓存也就是为了提高查询效率**

缓存顺字

1.  先看二级缓存中有没有
2.  再看一-级缓存中有没有
3.  查询数据库



#### **6、自定义缓存-ehcache**

```
Ehcache是- - 种广泛使用的开源Java分布式缓存。主要面向通用缓存
```

```xml
要在程序中使用ehcache,先要导包! 在maven仓库中实现
 <!-- https://mvnreposi tory. com/artifact/org. mybatis. caches/mybatis -ehcache -->
<dependency>
    <groupId>org. mybatis. caches</groupId>
    <artifactId>mybati s-ehcache </artifactId>
    <version>1.1.0</version>
</dependency>

```

在mapper中指定使用我们的ehcache缓存实现!

```xml
<!--在当前Mapper.xm1中使用二级缓存-->
<cache type="org.mybatis.caches.ehcache.EhcacheCache"/>

```



**Redis（瑞第欧斯）数据库来做缓存**



## 13、日期类型

NOW()函数以`'YYYY-MM-DD HH:MM:SS'返回当前的日期时间，可以直接存到DATETIME字段中。

CURDATE()以’YYYY-MM-DD’的格式返回今天的日期，可以直接存到DATE字段中。

CURTIME()以’HH:MM:SS’的格式返回当前的时间，可以直接存到TIME字段中。



