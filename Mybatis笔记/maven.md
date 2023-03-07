# 问题

>   

**本地仓库：用来存储从远程或中央仓库下载的插件和jar包**、

**默认路径：C:\Users\夜生情\.m2\repository**

**远程仓库：如果本地需要插件或者 jar 包，本地仓库没有，默认去远程仓库下载。 远程仓库可以在互联网内也可以在局域网内**

**中央仓库 ：在 maven 软件中内置一个远程仓库地址 http://repo1.maven.org/maven2**



## 常用命令

-   **mvn clean  **

    >   **清理命令**，执行 clean 会删除 target 目录及内容。

-   **mvn compile**

    >   **编译命令** 将 src/main/java 下的文件编译为 class 文件输出到 target 目录下。

-   **mvn test**

    >   **测试命令** 会执行 src/test/java 下的单元测试类

-   **mvn package**

    >   **打包命令**  **对于 java 工程执行 package 打成 jar 包**，**对于 web 工程打成 war 包**。

-   **mvn install **

    >   **工程的安装命令**  执行 install 将 maven 打成 jar 包或 war 包发布到本地仓库

    

## 2.maven

#### 1.为什么要学习这个技术

> 	在javaweb开发中，需要使用大量的jar包，需要我们手动去导入
>  	如果能够让一个东西自动帮我们导入和配置这个jar包
>  	由此，Maven诞生了

#### **2.Maven它是一个 =>项目架构管理工具 (一个依赖管理系统)**

> **Maven的核心思想：约定大于配置**
>
> - 有约束，不要去违反
>
> Maven会规定发你该如何去编写我们的java代码，必须要按照这个规范来

#### **3.下载安装Maven**

​	官网：https://mvnrepository.com/



#### **4.配置Maven**

> 在系统环境变量中配置：
>
> - M2_HOME  maven目录下的bin目录地址
> - MAVEN_HOME maven目录的地址
> - 在系统环境变量中配置 %MAVEN_HOME%\bin
> - **使用cmd中输入mvn -version 测试是否配置成功**

#### **5.配置阿里云镜像**

> 镜像：**mirrors**
>
> ​	作用：加速我们下载
>
> ```xml
> <mirror>
>      <id>nexus-aliyun</id>
>      <mirrorof>*,!jeecg,!jeecg-snapshots</mirrorof>
>      <name>Nexus aliyun</name>
>      <url>http://maven.aliyun.com/nexus/content/groups/pub1ic/</url>
> </mirror>
> 
> <!--  -->
> <mirror>
>      <id>alimaven</id>
>      <mirrorOf>central</mirrorOf>
>      <name>aliyun maven</name>
>      <url>http://maven.aliyun.com/nexus/content/repositories/central/</url>
> </mirror>
> ```
>
> #### 建立一个本地仓库
>
> ```xml
> <localRepository>G:\jar\Mybatis\apache-maven-3.6.3\maven-repo</localRepository>
> ```

### 配置高级镜像

>   # 高级镜像配置
>
>   为了满足一些复杂的需求，Maven还支持更高级的镜像配置：
>
>   1.<mirrorOf>*</mirrorOf>
>
>   匹配所有远程仓库。
>
>   2.<mirrorOf>external:*</mirrorOf>
>
>   匹配所有远程仓库，使用localhost的除外，使用file://协议的除外。也就是说，匹配所有不在本机上的远程仓库。
>
>   3.<mirrorOf>repo1,repo2</mirrorOf>
>
>   匹配仓库repo1和repo2，使用逗号分隔多个远程仓库。
>
>   4.<mirrorOf>*,!repo1</miiroOf>
>
>   匹配所有远程仓库，repo1除外，使用感叹号将仓库从匹配中排除。
>
>   需要注意的是，由于镜像仓库完全屏蔽了被镜像仓库，当镜像仓库不稳定或者停止服务的时候，Maven仍将无法访问被镜像仓库，因而将无法下载构件
>
>   
>
>   作者：DrinkwaterGor
>   链接：https://www.jianshu.com/p/274c363ffd7c
>   来源：简书
>   著作权归作者所有。商业转载请联系作者获得授权，非商业转载请注明出处。



#### 1.创建一个MavenWeb项目

​	普通Maven项目什么都不用勾

![image-20210217101200840](G:\各科笔记\Mybatis笔记\maven.assets\image-20210217101200840.png)

![image-20210217101430630](G:\各科笔记\Mybatis笔记\maven.assets\image-20210217101430630.png)

![image-20210217101629191](G:\各科笔记\Mybatis笔记\maven.assets\image-20210217101629191.png)

#### 一个干净的Maven项目

![image-20210217190927533](G:\各科笔记\Mybatis笔记\maven.assets\image-20210217190927533.png)

![image-20210217191249410](G:\各科笔记\Mybatis笔记\maven.assets\image-20210217191249410.png)

#### Maven中的配置文件

![image-20210217194935979](G:\各科笔记\Mybatis笔记\maven.assets\image-20210217194935979.png)

```xml
<!--配置--> .
<properties>
    <!--项目的默认构建编码-->
    <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
    <!--编码版本-->
    <maven.compiler.source>1.8</maven.compiler.source>
    <maven.compiler.target>1.8</maven.compiler.target>
</properties>

```



![image-20210217195018327](G:\各科笔记\Mybatis笔记\maven.assets\image-20210217195018327.png)

```xml
<!--项目依赖-->
<dependencies>
    <!--具体依赖的jar包配置文件-->
    <dependency>
        <groupId>junit</groupId>
        <artifactId>junit</artifactId>
        <version>4.11</version>
    </dependency>
</dependencies>
```



![image-20210217195702666](G:\各科笔记\Mybatis笔记\maven.assets\image-20210217195702666.png)

```xml
<!--Maven的高级之处在于，他会帮你导入这个JAR包所依赖的其他jar-->
<!-- https://mvnrepository. com/artifact/org. springframework/spring-webmvc -->
<dependency>
    <groupId>org.springframework</groupId>
    <artifactId>spring-webmvc</artifactId>
    <version>5.1.9.RELEASE</version>
</dependency>

```



![image-20210217195955405](G:\各科笔记\Mybatis笔记\maven.assets\image-20210217195955405.png)

```xml
<!--在build中配置resources，来防止我们资源导出失败的问题-->
<build>
    <resources>
        <resource>
            <directory>src/main/resources</directory>
            <excludes>
                <exclude>**/*.properties</exclude>
                <exclude>**/*.xml</exclude>
            </excludes>
            <filtering>false</filtering>
        </resource>
        <resource >
            <directory>src/main/java</directory>
            <includes>
                <include>**/*.properties</include>
                <include>**/*.xml</include>
            </includes>
            <filtering>false</filtering>
        </resource>
    </resources>
</build>
```

```xml
<build>
    <!-- 项目资源清单 -->
    <resources>
        <!-- 项目资源 -->
        <resource>
            <!-- 资源目录（编译时会将指定资源目录中的内容复制到输出目录） -->
            <directory>src/main/resources</directory>
            <!-- 排除内容（编译时不复制指定排除内容） -->
            <excludes>
                <exclude>**/*.properties</exclude>
                <exclude>**/*.xml</exclude>
            </excludes>
            <!-- 是否开启过滤 true：使用过滤  false：不做过滤替换操作 -->
            <filtering>false</filtering>
        </resource>
        <resource >
            <directory>src/main/java</directory>
            <!-- 包含内容（编译时仅复制指定包含内容） -->
            <includes>
                <include>**/*.properties</include>
                <include>**/*.xml</include>
            </includes>
            <filtering>true</filtering>
        </resource>
    </resources>
</build>
```

```xml
<build>
        <!-- 资源目录 -->
        <resources>
            <resource>
                <!-- 设定主资源目录  -->
                <directory>src/main/java</directory>

                <!-- maven default生命周期，process-resources阶段执行maven-resources-plugin插件的resources目标处理主资源目下的资源文件时，只处理如下配置中包含的资源类型 -->
                <includes>
                    <include>**/*.xml</include>
                </includes>

                <!-- maven default生命周期，process-resources阶段执行maven-resources-plugin插件的resources目标处理主资源目下的资源文件时，不处理如下配置中包含的资源类型（剔除下如下配置中包含的资源类型）-->
                <excludes>
        <build>
        <!-- 资源目录 -->
        <resources>
            <resource>
                <!-- 设定主资源目录  -->
                <directory>src/main/java</directory>

                <!-- maven default生命周期，process-resources阶段执行maven-resources-plugin插件的resources目标处理主资源目下的资源文件时，只处理如下配置中包含的资源类型 -->
                <includes>
                    <include>**/*.xml</include>
                </includes>

                <!-- maven default生命周期，process-resources阶段执行maven-resources-plugin插件的resources目标处理主资源目下的资源文件时，不处理如下配置中包含的资源类型（剔除下如下配置中包含的资源类型）-->
                <excludes>
                    <exclude>**/*.yaml</exclude>
                </excludes>

                <!-- maven default生命周期，process-resources阶段执行maven-resources-plugin插件的resources目标处理主资源目下的资源文件时，指定处理后的资源文件输出目录，默认是${build.outputDirectory}指定的目录-->
                <!--<targetPath>${build.outputDirectory}</targetPath> -->

                <!-- maven default生命周期，process-resources阶段执行maven-resources-plugin插件的resources目标处理主资源目下的资源文件时，是否对主资源目录开启资源过滤 -->
                <filtering>true</filtering>
            </resource>
        </resources>
    </build>            <exclude>**/*.yaml</exclude>
                </excludes>

                <!-- maven default生命周期，process-resources阶段执行maven-resources-plugin插件的resources目标处理主资源目下的资源文件时，指定处理后的资源文件输出目录，默认是${build.outputDirectory}指定的目录-->
                <!--<targetPath>${build.outputDirectory}</targetPath> -->

                <!-- maven default生命周期，process-resources阶段执行maven-resources-plugin插件的resources目标处理主资源目下的资源文件时，是否对主资源目录开启资源过滤 -->
                <filtering>true</filtering>
            </resource>
        </resources>
    </build>
```



#### **解决配置文件无法被导出的问题**

![image-20210220101152655](G:\各科笔记\Mybatis笔记\maven.assets\image-20210220101152655.png)

![image-20210220101247238](G:\各科笔记\Mybatis笔记\maven.assets\image-20210220101247238.png)

### jdk配置

```xml
<profiles>
    <profile>
        <id>jdk18</id>
        <activation>
            <activeByDefault>true</activeByDefault>
            <jdk>1.8</jdk>
        </activation>
        <properties>
            <maven.compiler.source>1.8</maven.compiler.source>
            <maven.compiler.target>1.8</maven.compiler.target>
            <maven.compiler.compilerVersion>1.8</maven.compiler.compilerVersion>
        </properties>
    </profile>
</profiles>
```

### 创建模板下载jar包

```xml
<?xml version="1.0" encoding="UTF-8"?>

<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
  <modelVersion>4.0.0</modelVersion>

  <groupId>org.example</groupId>
  <artifactId>maven07</artifactId>
  <version>1.0-SNAPSHOT</version>
  <packaging>war</packaging>

  <name>maven07 Maven Webapp</name>
  <!-- FIXME change it to the project's website -->
  <url>http://www.example.com</url>

  <properties>
    <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
    <maven.compiler.source>1.7</maven.compiler.source>
    <maven.compiler.target>1.7</maven.compiler.target>
  </properties>

  <dependencies>
    <dependency>
      <groupId>junit</groupId>
      <artifactId>junit</artifactId>
      <version>4.11</version>
      <scope>test</scope>
    </dependency>
  </dependencies>

  <build>
    <finalName>maven07</finalName>
    <pluginManagement><!-- lock down plugins versions to avoid using Maven defaults (may be moved to parent pom) -->
      <plugins>
        <plugin>
          <artifactId>maven-clean-plugin</artifactId>
          <version>3.1.0</version>
        </plugin>
        <!-- see http://maven.apache.org/ref/current/maven-core/default-bindings.html#Plugin_bindings_for_war_packaging -->
        <plugin>
          <artifactId>maven-resources-plugin</artifactId>
          <version>3.0.2</version>
        </plugin>
        <plugin>
          <artifactId>maven-compiler-plugin</artifactId>
          <version>3.8.0</version>
        </plugin>
        <plugin>
          <artifactId>maven-surefire-plugin</artifactId>
          <version>2.22.1</version>
        </plugin>
        <plugin>
          <artifactId>maven-war-plugin</artifactId>
          <version>3.2.2</version>
        </plugin>
        <plugin>
          <artifactId>maven-install-plugin</artifactId>
          <version>2.5.2</version>
        </plugin>
        <plugin>
          <artifactId>maven-deploy-plugin</artifactId>
          <version>2.8.2</version>
        </plugin>
      </plugins>
    </pluginManagement>
  </build>
</project>

```

```xml
<build>
    <resources>
        <resource>
            <directory>src/main/java</directory>
            <includes>
                <include>**/*.properties</include>
                <include>**/*.xml</include>
            </includes>
            <filtering>false</filtering>
        </resource>
        <resource>
            <directory>src/main/resources</directory>
            <includes>
                <include>**/*.properties</include>
                <include>**/*.xml</include>
            </includes>
            <filtering>false</filtering>
        </resource>
    </resources>
</build>
```

```

```

