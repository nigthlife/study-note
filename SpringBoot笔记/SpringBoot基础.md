### SpringBoot配置相关

```bash
# 更改项目端口号
server.port=8081
```



```java
// @SpringBootApplication: 标注这个类是一个SpringBoot的应用
// 这个注解是一个组合注解
@SpringBootApplication  => 启动类下所有资源被导入
public class Sprintboot01HelloApplication {

    public static void main(String[] args) {
        // 将SpringBoot应用启动的  通过反射加载类
        SpringApplication.run(Sprintboot01HelloApplication.class, args);
    }

}

```

####@SpringBootApplication

```properties

@Target({ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Inherited

@SpringBootConfiguration    #核心 这是springboot的配置
	@Configuration  Spring配置类
		 @Component  说明这也是一个Spring组件
@EnableAutoConfiguration	#核心 这是自动配置
	@AutoConfigurationPackage  => 自动配置包
		@Import({Registrar.class}) => 自动配置包注册
	@Import({AutoConfigurationImportSelector.class}) => 自动配置导入选择


# 扫码这个文件下的所有包
@ComponentScan(
    excludeFilters = {@Filter(
    type = FilterType.CUSTOM,
    classes = {TypeExcludeFilter.class}
), @Filter(
    type = FilterType.CUSTOM,
    classes = {AutoConfigurationExcludeFilter.class}
)}
)
```

### 自动配置核心文件

![image-20210513105530001](G:\各科笔记\springBoot\SpringBoot基础.assets\image-20210513105530001.png)

