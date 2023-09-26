==@Cacheable==

```properties
当我们在调用一个缓存方法时会把该方法参数和返回结果作为一个键值对存放在缓存中，
等到下次利用同样的参数来调用该方法时将不再执行该方法，而是直接从缓存中获取结果进行返回
所以在使用Spring Cache的时候我们要保证我们缓存的方法对于相同的方法参数要有相同的返回结果。
```

==Stream.map()==

```properties
Stream.map()是Stream最常用的一个转换方法，它把一个Stream转换为另一个Stream。所谓map操作，就是把一种操作运算，映射到一个序列的每一个元素上。如果我们查看Stream的源码，会发现map()方法接收的对象是Function接口对象，它定义了一个apply()方法，负责把一个T类型转换成R类型
```

==InitializingBean==

```properties
InitializingBean接口为bean提供了初始化方法的方式，
它只包括afterPropertiesSet方法，凡是继承该接口的类，
在初始化bean的时候都会执行该方法
```

