[TOC]



## 1、什么是JUC

>   **什么是JUC**,顾名思义**J**是java，**u**是util，**c**是concurrent，也就是java工具类中的一个包
>
>   主要是对java工具类中的concurrent、concurrent.atomic、concurrent.lock三个包的操作

**一般业务：普通的线程代码 Therad**  开启线程 => new Thread(Runnable隐藏内部类,线程名称).strat()

**Runnable：**没有返回值，效率相比于Callable相对较低

![image-20210707210224783](G:\各科笔记\JUC笔记\JUC.assets\image-20210707210224783.png)

主要是对这三个包的操作：

![image-20210707210132055](G:\各科笔记\JUC笔记\JUC.assets\image-20210707210132055.png)

**java开启线程的三种方式：Thread、Runnable、Callable**

==java并不能真正开启线程！==

当前我们使用Thread开启start一个线程，他会先把个线程加入一个线程组，然后再调用一个**本地方法start0()**方法

## 2、线程与进程

>   **进程：一个进程包含多个线程，至少包含一个线程**
>
>   **线程：线程为进程的进一步单位划分**
>
>   **线程与进程的本质：进程拥有独立资源，线程共享除堆栈外的所有资源**



**Java启动默认开启两个线程，一个为main线程，一个为GC垃圾回收线程**

**Java真的不能开启线程**

```java
    public synchronized void start() {
        if (threadStatus != 0)
            throw new IllegalThreadStateException();
        // 将线程加入线程组
        group.add(this);
        boolean started = false;
        try {
            start0();
            started = true;
        } finally {
            try {
                if (!started) {
                    group.threadStartFailed(this);
                }
            } catch (Throwable ignore) {
                /* do nothing. If start0 threw a Throwable thenit will be passed up the 				call stack */
            }
        }
    }
    // 本地方法，底层的C++ ，Java 无法直接操作硬件
	private native void start0(

```



### 2.1、并发、并行

**并发编程的本质：充分利用CPU的资源**

>   **并发：（多线程同时操作一个资源）**
>
>   -   CPU 单核情况，模拟多条线程，也就是快速交替
>
>   **并行：（多个人一起行走）**
>
>   -   CPU 多核情况去，多个线程同时执行

![image-20210707212212578](G:\各科笔记\JUC笔记\JUC.assets\image-20210707212212578.png)

```java
package com.kuang.demo01;

// CPU密集型，IO密集型
public class Test1 {
    public static void main(String[] args) {
        // 获取cpu的核数
        System.out.println(Runtime.getRuntime().availableProcessors());
    }
}
```

>   **线程有几个状态（7个）**

```java
使用Thread.State查看线程的所有状态
    public enum State {
		// 新生 new
        NEW,

		// 运行 runnable
        RUNNABLE,

      	// 阻塞 blocked
        BLOCKED,

       	// 等待，一直等待 waiting
        WAITING,

   		// 超时等待
        TIMED_WAITING,

        // 终止 terminated
        TERMINATED;
}
```

#### wait/sleep方法的区别

**1、来自不同的类**

wait =>  Object

sleep =>  Thread

**2、关于锁的释放**

wait会释放锁，

sleep不会释放锁，抱着锁睡觉

**3、使用范围的不同**

wait 必须在同步代码块中

sleep 可以在任何地方

**4、是否需要捕获异常**

wait 不需要捕获

sleep 需要捕获



## 3、[Lock锁]()



### 3.1、Lock接口

>   加锁：l.lock
>
>   解锁：l.unlock
>
>   [基本的卖票案例（Thread版）](./JUC.assets/基本的卖票.java)
>
>   [基本的卖票案例（lock版）](./JUC.assets/基本的卖票Lock版.java)

>   **lock锁实现类**
>
>   ==**ReentrantLock**==（可重入锁）、
>
>   >   用于公平锁与
>   >
>   >   **NonfairSync()** 非公平锁：可以插队（**Java默认**）飞儿sing课
>   >
>   >   **FairSync() **公平锁：先来后到
>
>   ==**ReentrantReadWriteLock.ReadLock（读锁）**==
>
>   ==**ReentrantReadWriteLock.WriteLock（写锁）**==

****

>   **Synchronized 和 Lock 的区别**
>
>   | Synchronized                                 | Lock                                            |
>   | -------------------------------------------- | ----------------------------------------------- |
>   | java内置的关键字                             | 是java的一个类                                  |
>   | 无法判断获取锁的状态                         | 可以判断是否获取到了锁                          |
>   | 会自动释放锁                                 | 必须手动释放释放锁，不释放会死锁                |
>   | 线程1 获取锁阻塞后别的线程会一直等待         | 不一定会一直等待下去                            |
>   | 可重入锁，不可以中断，是非公平锁（先来后到） | 可重入锁，可以 判断锁，非公平锁（可以自己设置） |
>   | 适合锁少量的代码同步问题                     | 适合锁大量的同步代码！                          |
>
>   [生产消费者案例（Synchronized版）](./JUC.assets/生产消费者Sync版.java)
>
>   [生产消费者案例（解决虚假唤醒）](./JUC.assets/生产消费者Sync版（虚假唤醒）.java)
>
>   [生产消费者案例（JUC版）](./JUC.assets/生产消费者Callable版.java)
>
>   [生产消费者案例（JUC唤醒指定的线程）](./JUC.assets/生产消费者Callable版唤醒指定线程.java)

## 4、8锁现象

>   如何判断锁的是谁，



>   **8锁：关于锁的8个问题**
>
>   [8锁问题（1-2问）](./JUC.assets/8锁问题（1-2）.java)
>
>   [8锁问题（3-4问）](./JUC.assets/8锁问题（3-4）.java)
>
>   [8锁问题（5-6问）](./JUC.assets/8锁问题（5-6）.java)
>
>   [8锁问题（7-8问）](./JUC.assets/8锁问题（7-8）.java)
>
>   new this 具体的一个手机	
>
>   static Class 唯一的一个模板



## 5、集合类不安全

>   **List不安全**
>
>   [集合List](./JUC.assets/集合List.java)



>   **Set不安全**
>
>   [集合Set](./JUC.assets/集合Set.java)
>
>   **hashSet的底层**
>
>   ```java
>   使用的是map的KV键值对，使用map的key来存储元素，value是一个固定的不变值
>   
>   public HashSet() {
>       map = new HashMap<>();
>   }
>   
>   // add set 本质就是 map key是无法重复的！
>   public boolean add(E e) {
>       return map.put(e, PRESENT)==null;
>   }
>   private static final Object PRESENT = new Object(); // 不变得值！
>   ```
>
>   



>   Map不安全
>
>   [集合map](./JUC.assets/集合map.java)
>
>   ```java
>   // 初始容量为16
>   static final int DEFAULT_INITIAL_CAPACITY = 1 << 4; // aka 16
>   
>   // 最大容量
>   static final int MAXIMUM_CAPACITY = 1 << 30;
>   
>   // 默认的加载因子0.75
>   static final float DEFAULT_LOAD_FACTOR = 0.75f;
>   ```
>
>   



## 6、Callable（简单）

>   `Callable`接口类似于[`Runnable`](../../../java/lang/Runnable.html)  ，因为它们都是为了**另一个线程执行**的类设计的。 然而，A  `Runnable`**不返回结果，也不能抛出被检查的异常**。 
>
>   该[`Executors`](../../../java/util/concurrent/Executors.html)类包含的实用方法，从其他普通形式转换为`Callable`类。 
>
>   `Callable`
>
>   -   可以有返回值
>
>   -   可以跑出异常
>
>       ```python
>       // Runnable的父类
>       RunnableFuture <V>， RunnableScheduledFuture <V>
>                               
>           // 实现类
>           AsyncBoxView.ChildState ，
>           ForkJoinWorkerThread ， 
>           FutureTask ， 
>           RenderableImageProducer ， 
>           SwingWorker ， 
>           Thread ， 
>           TimerTask 
>       ```
>
>       [Callable案例](./JUC.assets/Callable.java)
>
>       细节：
>       1、有缓存
>       2、结果可能需要等待，会阻塞！



## 7、常用辅助类

### 7.1、CountDownLatch

>   -   允许一个或多个线程等待直到在其他线程中执行的一组操作完成的同步辅助。 
>
>   -   ```java
>       package com.kuang.add;
>       import java.util.concurrent.CountDownLatch;
>       // 计数器
>       public class CountDownLatchDemo {
>           public static void main(String[] args) throws InterruptedException {
>               // 总数是6，必须要执行完6个任务的时候，才会执行 countDownLatch.await();后的代码
>               CountDownLatch countDownLatch = new CountDownLatch(6);
>               for (int i = 1; i <=6 ; i++) {
>                   new Thread(()->{
>                       System.out.println(Thread.currentThread().getName()+" Go out");
>                       countDownLatch.countDown(); // 数量-1
>                   },String.valueOf(i)).start();
>               }
>               countDownLatch.await(); // 等待计数器归零，然后再向下执行
>               System.out.println("Close Door");
>           }
>       }
>       ```
>
>       原理：
>       **countDownLatch.countDown()**;      // 数量-1
>       **countDownLatch.await();** 				// 等待计数器归零，然后再向下执行
>       **每次有线程调用 countDown() 数量-1，**
>
>       **假设计数器变为0，countDownLatch.await() 就会被唤醒，继续执行！**



### 7.3 CyclicBarrier (加法计数器)



>   ```java
>   package com.kuang.add;
>   import java.util.concurrent.BrokenBarrierException;
>   import java.util.concurrent.CyclicBarrier;
>   public class CyclicBarrierDemo {
>       public static void main(String[] args) {
>           /**
>            * 集齐7颗龙珠召唤神龙
>            */
>           // 召唤龙珠的线程
>           CyclicBarrier cyclicBarrier = new CyclicBarrier(7,()->{
>               System.out.println("召唤神龙成功！");
>           });
>           
>           for (int i = 1; i <=7 ; i++) {
>               final int temp = i;
>               // lambda能操作到 i 吗
>               new Thread(()->{
>                   System.out.println(Thread.currentThread().getName()+"收集"+temp+"珠");
>                        try {
>                            	  // 当等待的线程数到达7个时执行cyclicBarrier中的方法
>                                 cyclicBarrier.await(); // 等待
>                             } catch (InterruptedException e) {
>                                 e.printStackTrace();
>                             } catch (BrokenBarrierException e) {
>                                 e.printStackTrace();
>                             }
>                             }).start();
>               }
>         }
>   }
>   ```
>
>   



### 7.3 Semaphore （限流）



>   ```java
>   import java.util.concurrent.Semaphore;
>   import java.util.concurrent.TimeUnit;
>   public class SemaphoreDemo {
>       public static void main(String[] args) {
>           // 线程数量：停车位! 限流！ 每次只能停三个车，车位满了必须等待其它车辆出去
>           Semaphore semaphore = new Semaphore(3);
>           for (int i = 1; i <=6 ; i++) {
>               new Thread(()->{
>                   // acquire() 得到
>                   try {
>                       semaphore.acquire();
>                       System.out.println(Thread.currentThread().getName()+"抢到车位");
>                       TimeUnit.SECONDS.sleep(2);
>                       System.out.println(Thread.currentThread().getName()+"离开车位");
>                   } catch (InterruptedException e) {
>                       e.printStackTrace();
>                   } finally {
>                       semaphore.release(); // release() 释放
>                   }
>               },String.valueOf(i)).start();
>           }
>       }
>   }
>   ```
>
>   **原理：**
>
>   -   semaphore.acquire() 获得，假设如果已经满了，等待，等待被释放为止！
>
>   -   semaphore.release(); 释放，会将当前的信号量释放 + 1，然后唤醒等待的线程！
>       -   作用： 多个共享资源互斥的使用！并发限流，控制最大的线程



## 8、读写锁

**ReadWriteLock**

>   实现类
>
>   -   ReentrantReadWriteLock
>
>   [ReentrantReadWriteLock案例](./JUC.assets/ReentrantReadWriteLock.java)



## 9、阻塞队列



**BlockingQueue**

>   阻塞队列：**[BlockingQueue](../../java/util/concurrent/BlockingQueue.html)** 
>
>   数组阻塞队列：[**ArrayBlockingQueue**](../../../java/util/concurrent/ArrayBlockingQueue.html)
>
>   链表阻塞队列：[**LinkedBlockingQueue**](../../java/util/concurrent/LinkedBlockingQueue.html)
>
>   双端队列：**[Deque](../../java/util/Deque.html)**
>
>   链表阻塞双端队列：[**LinkedBlockingDeque**](../../java/util/concurrent/LinkedBlockingDeque.html)
>
>   非阻塞队列：**[ArrayBlockingQueue](../../../java/util/concurrent/ArrayBlockingQueue.html)** 
>
>   同步队列：[**SynchronousQueue**](../../java/util/concurrent/SynchronousQueue.html)

![image-20210712172410345](G:\各科笔记\JUC笔记\JUC.assets\image-20210712172410345.png)

什么情况下我们会使用 阻塞队列：多线程并发处理，线程池！

**学会使用队列**

**添加、移除**

**四组API**

| 方式         | 抛出异常 | 有返回值，不抛出异常 | 阻塞 等待 | 超时等待  |
| ------------ | -------- | -------------------- | --------- | --------- |
| 添加         | add      | offer()              | put()     | offer(,,) |
| 移除         | remove   | poll()               | take()    | poll(,)   |
| 检测队首元素 | element  | peek                 | -         | -         |

>   ```java
>   /**
>   * 抛出异常
>   */
>   public static void test1(){
>       // 队列的大小
>       ArrayBlockingQueue blockingQueue = new ArrayBlockingQueue<>(3);
>       System.out.println(blockingQueue.add("a"));
>       System.out.println(blockingQueue.add("b"));
>       System.out.println(blockingQueue.add("c"));
>       // IllegalStateException: Queue full 抛出异常！
>       // System.out.println(blockingQueue.add("d"));
>       System.out.println("=-===========");
>       System.out.println(blockingQueue.remove());
>       System.out.println(blockingQueue.remove());
>       System.out.println(blockingQueue.remove());
>       // java.util.NoSuchElementException 抛出异常！
>       // System.out.println(blockingQueue.remove());
>   }
>   ```
>
>   ```java
>   /**
>   * 有返回值，没有异常
>   */
>   public static void test2(){
>       // 队列的大小
>       ArrayBlockingQueue blockingQueue = new ArrayBlockingQueue<>(3);
>       System.out.println(blockingQueue.offer("a"));
>       System.out.println(blockingQueue.offer("b"));
>       System.out.println(blockingQueue.offer("c"));
>       // System.out.println(blockingQueue.offer("d")); // false 不抛出异常！
>       System.out.println("============================");
>       System.out.println(blockingQueue.poll());
>       System.out.println(blockingQueue.poll());
>       System.out.println(blockingQueue.poll());
>       System.out.println(blockingQueue.poll()); // null 不抛出异常！
>   }
>   ```
>
>   ```java
>   /**
>   * 等待，阻塞（一直阻塞）
>   */
>   public static void test3() throws InterruptedException {
>       // 队列的大小
>       ArrayBlockingQueue blockingQueue = new ArrayBlockingQueue<>(3);
>   
>       // 一直阻塞
>       blockingQueue.put("a");
>       blockingQueue.put("b");
>       blockingQueue.put("c");
>       // blockingQueue.put("d"); // 队列没有位置了，一直阻塞
>       System.out.println(blockingQueue.take());
>       System.out.println(blockingQueue.take());
>       System.out.println(blockingQueue.take());
>       System.out.println(blockingQueue.take()); // 没有这个元素，一直阻塞
>   }
>   ```
>
>   ```java
>   /**
>   * 等待，阻塞（等待超时）
>   */
>   public static void test4() throws InterruptedException {
>       // 队列的大小
>       ArrayBlockingQueue blockingQueue = new ArrayBlockingQueue<>(3);
>       blockingQueue.offer("a");
>       blockingQueue.offer("b");
>       blockingQueue.offer("c");
>       // blockingQueue.offer("d",2,TimeUnit.SECONDS); // 等待超过2秒就退出
>       System.out.println("===============");
>       System.out.println(blockingQueue.poll());
>       System.out.println(blockingQueue.poll());
>       System.out.println(blockingQueue.poll());
>       blockingQueue.poll(2,TimeUnit.SECONDS); // 等待超过2秒就退出
>   }
>   ```
>
>   



>   **SynchronousQueue 同步队列**
>
>   没有容量，进去一个元素，必须等待取出来之后，才能再往里面放一个元素！

```java
package com.kuang.bq;
import java.sql.Time;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.SynchronousQueue;
import java.util.concurrent.TimeUnit;
/**
* 同步队列
* 和其他的BlockingQueue 不一样， SynchronousQueue 不存储元素
* put了一个元素，必须从里面先take取出来，否则不能在put进去值！
*/
public class SynchronousQueueDemo {
    public static void main(String[] args) {
        BlockingQueue<String> blockingQueue = new SynchronousQueue<>(); // 同步队列
            new Thread(()->{
                try {
                    System.out.println(Thread.currentThread().getName()+" put 1");
                    blockingQueue.put("1");
                    System.out.println(Thread.currentThread().getName()+" put 2");
                    blockingQueue.put("2");
                    System.out.println(Thread.currentThread().getName()+" put 3");
                    blockingQueue.put("3");
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            },"T1").start();
        new Thread(()->{
            try {
                TimeUnit.SECONDS.sleep(3);
                System.out.println(Thread.currentThread().getName()+"=>"+blockingQueue.take());
                TimeUnit.SECONDS.sleep(3);
                System.out.println(Thread.currentThread().getName()+"=>"+blockingQueue.take());
                TimeUnit.SECONDS.sleep(3);
                System.out.println(Thread.currentThread().getName()+"=>"+blockingQueue.take());
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        },"T2").start();
    }
}
```



## 10、线程池

**==线程池：三大方法、7大参数、4中拒绝策略==**



>   **池化技术**
>
>   程序运行的本质：占用系统的资源！优化资源的使用  ==>  池化技术
>
>   线程池、连接池、内存池、对象池、常量池，为什么需要池化技术，为解决某些东西创建或者销毁十分浪费资源
>
>   池化技术：事先准备好一些资源，有人要用，就来我这里来拿，用完之后在还会给我
>
>   **池化技术的好处**
>
>   1.  降低支资源的消耗
>   2.  提高响应速度
>   3.  方便管理
>   4.  线程复用，可以控制最大的并发数，管理线程
>
>   



### 三大方法

![image-20210712173759415](G:\各科笔记\JUC笔记\JUC.assets\image-20210712173759415.png)

**使用ThreadPoolExecutor创建线程池**

```java
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
// Executors 工具类、3大方法
public class Demo01 {
    public static void main(String[] args) {
        ExecutorService threadPool = Executors.newSingleThreadExecutor();// 单个线
        程
            // ExecutorService threadPool = Executors.newFixedThreadPool(5); // 创建一个固定的线程池的大小
            // ExecutorService threadPool = Executors.newCachedThreadPool(); // 可伸缩的，遇强则强，遇弱则弱
            try {
                for (int i = 0; i < 100; i++) {
                    // 使用了线程池之后，使用线程池来创建线程
                    threadPool.execute(()->{
                        System.out.println(Thread.currentThread().getName()+" ok");
                    });
                }
            } catch (Exception e) {
                e.printStackTrace();
            } finally {
                // 线程池用完，程序结束，关闭线程池
                threadPool.shutdown();
            }
    }
}
```

### 7 大参数

源码分析

```java
public static ExecutorService newSingleThreadExecutor() {
    return new FinalizableDelegatedExecutorService
        (new ThreadPoolExecutor(1, 1,
                                0L, TimeUnit.MILLISECONDS,
                                new LinkedBlockingQueue<Runnable>()));
}
public static ExecutorService newFixedThreadPool(int nThreads) {
    return new ThreadPoolExecutor(5, 5,
                                  0L, TimeUnit.MILLISECONDS,
                                  new LinkedBlockingQueue<Runnable>());
}
public static ExecutorService newCachedThreadPool() {
    return new ThreadPoolExecutor(0, Integer.MAX_VALUE,
                                  60L, TimeUnit.SECONDS,
                                  new SynchronousQueue<Runnable>());
}
// 本质ThreadPoolExecutor（）
public ThreadPoolExecutor(int corePoolSize, // 核心线程池大小
                          int maximumPoolSize, // 最大核心线程池大小
                          long keepAliveTime, // 超时了没有人调用就会释放
                          TimeUnit unit, // 超时单位
                          BlockingQueue<Runnable> workQueue, // 阻塞队列
                          ThreadFactory threadFactory, // 线程工厂：创建线程的，一般
                          不用动
                          RejectedExecutionHandler handle // 拒绝策略
                         ) {
    if (corePoolSize < 0 ||
        maximumPoolSize <= 0 ||
        maximumPoolSize < corePoolSize ||
        keepAliveTime < 0)
        throw new IllegalArgumentException();
    if (workQueue == null || threadFactory == null || handler == null)
        throw new NullPointerException();
    this.acc = System.getSecurityManager() == null ?
        null :
    AccessController.getContext();
    this.corePoolSize = corePoolSize;
    this.maximumPoolSize = maximumPoolSize;
    this.workQueue = workQueue;
    this.keepAliveTime = unit.toNanos(keepAliveTime);
    this.threadFactory = threadFactory;
    this.handler = handler;
}
```

[**银行案例**](./JUC.assets/线程池银行案例.java)

**[IO密集型、CPU密集型](./JUC.assets/设置最大核心数.java)**

### 四种拒绝策略

**RejectedExecutionHandler**

![image-20210712175446236](G:\各科笔记\JUC笔记\JUC.assets\image-20210712175446236.png)

```java
/**
* new ThreadPoolExecutor.AbortPolicy() // 银行满了，还有人进来，不处理这个人的，抛出异常
* new ThreadPoolExecutor.CallerRunsPolicy() // 哪来的去哪里！
* new ThreadPoolExecutor.DiscardPolicy() //队列满了，丢掉任务，不会抛出异常！
* new ThreadPoolExecutor.DiscardOldestPolicy() //队列满了，尝试去和最早的竞争，也不会抛出异常！
*/
```



## 11、四大函数式接口

新时代的程序员：lambda表达式、链式编程、函数式接口、Stream流式

四大函数式接口：**Consumer、Function、Predicate、Supplier**

### 函数式接口

>    只有一个方法的接口
>
>   ```java
>   @FunctionalInterface
>   public interface Runnable {
>       public abstract void run();
>   }
>   // 泛型、枚举、反射
>   // lambda表达式、链式编程、函数式接口、Stream流式计算
>   // 超级多FunctionalInterface
>   // 简化编程模型，在新版本的框架底层大量应用！
>   // foreach(消费者类的函数式接
>   ```
>
>   >   **函数式接口**
>   >
>   >   ```java
>   >   
>   >   import java.util.function.Function;
>   >   /**
>   >   * Function 函数型接口, 有一个输入参数，有一个输出
>   >   * 只要是 函数型接口 可以 用 lambda表达式简化
>   >   */
>   >   public class Demo01 {
>   >       public static void main(String[] args) {
>   >           //
>   >           // Function<String,String> function = new Function<String,String>() {
>   >           // @Override
>   >           // public String apply(String str) {
>   >           // return str;
>   >           // }
>   >           // };
>   >           Function<String,String> function = (str)->{return str;};
>   >           System.out.println(function.apply("asd"));
>   >       }
>   >   }
>   >   ```
>   >
>   >   
>
>   >   **断定型接口：有一个输入参数，返回值只能是 布尔值**
>   >
>   >   ```java
>   >   import java.util.function.Predicate;
>   >   /**
>   >   * 断定型接口：有一个输入参数，返回值只能是 布尔值！
>   >   */
>   >   public class Demo02 {
>   >       public static void main(String[] args) {
>   >           // 判断字符串是否为空
>   >           // Predicate<String> predicate = new Predicate<String>(){
>   >           // @Override
>   >           // public boolean test(String str) {
>   >           // return str.isEmpty();
>   >           // }
>   >           // };
>   >           Predicate<String> predicate = (str)->{return str.isEmpty(); };
>   >           System.out.println(predicate.test(""));
>   >       }
>   >   }
>   >   ```
>
>   >   **Consumer 消费型，只有输入，没有返回值**
>   >
>   >   ```java
>   >   import java.util.function.Consumer;
>   >   /**
>   >   * Consumer 消费型接口: 只有输入，没有返回值
>   >   */
>   >   public class Demo03 {
>   >       public static void main(String[] args) {
>   >           // Consumer<String> consumer = new Consumer<String>() {
>   >           // @Override
>   >           // public void accept(String str) {
>   >           // System.out.println(str);
>   >           // }
>   >           // };
>   >           Consumer<String> consumer = (str)->{System.out.println(str);};
>   >           consumer.accept("sdadasd");
>   >       }
>   >   }
>   >   ```
>
>   >   **Supplier 供给型接口，没有参数，只有返回值**
>   >
>   >   ```java
>   >   import java.util.function.Supplier;
>   >   /**
>   >   * Supplier 供给型接口 没有参数，只有返回值
>   >   */
>   >   public class Demo04 {
>   >       public static void main(String[] args) {
>   >           // Supplier supplier = new Supplier<Integer>() {
>   >           // @Override
>   >           // public Integer get() {
>   >           // System.out.println("get()");
>   >           // return 1024;
>   >           // }
>   >           // };
>   >           Supplier supplier = ()->{ return 1024; };
>   >           System.out.println(supplier.get());
>   >       }
>   >   }
>   >   ```



## 12、Stream流式计算

>   **什么是流式计算**
>
>   大数据：存储 + 计算
>
>   集合、MySQL 本质就是存储东西的；
>
>   计算都应该交给流来操作！
>
>   ```java
>   import java.util.Arrays;
>   import java.util.List;
>   /**
>   * 题目要求：一分钟内完成此题，只能用一行代码实现！
>   * 现在有5个用户！筛选：
>   * 1、ID 必须是偶数
>   * 2、年龄必须大于23岁
>   * 3、用户名转为大写字母
>   * 4、用户名字母倒着排序
>   * 5、只输出一个用户！
>   */
>   public class Test {
>       public static void main(String[] args) {
>           User u1 = new User(1,"a",21);
>           User u2 = new User(2,"b",22);
>           User u3 = new User(3,"c",23);
>           User u4 = new User(4,"d",24);
>           User u5 = new User(6,"e",25);
>           // 集合就是存储
>           List<User> list = Arrays.asList(u1, u2, u3, u4, u5);
>           // 计算交给Stream流
>           // lambda表达式、链式编程、函数式接口、Stream流式计算
>           list.stream()
>               .filter(u->{return u.getId()%2==0;})
>               .filter(u->{return u.getAge()>23;})
>               .map(u->{return u.getName().toUpperCase();})
>               .sorted((uu1,uu2)->{return uu2.compareTo(uu1);})
>               .limit(1)
>               .forEach(System.out::println);
>       }
>   }
>   ```
>
>   



## 13、ForkJoin	



>   什么是**ForkJoin**
>
>   **特点：工作窃取**
>
>   ForkJoin 在 JDK 1.7 ， 并行执行任务！提高效率。大数据量！
>
>   大数据：Map Reduce （把大任务拆分为小任务）
>
>   ![image-20210712181335493](G:\各科笔记\JUC笔记\JUC.assets\image-20210712181335493.png)



>   1
>
>   >   如何使用 **forkjoin**
>   >
>   >   ```java
>   >   import java.util.concurrent.RecursiveTask;
>   >   /**
>   >   * 求和计算的任务！
>   >   * 3000 6000（ForkJoin） 9000（Stream并行流）
>   >   * // 如何使用 forkjoin
>   >   * // 1、forkjoinPool 通过它来执行
>   >   * // 2、计算任务 forkjoinPool.execute(ForkJoinTask task)
>   >   * // 3. 计算类要继承 ForkJoinTask
>   >   */
>   >   public class ForkJoinDemo extends RecursiveTask<Long> {
>   >       private Long start; // 1
>   >       private Long end; // 1990900000
>   >       // 临界值
>   >       private Long temp = 10000L;
>   >       public ForkJoinDemo(Long start, Long end) {
>   >           this.start = start;
>   >           this.end = end;
>   >       }
>   >       // 计算方法
>   >       @Override
>   >       protected Long compute() {
>   >           if ((end-start)<temp){
>   >               Long sum = 0L;
>   >               for (Long i = start; i <= end; i++) {
>   >                   sum += i;
>   >               }
>   >               return sum;
>   >           }else { // forkjoin 递归
>   >               long middle = (start + end) / 2; // 中间值
>   >               ForkJoinDemo task1 = new ForkJoinDemo(start, middle);
>   >               task1.fork(); // 拆分任务，把任务压入线程队列
>   >               ForkJoinDemo task2 = new ForkJoinDemo(middle+1, end);
>   >               task2.fork(); // 拆分任务，把任务压入线程队列
>   >               return task1.join() + task2.join();
>   >           }
>   >       }
>   >   }
>   >   ```
>
>   >   测试
>   >
>   >   ```java
>   >   import java.util.concurrent.ExecutionException;
>   >   import java.util.concurrent.ForkJoinPool;
>   >   import java.util.concurrent.ForkJoinTask;
>   >   import java.util.stream.DoubleStream;
>   >   import java.util.stream.IntStream;
>   >   import java.util.stream.LongStream;
>   >   /**
>   >   * 同一个任务，别人效率高你几十倍！
>   >   */
>   >   public class Test {
>   >       public static void main(String[] args) throws ExecutionException,
>   >       InterruptedException {
>   >           // test1(); // 12224
>   >           // test2(); // 10038
>   >           // test3(); // 153
>   >       }
>   >       // 普通程序员
>   >       public static void test1(){
>   >           Long sum = 0L;
>   >           long start = System.currentTimeMillis();
>   >           for (Long i = 1L; i <= 10_0000_0000; i++) {
>   >               sum += i;
>   >           }
>   >           long end = System.currentTimeMillis();
>   >           System.out.println("sum="+sum+" 时间："+(end-start));
>   >       }
>   >       // 会使用ForkJoin
>   >       public static void test2() throws ExecutionException, InterruptedException {
>   >           long start = System.currentTimeMillis();
>   >           ForkJoinPool forkJoinPool = new ForkJoinPool();
>   >           ForkJoinTask<Long> task = new ForkJoinDemo(0L, 10_0000_0000L);
>   >           ForkJoinTask<Long> submit = forkJoinPool.submit(task);// 提交任务
>   >           Long sum = submit.get();
>   >           long end = System.currentTimeMillis();
>   >           System.out.println("sum="+sum+" 时间："+(end-start));
>   >       }
>   >       public static void test3(){
>   >           long start = System.currentTimeMillis();
>   >           // Stream并行流 () (]
>   >           long sum = LongStream.rangeClosed(0L,10_0000_0000L).parallel().reduce(0, Long::sum);
>   >           long end = System.currentTimeMillis();
>   >   
>   >           System.out.println("sum="+"时间："+(end-start));
>   >       }
>   >   }
>   >   ```
>   >
>   >   



## 14、异步回调

>   Future 设计的初衷： 对将来的某个事件的结果进行

>   ```java
>   import java.util.concurrent.CompletableFuture;
>   import java.util.concurrent.ExecutionException;
>   import java.util.concurrent.Future;
>   import java.util.concurrent.TimeUnit;
>   /**
>   * 异步调用： CompletableFuture
>   * // 异步执行
>   * // 成功回调
>   * // 失败回调
>   */
>   public class Demo01 {
>       public static void main(String[] args) throws ExecutionException,
>       InterruptedException {
>           // 没有返回值的 runAsync 异步回调
>           // CompletableFuture<Void> completableFuture =CompletableFuture.runAsync(()->{
>           // try {
>           // TimeUnit.SECONDS.sleep(2);
>           // } catch (InterruptedException e) {
>           // e.printStackTrace();
>           // }
>           //System.out.println(Thread.currentThread().getName()+"runAsync=>Void");
>           // });
>           //
>           // System.out.println("1111");
>           //
>           // completableFuture.get(); // 获取阻塞执行结果
>           // 有返回值的 supplyAsync 异步回调
>           // ajax，成功和失败的回调
>   
>           // 返回的是错误信息；
>           CompletableFuture<Integer> completableFuture =
>               CompletableFuture.supplyAsync(()->{
>                   System.out.println(Thread.currentThread().getName()+"supplyAsync=>Integer");
>                   int i = 10/0;
>                   return 1024;
>               });
>           System.out.println(completableFuture.whenComplete((t, u) -> {
>               System.out.println("t=>" + t); // 正常的返回结果
>               System.out.println("u=>" + u); // 错误信息：
>               java.util.concurrent.Complet ionException: java.lang.ArithmeticException: / by
>                   zero
>           }).exceptionally((e) -> {
>               System.out.println(e.getMessage());
>               return 233; // 可以获取到错误的返回结果
>           }).get());
>           /**
>            * succee Code 200
>            * error Code 404 500
>            */
>       }
>   }
>   ```
>
>   



## 15、JMM

>   在说JMM之前首先会了解一下Volatile
>
>   **Volatile是Java虚拟机提供的轻量级的同步机制**
>
>   Volattile有三个特性
>
>   -   保证可见性
>
>   -   >   ```java
>       >   import java.util.concurrent.TimeUnit;
>       >   public class JMMDemo {
>       >       // 不加 volatile 程序就会死循环！
>       >       // 加 volatile 可以保证可见性
>       >       private volatile static int num = 0;
>       >       public static void main(String[] args) { // main
>       >           new Thread(()->{ // 线程 1 对主内存的变化不知道的
>       >               while (num==0){
>       >               }
>       >           }).start();
>       >           try {
>       >               TimeUnit.SECONDS.sleep(1);
>       >           } catch (InterruptedException e) {
>       >               e.printStackTrace();
>       >           }
>       >           num = 1;
>       >           System.out.println(num);
>       >       }
>       >   }
>       >   ```
>
>   -   不保证原子性
>
>       -   原子性：不可分割
>
>       -   线程A在执行任务的时候，不能被打扰，也不能被分割，要么同时成功，要是同时失败
>
>       -   >   ```java
>           >   // volatile 不保证原子性
>           >   public class VDemo02 {
>           >       // volatile 不保证原子性
>           >       private volatile static int num = 0;
>           >       public static void add(){
>           >           num++;
>           >       }
>           >       public static void main(String[] args) {
>           >           //理论上num结果应该为 2 万
>           >           for (int i = 1; i <= 20; i++) {
>           >               new Thread(()->{
>           >                   for (int j = 0; j < 1000 ; j++) {
>           >                       add();
>           >                   }
>           >               }).start();
>           >           }
>           >           while (Thread.activeCount()>2){ // main gc
>           >               Thread.yield();
>           >           }
>           >           System.out.println(Thread.currentThread().getName() + " " + num);
>           >       }
>           >   }
>           >   ```
>           >
>           >   **如果不加lock锁和使用synchronized关键字如可保证原子性**
>           >
>           >   使用原子类，解决 原子性问题（**java.util.concurrent.atomic**包下）
>           >
>           >   ```java
>           >   
>           >   import java.util.concurrent.atomic.AtomicInteger;
>           >   // volatile 不保证原子性
>           >   public class VDemo02 {
>           >       // volatile 不保证原子性
>           >       // 原子类的 Integer
>           >       private volatile static AtomicInteger num = new AtomicInteger();
>           >       public static void add(){
>           >               // num++; // 不是一个原子性操作
>           >               num.getAndIncrement(); // AtomicInteger + 1 方法， CAS
>           >       }
>           >       public static void main(String[] args) {
>           >           //理论上num结果应该为 2 万
>           >           for (int i = 1; i <= 20; i++) {
>           >               new Thread(()->{
>           >                   for (int j = 0; j < 1000 ; j++) {
>           >                       add();
>           >                   }
>           >               }).start();
>           >           }
>           >           while (Thread.activeCount()>2){ // main gc
>           >               Thread.yield();
>           >           }
>           >           System.out.println(Thread.currentThread().getName() + " " + num);
>           >       }
>           >   }
>           >   ```
>           >
>           >   **这些类的底层都直接和操作系统挂钩！在内存中修改值！Unsafe类是一个很特殊的存在！**
>
>   -   禁止指令重排
>
>       -   由于你写的程序，计算机并不是按照你写的那样去执行的
>       -   它需要经过几个阶段，才会执行
>       -   **源代码-> 编译器优化的重排-> 指令并行也可能会重排-> 内存系统也会重排-> 执行**
>       -   **==处理器在进行指令重排的时候会考虑：数据之间的依赖性！==**



>   **Volatile为什么可以避免指令重排？**
>
>   **==Volatile 是可以保持 可见性。不能保证原子性，由于内存屏障，可以保证避免指令重排的现象产==**
>
>   **因为存在内存屏障，他的作用为：**
>
>   -   保证特定的操作的执行顺序
>   -   可以保证某些变量的内存可见性（利用这些特性volatile实现了可见
>
>   ![image-20210714215211120](G:\各科笔记\JUC笔记\JUC.assets\image-20210714215211120.png)



>   什么是JMM
>
>   **JMM是java内存模型，它只是一个概念，约定，java中并没有**

**JMM的一些同步约定**

1.  线程解锁前，必须把共享变量立刻刷会主内存
2.  线程加锁前，必须读取主内存中的最新值到工作内存中
3.  加锁和解锁是同一把锁



**线程分为：工作内存与主内存**



>   **内存交互操作有8种，虚拟机实现必须保证每一个操作都是原子的，不可在分的（对于double和long类**
>   **型的变量来说，load、store、read和write操作在某些平台上允许例外）**
>
>   -   lock （锁定）：作用于主内存的变量，把一个变量标识为线程独占状态
>
>   -   unlock （解锁）：作用于主内存的变量，它把一个处于锁定状态的变量释放出来，释放后的变量
>       才可以被其他线程锁定
>
>       
>
>   -   read （读取）：作用于主内存变量，它把一个变量的值从主内存传输到线程的工作内存中，以便
>       随后的load动作使用
>
>   -   load （载入）：作用于工作内存的变量，它把read操作从主存中变量放入工作内存中
>
>       
>
>   -   use （使用）：作用于工作内存中的变量，它把工作内存中的变量传输给执行引擎，每当虚拟机
>       遇到一个需要使用到变量的值，就会使用到这个指令
>
>   -   assign （赋值）：作用于工作内存中的变量，它把一个从执行引擎中接受到的值放入工作内存的变
>       量副本中
>
>   -   store （存储）：作用于主内存中的变量，它把一个从工作内存中一个变量的值传送到主内存中，
>       以便后续的write使用
>
>   -   write （写入）：作用于主内存中的变量，它把store操作从工作内存中得到的变量的值放入主内
>       存的变量中



>   **JMM对这八种指令的使用，制定了如下规则：**
>
>   -   不允许read和load、store和write操作之一单独出现。即使用了read必须load，使用了store必须
>       write
>   -   不允许线程丢弃他最近的assign操作，即工作变量的数据改变了之后，必须告知主存
>   -   不允许一个线程将没有assign的数据从工作内存同步回主内存
>   -   一个新的变量必须在主内存中诞生，不允许工作内存直接使用一个未被初始化的变量。就是怼变量
>       实施use、store操作之前，必须经过assign和load操作
>   -   一个变量同一时间只有一个线程能对其进行lock。多次lock后，必须执行相同次数的unlock才能解
>       锁
>   -   如果对一个变量进行lock操作，会清空所有工作内存中此变量的值，在执行引擎使用这个变量前，
>       必须重新load或assign操作初始化变量的值
>   -   如果一个变量没有被lock，就不能对其进行unlock操作。也不能unlock一个被其他线程锁住的变量
>   -   对一个变量进行unlock操作之前，必须把此变量同步回主内存



## 16、彻底玩转单例

>   >   **饿汉式**
>   >
>   >   ```java
>   >   // 饿汉式单例
>   >   public class Hungry {
>   >       // 可能会浪费空间
>   >       private byte[] data1 = new byte[1024*1024];
>   >       private byte[] data2 = new byte[1024*1024];
>   >       private byte[] data3 = new byte[1024*1024];
>   >       private byte[] data4 = new byte[1024*1024];
>   >       private Hungry(){
>   >       }
>   >       private final static Hungry HUNGRY = new Hungry();
>   >       public static Hungry getInstance(){
>   >           return HUNGRY;
>   >       }
>   >   }
>   >   ```
>   >
>   >   
>
>   
>
>   >   **DCL 懒汉式**
>   >
>   >   ```java
>   >   import com.sun.corba.se.impl.orbutil.CorbaResourceUtil;
>   >   import java.lang.reflect.Constructor;
>   >   import java.lang.reflect.Field;
>   >   // 懒汉式单例
>   >   // 道高一尺，魔高一丈！
>   >   public class LazyMan {
>   >       private static boolean qinjiang = false;
>   >       private LazyMan(){
>   >           synchronized (LazyMan.class){
>   >               if (qinjiang == false){
>   >                   qinjiang = true;
>   >               }else {
>   >                   throw new RuntimeException("不要试图使用反射破坏异常");
>   >               }
>   >           }
>   >       }
>   >       private volatile static LazyMan lazyMan;
>   >       // 双重检测锁模式的 懒汉式单例 DCL懒汉式
>   >       public static LazyMan getInstance(){
>   >           if (lazyMan==null){
>   >               synchronized (LazyMan.class){
>   >                   if (lazyMan==null){
>   >                       lazyMan = new LazyMan(); // 不是一个原子性操作
>   >                   }
>   >               }
>   >           }
>   >           return lazyMan;
>   >       }
>   >       // 反射！
>   >       public static void main(String[] args) throws Exception {
>   >           // LazyMan instance = LazyMan.getInstance();
>   >           Field qinjiang = LazyMan.class.getDeclaredField("qinjiang");
>   >           qinjiang.setAccessible(true);
>   >           Constructor<LazyMan> declaredConstructor =
>   >               LazyMan.class.getDeclaredConstructor(null);
>   >           declaredConstructor.setAccessible(true);
>   >           LazyMan instance = declaredConstructor.newInstance();
>   >           qinjiang.set(instance,false);
>   >           LazyMan instance2 = declaredConstructor.newInstance();
>   >           System.out.println(instance);
>   >           System.out.println(instance2);
>   >       }
>   >   }
>   >   /**
>   >   * 1. 分配内存空间
>   >   * 2、执行构造方法，初始化对象
>   >   * 3、把这个对象指向这个空间
>   >   *
>   >   * 123
>   >   * 132 A
>   >   * B // 此时lazyMan还没有完成构造
>   >   */
>   >   ```
>
>   >   **静态内**
>   >
>   >   ```java
>   >   // 静态内部类
>   >   public class Holder {
>   >       private Holder(){
>   >       }
>   >       public static Holder getInstace(){
>   >           return InnerClass.HOLDER;
>   >       }
>   >       public static class InnerClass{
>   >           private static final Holder HOLDER = new Holder();
>   >       }
>   >   }
>   >   ```
>
>   >   **枚举**
>   >
>   >   ```java
>   >   import java.lang.reflect.Constructor;
>   >   import java.lang.reflect.InvocationTargetException;
>   >   // enum 是一个什么？ 本身也是一个Class类
>   >   public enum EnumSingle {
>   >       INSTANCE;
>   >       public EnumSingle getInstance(){
>   >           return INSTANCE;
>   >       }
>   >   }
>   >   class Test{
>   >       public static void main(String[] args) throws NoSuchMethodException,
>   >       IllegalAccessException, InvocationTargetException, InstantiationException {
>   >           EnumSingle instance1 = EnumSingle.INSTANCE;
>   >           Constructor<EnumSingle> declaredConstructor =
>   >               EnumSingle.class.getDeclaredConstructor(String.class,int.class);
>   >           declaredConstructor.setAccessible(true);
>   >           EnumSingle instance2 = declaredConstructor.newInstance();
>   >           // NoSuchMethodException: com.kuang.single.EnumSingle.<init>()
>   >           System.out.println(instance1);
>   >           System.out.println(instance2);
>   >       }
>   >   }
>   >   ```
>   >
>   >   



## 17、深入理解CAS

>   **什么是CAS?**
>
>   ==CAS ： 比较当前工作内存中的值和主内存中的值，==
>
>   ==如果这个值是期望的，那么则执行操作！如果不是就一直循==
>
>   缺点：
>
>   1、 循环会耗时
>
>   2、一次性只能保证一个共享变量的原子性
>
>   3、ABA问题（狸猫换太子）
>
>   -   ```java
>       import java.util.concurrent.atomic.AtomicInteger;
>       public class CASDemo {
>           // CAS compareAndSet : 比较并交换！
>           public static void main(String[] args) {
>               AtomicInteger atomicInteger = new AtomicInteger(2020);
>               // 期望、更新
>               // public final boolean compareAndSet(int expect, int update)
>               // 如果我期望的值达到了，那么就更新，否则，就不更新, CAS 是CPU的并发原语！
>               // ============== 捣乱的线程 ==================
>               System.out.println(atomicInteger.compareAndSet(2020, 2021));
>               System.out.println(atomicInteger.get());
>               System.out.println(atomicInteger.compareAndSet(2021, 2020));
>               System.out.println(atomicInteger.get());
>               // ============== 期望的线程 ==================
>               System.out.println(atomicInteger.compareAndSet(2020, 6666));
>               System.out.println(atomicInteger.get());
>           }
>       }
>                           
>       ```
>
>       
>
>   ```java
>   import java.util.concurrent.atomic.AtomicInteger;
>   public class CASDemo {
>       // CAS compareAndSet : 比较并交换！
>       public static void main(String[] args) {
>           AtomicInteger atomicInteger = new AtomicInteger(2020);
>           // 期望、更新
>           // public final boolean compareAndSet(int expect, int update)
>           // 如果我期望的值达到了，那么就更新，否则，就不更新, CAS 是CPU的并发原语！
>           System.out.println(atomicInteger.compareAndSet(2020, 2021));
>           System.out.println(atomicInteger.get());
>           atomicInteger.getAndIncrement()
>               System.out.println(atomicInteger.compareAndSet(2020, 2021));
>           System.out.println(atomicInteger.get());
>       }
>   }
>   ```
>
>   >   **Unsafe类**
>   >
>   >   
>   >
>   >   ![image-20210714215828889](G:\各科笔记\JUC笔记\JUC.assets\image-20210714215828889.png)
>   >
>   >   ![image-20210714215758536](G:\各科笔记\JUC笔记\JUC.assets\image-20210714215758536.png)





## 18、原子引用



>   解决ABA 问题，引入原子引用！ **对应的思想：乐观**
>
>   **带版本号 的原操作**
>
>   ```java
>   import java.util.concurrent.TimeUnit;
>   import java.util.concurrent.atomic.AtomicStampedReference;
>   public class CASDemo {
>       //AtomicStampedReference 注意，如果泛型是一个包装类，注意对象的引用问题
>       // 正常在业务操作，这里面比较的都是一个个对象
>       static AtomicStampedReference<Integer> atomicStampedReference = new
>           AtomicStampedReference<>(1,1);
>       // CAS compareAndSet : 比较并交换！
>       public static void main(String[] args) {
>           new Thread(()->{
>               int stamp = atomicStampedReference.getStamp(); // 获得版本号
>               System.out.println("a1=>"+stamp);
>               try {
>                   TimeUnit.SECONDS.sleep(1);
>               } catch (InterruptedException e) {
>                   e.printStackTrace();
>               }
>               atomicStampedReference.compareAndSet(1, 2,
>                                                    atomicStampedReference.getStamp(),
>                                                    atomicStampedReference.getStamp() + 1);
>               System.out.println("a2=>"+atomicStampedReference.getStamp());
>               System.out.println(atomicStampedReference.compareAndSet(2, 1,
>                                                                       atomicStampedReference.getStamp(),
>                                                                       atomicStampedReference.getStamp() + 1));
>               System.out.println("a3=>"+atomicStampedReference.getStamp());
>           },"a").start();
>           // 乐观锁的原理相同！
>           new Thread(()->{
>               int stamp = atomicStampedReference.getStamp(); // 获得版本号
>               System.out.println("b1=>"+stamp);
>               try {
>                   TimeUnit.SECONDS.sleep(2);
>               } catch (InterruptedException e) {
>                   e.printStackTrace();
>               }
>               System.out.println(atomicStampedReference.compareAndSet(1, 6,
>                                                                       stamp, stamp + 1));
>               System.out.println("b2=>"+atomicStampedReference.getStamp());
>           },"b").start();
>       }
>   }
>   ```
>
>   ==坑==
>
>   `Integer 使用了对象缓存机制，默认范围是 -128 ~ 127 ，推荐使用静态工厂方法 valueOf 获取对象实例，而不是 new，因为 valueOf 使用缓存，而 new 一定会创建新的对象分配新的内存空`
>
>   ![image-20210714220225896](G:\各科笔记\JUC笔记\JUC.assets\image-20210714220225896.png)



## 19、各种锁的理解

### 1、公平锁、非公平锁

公平锁： 非常公平， 不能够插队，必须先来后

非公平锁：非常不公平，可以插队 （默认都是非公平）

```java
public ReentrantLock() {
    sync = new NonfairSync();
}
public ReentrantLock(boolean fair) {
    sync = fair ? new FairSync() : new NonfairSync();
}
```

### 2、可重锁（递归锁）

==拿到外面的锁后里面的锁自动获得==

>   >   synchronized
>   >
>   >   ```java
>   >   import javax.sound.midi.Soundbank;
>   >   // Synchronized
>   >   public class Demo01 {
>   >       public static void main(String[] args) {
>   >           Phone phone = new Phone();
>   >           new Thread(()->{
>   >               phone.sms();
>   >           },"A").start();
>   >           new Thread(()->{
>   >               phone.sms();
>   >           },"B").start();
>   >       }
>   >   }
>   >   class Phone{
>   >       public synchronized void sms(){
>   >           System.out.println(Thread.currentThread().getName() + "sms");
>   >           call(); // 这里也有锁
>   >       }
>   >       public synchronized void call(){
>   >           System.out.println(Thread.currentThread().getName() + "call");
>   >       }
>   >   }
>   >   ```
>   >
>   >   >   lock
>   >   >
>   >   >   ```java
>   >   >   import java.util.concurrent.locks.Lock;
>   >   >   import java.util.concurrent.locks.ReentrantLock;
>   >   >   public class Demo02 {
>   >   >       public static void main(String[] args) {
>   >   >           Phone2 phone = new Phone2();
>   >   >           new Thread(()->{
>   >   >               phone.sms();
>   >   >           },"A").start();
>   >   >           new Thread(()->{
>   >   >               phone.sms();
>   >   >           },"B").start();
>   >   >       }
>   >   >   }
>   >   >   class Phone2{
>   >   >       Lock lock = new ReentrantLock();
>   >   >       public void sms(){
>   >   >           lock.lock(); // 细节问题：lock.lock(); lock.unlock(); // lock 锁必须配对，否
>   >   >           则就会死在里面
>   >   >               lock.lock();
>   >   >           try {
>   >   >               System.out.println(Thread.currentThread().getName() + "sms");
>   >   >               call(); // 这里也有锁
>   >   >           } catch (Exception e) {
>   >   >               e.printStackTrace();
>   >   >           } finally {
>   >   >               lock.unlock();
>   >   >               lock.unlock();
>   >   >           }
>   >   >       }
>   >   >       public void call(){
>   >   >           lock.lock();
>   >   >           try {
>   >   >               System.out.println(Thread.currentThread().getName() + "call");
>   >   >           } catch (Exception e) {
>   >   >               e.printStackTrace();
>   >   >           } finally {
>   >   >               lock.unlock();
>   >   >           }
>   >   >       }
>   >   >   }
>   >   >   ```
>   >   >
>   >   >   



### 3、自旋锁

```java
import java.util.concurrent.atomic.AtomicReference;
/**
* 自旋锁
*/
public class SpinlockDemo {
    // int 0
    // Thread null
    AtomicReference<Thread> atomicReference = new AtomicReference<>();
    // 加锁
    public void myLock(){
        Thread thread = Thread.currentThread();
        System.out.println(Thread.currentThread().getName() + "==> mylock");
        // 自旋锁
        while (!atomicReference.compareAndSet(null,thread)){
        }
    }
    // 解锁
    // 加锁
    public void myUnLock(){
        Thread thread = Thread.currentThread();
        System.out.println(Thread.currentThread().getName() + "==> myUnlock");
        atomicReference.compareAndSet(thread,null);
    }
}

import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;
public class TestSpinLock {
    public static void main(String[] args) throws InterruptedException {
        // ReentrantLock reentrantLock = new ReentrantLock();
        // reentrantLock.lock();
        // reentrantLock.unlock();
        // 底层使用的自旋锁CAS
        SpinlockDemo lock = new SpinlockDemo();
        new Thread(()-> {
            lock.myLock();
            try {
                TimeUnit.SECONDS.sleep(5);
            } catch (Exception e) {
                e.printStackTrace();
            } finally {
                lock.myUnLock();
            }
        },"T1").start();
        TimeUnit.SECONDS.sleep(1);
        new Thread(()-> {
            lock.myLock();
            try {
                TimeUnit.SECONDS.sleep(1);
            } catch (Exception e) {
                e.printStackTrace();
            } finally {
                lock.myUnLock();
            }
        },"T2").start();
    }
}
```

![image-20210714220759139](G:\各科笔记\JUC笔记\JUC.assets\image-20210714220759139.png)



### 死锁

1.  使用**jps -l** 定位死锁的进程号
2.  使用==jstack 进程号== 找到死锁问题



排插问题可从查看日志

查看堆栈信息