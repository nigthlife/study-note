package Test.one;

;
import javax.sound.midi.SoundbankResource;
import java.io.*;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Type;
import java.util.Scanner;

/**
 * Description:
 * className: ${}
 * date : 2020/9/20 17:19
 *
 * @author 夜生情
 */
@Custom(className = "Test.one.Ticket",clazzName = "Test.one.MyRunnable")
public class Test {
    public static void main(String[] args) throws Exception {
        File file = new File("D:" + File.separator + "preakness.txt");
        OutputStream outputStream = new FileOutputStream(file);
        BufferedOutputStream buffout = new BufferedOutputStream(outputStream);
        Scanner in = new Scanner(System.in);

        Class TestClass = Test.class;
        Custom custom = (Custom) TestClass.getAnnotation(Custom.class);//获得了文件注解对象
        String ClassTicket = custom.className();
        String ClassMyRunnable = custom.clazzName();
        Class<?> classTicket = Class.forName(ClassTicket);
        Class<?> classMy = Class.forName(ClassMyRunnable);
        Constructor<?> constructor = classTicket.getConstructor(new Class[]{});
        Object objectCons = constructor.newInstance();

        Object objectTic = classTicket.newInstance();
        Constructor<?> MyConstructor = classMy.getConstructor(new Class[]{Ticket.class});
        Object Newobject = MyConstructor.newInstance(new Object[]{objectCons});

        new Thread((Runnable) Newobject,"窗口一").start();
        new Thread((Runnable) Newobject,"窗口二").start();
        new Thread((Runnable) Newobject,"窗口三").start();
        new Thread((Runnable) Newobject,"窗口四").start();


        Class clazz = Test.class;
        System.out.println(clazz);
        Class studentClass = Class.forName("Test.one.Student");//会有一个找不到类的异常
        Constructor<?> StudentConstructor = studentClass.getDeclaredConstructor(new Class[]{String.class, int.class, String.class});
        System.out.println(StudentConstructor);
        String str = "in.next()";
        String str2 = "in.next()";
        int number = 20;
        Object objectConstructor = StudentConstructor.newInstance(new Object[]{str, number, str2});
        Method methodStudent = studentClass.getDeclaredMethod("toString");
        System.out.println("methodStudent = " + methodStudent);
        Object object = methodStudent.invoke(objectConstructor, null);
        System.out.println("object = " + object);
        String str3 = object.toString();
        System.out.println("str = " + object);
        Method[] methods = studentClass.getDeclaredMethods();
        for (Method method : methods) {
            System.out.println("方法名 = " + method);
            Class<?>[] parameterTypes = method.getParameterTypes();
            if (parameterTypes.length == 0) {
                System.out.println("此方法为无参构造方法！");
            }
            for (Class<?> parameter : parameterTypes) {
                String paraString = parameter.getName();
                System.out.println("参数类型 = " + paraString);
            }
        }
        Field[] fields = studentClass.getDeclaredFields();
        for (Field field : fields) {
            System.out.println("变量名为" + field.getName());
            field.setAccessible(true);
            Type numbers = field.getGenericType();
            System.out.println("变量值为 = " + numbers + "类型");
        }
        ObjectOutputStream oos = new ObjectOutputStream(outputStream);
        oos.writeObject(object);//写不进去，object虽然是对象但是写不进去
        System.out.println(object);

        byte[] bytes = str3.getBytes();
        for (byte aByte : bytes) {
            buffout.write(aByte);
        }
        oos.close();
    }
}

class Ticket {
    private int sumTicket = 100;
    private volatile int count = 0;
    public Ticket(){}

    //判断是否有票
    public synchronized void IfTicket() throws NotuptedException {
        if (count < 100) {
            try {
                //System.err.println("cont = "+count+"sumTicket"+sumTicket);
                System.out.println(Thread.currentThread().getName() + "卖出第" + (++count) + "张票,剩余" + (--sumTicket) + "张票");
                Thread.sleep(10);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        } else {
            throw new NotuptedException("车票卖完了");
        }

    }

}

class MyRunnable implements Runnable {
    private Object object;
    private Ticket ticket;

    public MyRunnable(Ticket ticket) {
        this.ticket = ticket;
    }

    @Override
    public void run() {
        while (true) {
            try {
                synchronized (ticket){
                    ticket.IfTicket();
                }
            } catch (NotuptedException e) {
                System.out.println("票以卖完！");
                e.printStackTrace();
                break;
            }
        }

    }
}

class NotuptedException extends Exception {
    public NotuptedException() {
    }

    public NotuptedException(String name) {
        super(name);
    }
}


class Student {
    private String name;
    private int age;
    private String sex;

    public Student() {}

    public Student(String name, int age, String sex) {
        this.name = name;
        this.age = age;
        this.sex = sex;
    }

    public void gotoStudent() {
        System.out.println(name + "->" + age + "->" + sex);
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public int getAge() {
        return age;
    }

    public void setAge(int age) {
        this.age = age;
    }

    public String getSex() {
        return sex;
    }

    public void setSex(String sex) {
        this.sex = sex;
    }

    @Override
    public String toString() {
        return "Student{" +
                "name='" + name + '\'' +
                ", age=" + age +
                ", sex='" + sex + '\'' +
                '}';
    }
}
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@interface Custom{
    String className();
    String clazzName();
}

@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@interface stuCustom{
    String className();
}