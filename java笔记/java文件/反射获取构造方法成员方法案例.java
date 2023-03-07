
public class Test{
    public static void main(String[] args) throws Exception {
        File file = new File("D:"+File.separator+"preakness");
        OutputStream inputStream = new FileOutputStream(file);
        //缓冲输出流
        BufferedOutputStream buffout = new BufferedOutputStream(inputStream);
        Scanner in = new Scanner(System.in);
        Class clazz = Test.class;//获取本类的字节码文件
        System.out.println(clazz);
        //使用反射获取另一个类的字节码文件
        Class studentClass = Class.forName("Test.one.Student");//会有一个找不到类的异常
        //获取其中的构造方法
        Constructor StudentConstructor = studentClass.getDeclaredConstructor(new Class[]{String.class,int.class,String.class});
        System.out.println(StudentConstructor);
        String str = "in.next()";
        String str2 = "in.next()";
        int number = 20;
        Object objectConstructor = StudentConstructor.newInstance(new Object[]{str,number,str2});
        Method methodStudent = studentClass.getDeclaredMethod("toString");
        System.out.println("methodStudent = "+methodStudent);
        Object object = methodStudent.invoke(objectConstructor,null);
        System.out.println(object);
        String str3 = object.toString();
        Method[] methods = studentClass.getDeclaredMethods();
        for(Method method : methods){
            System.out.println("method = "+method);
        }

        byte[] bytes = str3.getBytes();
        int len = -1;
        for (int i = 0; i < bytes.length; i++) {
            buffout.write(bytes[i]);
        }
        buffout.close();
    }
}

class Student{
    private String name;
    private int age;
    private String sex;
    public Student(){}
    public Student(String name,int age,String sex){
        this.name = name;
        this.age = age;
        this.sex = sex;
    }
    public void gotoStudent(){
        System.out.println(name+"->"+age+"->"+sex);
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