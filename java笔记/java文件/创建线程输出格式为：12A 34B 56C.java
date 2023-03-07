
/**
 * 创建两个线程，其中一个输出1-52，另一个输出A-Z.输出格式要求：12A 34B 56C
 */

class JAVA_1 {
    public static void main(String[] args) {
        Object object = new Object();
        new Thread(new Number(object)).start();
        new Thread(new Charactor(object)).start();
    }

}

class Number implements Runnable {
    private Object object;

    public Number(Object object) {
        this.object = object;
    }

    @Override
    public void run() {
        synchronized (object) {
            for (int i = 1; i <= 52; i++) {
                if (i > 1 && i % 2 == 1) {
                    System.out.print(" ");
                }
                System.out.print(i);
                if (i % 2 == 0) {
                    object.notifyAll();

                    try {
                        object.wait();//使当前线程等待，直到另一个线程调用nofigy()或者notfiyAll
                    } catch (InterruptedException e) {
                        e.printStackTrace();
                    }
                }
            }
        }
    }
}

class Charactor implements Runnable {
    private Object object;

    public Charactor(Object object) {
        this.object = object;
    }

    @Override
    public void run() {
        synchronized (object) {
            for (char i = 'A'; i <= 'Z'; i++) {
                System.out.print(i + "\n");
                object.notifyAll();
                if (i < 'Z') {
                    try {
                        object.wait();
                    } catch (InterruptedException e) {
                        e.printStackTrace();
                    }

                }
            }
        }
    }
}