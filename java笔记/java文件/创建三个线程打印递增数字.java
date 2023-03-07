package Test;

/**
 * 启动3个线程打印递增的数字, 
 * 线程1先打印1,2,3,4,5, 然后是线程2打印6,7,8,9,10, 然后是线程3打印11,12,13,14,15.  
 * 接着再由线程1打印16,17,18,19,20….以此类推 
 */
class Java{
    public static void main(String[] args){
        Object object = new Object();
        new Thread(new PrintRunnable(object,1)).start();
        new Thread(new PrintRunnable(object,2)).start();
        new Thread(new PrintRunnable(object,3)).start();
    }
}


class PrintRunnable implements Runnable{
    //volatile关键字就是提示VM：对于这个成员变量不能保存它的私有拷贝，而应直接与共享成员变量交互
    private static volatile int printNum = 0;
    private Object object;
    private int threadId;

    public PrintRunnable(Object object,int threadId){
        this.object = object;
        this.threadId = threadId;
    }

    @Override
    public void run(){

        while(printNum < 75){
            synchronized(object){
                if(printNum /5 %3+1 == threadId){
                	
                    for(int i = 0; i < 5; i++){
                        System.out.println(Thread.currentThread().getName()+"线程"+threadId+":"+(++printNum));
                    }
                    object.notifyAll();
                }else{
                    try{
                        object.wait();
                    }catch(InterruptedException e){
                        e.printStackTrace();
                    }
                }
            }
        }
    }

}