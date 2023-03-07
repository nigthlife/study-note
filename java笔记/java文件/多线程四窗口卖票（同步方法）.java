package Test.one;

/**
 * Description:
 * className: ${}
 * date : 2020/9/20 17:19
 *
 * @author 夜生情
 */


public class Test{
    public static void main(String[] args){
        Ticket ticket = new Ticket();
        Thread t1 = new Thread(new initializeTicket(ticket),"初始化线程");
        t1.start();
        try{
            t1.join();
        }catch(InterruptedException e){
            e.printStackTrace();
        }
        new Thread(new sellTicket(ticket),"卖票窗口1").start();
        new Thread(new sellTicket(ticket),"卖票窗口2").start();
        new Thread(new sellTicket(ticket),"卖票窗口3").start();
        new Thread(new sellTicket(ticket),"卖票窗口4").start();
    }
}



class Ticket{
    private String[] ticket = new String[100];//定义100张车票
    private int sumTicket = ticket.length-1;

    public void setTicket(){
        int index = ticket.length;
        for(int i = 0; i < index; i++){
            ticket[i] = "第"+(i+1)+"号车票";
        }
    }

    public synchronized String IfThreadTicket() throws NotuptedException{
        //判断是否卖到最后一张票
        if(sumTicket >= 0){
            String s = ticket[sumTicket];
            try{
                Thread.sleep(100);
            }catch(InterruptedException e){
                e.printStackTrace();
            }
            ticket[sumTicket] = null;
            sumTicket--;
            return s;
        }else{
            throw new NotuptedException("车票卖完了");
        }
    }
}

class sellTicket implements Runnable{
    private Ticket ticket;
    public sellTicket(){}
    public sellTicket(Ticket ticket){
        this.ticket = ticket;
    }

    public void run(){
        while (true){
            try{
                String str = ticket.IfThreadTicket();
                System.out.println(Thread.currentThread().getName()+"卖票成功！===========>"+str);
            }catch(NotuptedException e){
                System.out.println(Thread.currentThread().getName()+"车票以卖完");
                e.printStackTrace();
                break;
            }
        }
    }
}

class initializeTicket implements Runnable{
    private Ticket ticket;
    public initializeTicket(){}
    public initializeTicket(Ticket ticket){
        this.ticket = ticket;
    }

    public void run(){
        ticket.setTicket();
    }
}

class NotuptedException extends Exception{
    public NotuptedException(){}
    public NotuptedException(String name){
        super(name);
    }
}