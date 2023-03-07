
public class Java_1 {
    public static void main(String[] args) {
        isTicket isticket = new isTicket();
        new Thread(new MyRunable(isticket, 22), "售票点2").start();
        new Thread(new MyRunable(isticket, 19), "售票点4").start();
        new Thread(new MyRunable(isticket, 21), "售票点5").start();
        new Thread(new MyRunable(isticket, 33), "售票点3").start();
        new Thread(new MyRunable(isticket, 11), "售票点1").start();


    }
}

//判断购买的票数是否足够
class isTicket {
    private int allTicket = 100;//总票数

    public isTicket() {
    }

    public boolean ifTicket(int ticketBuy) {
        if (ticketBuy > allTicket) {
            return false;
        } else {
            allTicket -= ticketBuy;
            return true;
        }
    }

    public int getallTicket() {
        return allTicket;
    }
}

class MyRunable implements Runnable {
    isTicket ticket;//火车窗口
    private int ticketBuy;//想一次性购买的票数

    public MyRunable(isTicket ticket, int ticketBuy) {
        this.ticketBuy = ticketBuy;
        this.ticket = ticket;
    }

    @Override
    public void run() {

        try {

            Thread.sleep(100);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        synchronized (ticket) {
            boolean flag = ticket.ifTicket(ticketBuy);
            if (flag) {
                System.out.println(Thread.currentThread().getName() + "想购买" + ticketBuy + "张票-----------购票成功，剩余" + ticket.getallTicket() + "张");
            } else {
                System.out.println(Thread.currentThread().getName() + "想购买" + ticketBuy + "张票------------失败!票仅剩余" + ticket.getallTicket() + "张");
            }

        }

    }
}
