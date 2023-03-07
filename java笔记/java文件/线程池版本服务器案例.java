package Test.one;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Scanner;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Description:
 * className: ${}
 * date : 2020/9/20 17:19
 *
 * @author 夜生情
 * 处理多个客户端
 * 主线程用于监听客户端的链接，每次有链接成功，开启一个线程
 * 来处理该客户端的消息
 */
//服务器端
public class Test {

    public static void main(String[] args) {
        //创建一个线程池
        ExecutorService es = Executors.newFixedThreadPool(3);
        try {
            //创建一个服务器端         ServerSocket
            ServerSocket server = new ServerSocket(6666);
            System.out.println("服务器以启动，正在等待连接。。。");

            while (true) {
                Socket s = server.accept();
                System.out.println(s.getInetAddress().getHostAddress());
                es.execute(new UserThread(s));
            }

        } catch (IOException e) {
            e.printStackTrace();
        }

    }
}

class UserThread implements Runnable {
    private static Socket s;

    public UserThread(Socket s) {
        this.s = s;
    }

    @Override
    public void run() {

        try {
            BufferedReader br = new BufferedReader(
                    new InputStreamReader(s.getInputStream()));
            PrintStream ps = new PrintStream(
                    new BufferedOutputStream(s.getOutputStream()));

            //读取网络中的文件
            String info = br.readLine();
            System.out.println("网络中的文件："+info);

            //返回给客户端的消息
            ps.println("服务器：" + info);
            ps.flush();

            ps.close();
            br.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}





package Test.one;

import java.io.*;
import java.net.Socket;
import java.util.Scanner;

/**
 * Description:
 * className: ${}
 * date : 2020/9/22 9:42
 *
 * @author 夜生情
 */
public class Test_3 {
    public static void main(String[] args) {
        Scanner input = new Scanner(System.in);
        try {
            //创建客户端然后指定ip地址跟端口号
            Socket socket = new Socket("localhost", 6666);

            //获取socket的输入输出流

            PrintStream ps = new PrintStream(
                    new BufferedOutputStream(socket.getOutputStream()));

            BufferedReader br = new BufferedReader(
                    new InputStreamReader(socket.getInputStream()));

            System.out.println("请输入：");
            String info = input.nextLine();
            //向服务器发送的消息

            ps.println(info);
            ps.flush();

            //读取服务器端返回的数据
            info = br.readLine();
            System.out.println("服务器端返回的消息："+info);

            ps.close();
            br.close();

        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
