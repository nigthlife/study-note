
package Test.one;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Scanner;

/**
 * Description:
 * className: ${}
 * date : 2020/9/20 17:19
 *
 * @author 夜生情
 *
 */

public class Test{
    public static void main(String[] args){
        try{
            //创建一个服务器端的Socket只能创建(1024 - 65535)之间的
            ServerSocket serverSocket = new ServerSocket(6666);
            System.out.println("服务器以启动，正在等待客户端的链接。。。");

            //监听并返回客户端的链接，如果没有链接，将阻塞
            Socket socket = serverSocket.accept();
            System.out.println("客户端连击成功！"+ serverSocket.getInetAddress().getHostAddress());

            //如果链接成功创建输入输入文件
            BufferedReader br = new BufferedReader(
                    new InputStreamReader(socket.getInputStream()));

            //通过输入流读取网络数据
            String info  = br.readLine();
            System.out.println(info);//输出读取到的文件

            //获取输出流，向客户端返回消息
            PrintStream ps = new PrintStream(
                    new BufferedOutputStream(socket.getOutputStream()));


            //通过println()方法向客户端返回消息

            ps.println("echo + "+info);
            ps.flush();
            //关闭流文件
            ps.close();
            br.close();

        }catch(IOException e){
            e.printStackTrace();
        }
    }

}




package Test.one;

import java.io.*;
import java.net.Socket;

/**
 * Description:
 * className: ${}
 * date : 2020/9/21 14:39
 *
 * @author 夜生情
 */

//创建客户端
public class Test_2 {
    public static void main(String[] args) {
        try {
            //创建客户端然后指定ip地址跟端口号
            Socket socket = new Socket("localhost", 6666);

            //获取socket的输入输出流

            PrintStream ps = new PrintStream(
                    new BufferedOutputStream(socket.getOutputStream()));

            BufferedReader br = new BufferedReader(
                    new InputStreamReader(socket.getInputStream()));

            //向服务器发送的消息
            ps.println("hello, my name is dabing");
            ps.flush();

            //读取服务器端返回的数据
            String info = br.readLine();
            System.out.println(info);

            ps.close();
            br.close();

        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}


