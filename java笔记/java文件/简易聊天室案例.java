
//聊天室程序
public class CharRoom{
	public static void main(String[] args){
		System.out.println("欢迎您进入聊天室！");
		Scanner input = new Scanner(System.in);
		System.out.print("请输入本程序发送端端口号：");
		int sendPort = input.nextInt();
		System.out.print("请输入本程序接收端端口号：");
		int receivePort = input.nextInt();
		System.out.println("聊天室系统启动！！");
		new Thread(new SendTask(sendPort),"发送端任务").start();//发送操作
		new Thread(new ReceiveTask(receivePort),"接受端任务").start();//接受操作
	}
}

/**
 * 发送数据端任务
 */
class SendTask implements Runnable{
	private int sendPort;  //发送数据的端口号
	public SendTask(int sendPort){
		this.sendPort = sendPort;
	}

	@Override
	public void run(){
		try{
			//1.创建DatagramSocket对象
			DatagramSocket ds = new DatagramSocket();
			//2.输入要发送的数据
			Scanner input = new Scanner(System.in);
			while(true){
				String data = input.next();
				//3.封装数据到DatagramPacket 对象中
				byte[] bytes = data.getBytes();
				DatagramPacket dp = new DatagramPacket(bytes,
					bytes.length,InetAddress.getByName(),sendPort);
				//发送数据
				ds.send(dp);
			}catch(Exception e){
				e.printStackTrace();
			}
		}
	}
}

class ReceiveTask implements Runnable{
	private int receivePort;//接受数据的端口号
	public ReceiveTask(int receivePort){
		this.receivePort = receivePort;
	}

	@Override
	public void run(){
		try{
			DatagramSocket ds = new DatagramSocket(receivePort);
			byte[] bytes = new byte[1024];
			DatagramPacket dp = new DatagramPacket(bytes,bytes.length);
			while(true){
				ds.receive(dp);
				String str = new String(dp.getData(),0,dp.getLength());
				System.out.println("收到"+dp.getAddress().getHostAddress()
					+"--发送的数据--"+str);
			}catch(Exception e){
				e.printStackTrace();
			}
		}
	}
}