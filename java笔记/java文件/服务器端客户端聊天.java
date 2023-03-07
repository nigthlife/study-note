
public final class MessageType{
	public static final int TYPE_LOGIN = 0x1;
	public static final int TYPE_SEND = 0x2;
}

public class Server{
	
	public staitc void main(String[] args){
		ExecutorService es = Executors.newFixedThreadPool(5);

		//保存用户
		Vector<UserThread> vector = new Vector<>();

		try{
			ServerSocket Server = new ServerSocket(8888);
			System.Out.println("服务器以启动，正等待连接...");

			while(true){
				Socket socket = Server.accept();
				UserThread user = new UserThread(socket,vector);
				es.

			} 
		}

	}
}

class UserThread implements Runnable{
	private String name;
	private Socket socket;
	private Vector<UserThread> vector;
	private ObjectInputStream ois;
	private ObjectOutputStream oos;
	public UserThread(Socket socket,Vector<UserThread> vector){
		this.socket = socket;
		this.vector = vector;
		vector.add(this);
	}

	@Override
	public void run(){

		try{
			System.out.println("客户端"+socket.getInetAddress().getHostAddress());
			ois = new ObjectInputStream(socket.getInputStream());
			oos = new ObjectOutputStream(socket.getOutputStream());

			while(true){
				information inf = (information)ois.readObject();
				int Type = inf.getTYPE();

				switch(Type){
					case informationType.TYPE_SEND:
						name = inf.getFrom();
						inf.setInfo("欢迎你");
						oos.writeObject(inf);
						break;
					case informationType.TYPE_LOGIN:
						String to = inf.getTo();
						UserThread ut;
						int size = vector.size();
						for(int i = 0; i < size; i++){
							ut = vector.get(i);
							if(to.equals(ut.name) && ut != this){
								ut.oos.writeObject(inf);
								break;
							}
						}
						break;
				}
			}
		}catch(IOException e){
			e.printStrackTrace();
		}
	}
}

public class Cilent{
	public static void main(String[] args) {
		ExecutorService ec = Executors.newSingleThreadExecutor();
		Scanner input = new Scanner(Sytem.in);

		try{
			Socket Socket = new Socket("localhost",8888);
			System.out.println("服务连接成功！");
			ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());
			ObjectInputStream ois = new ObjectOutputStream(socket.getInputStream());
			//向服务器发送登陆信息
			Sytem.out.println("请输入名称：");
			String name = input.next();
			information infor = new information(name,null,informationType.TYPE_SEND,null);
			oos.writeObject(infor);
			information in = (information)oos.readObject();	

			 ec.execute(new readInfoThread(ois));

			 while(true){
			 	in = new information();
			 	Sytem.out.println("To:");
			 	in.setTo(input.next());
			 	in.setFrom(name);
			 	in.setTYPE(informationType.TYPE_SEND);
			 	System.out.println("Info");
			 	in.setInfo(input.next());
			 	oos.writeObject(in);
			 }
		}catch(IOException | ClassNotFoundException e){
			e.printStackTrace();
		}	
	}
}

class ReadInfoThread implements Runnable{
    private ObjectInputStream ois;
    private boolean flag = true;

    public ReadInfoThread(ObjectInputStream ois) {
        this.ois = ois;
    }

    @Override
    public void run() {
        try {
        while (flag){
                information im = (information) ois.readObject();
                System.out.println("["+im.getFrom()+"]"+"对我说"+im.getInfo());
            }
            if(ois != null){
                ois.close();
            }
        }catch (IOException e) {
            e.printStackTrace();
        }catch (ClassNotFoundException e) {
            e.printStackTrace();
        }
    }
}