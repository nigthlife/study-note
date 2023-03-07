
//TCPClient demo
//客户端
public static void main(String[] args){
	String sentence;
	String modifiedSentence;
	System.out.prinln("请输入一个英文字符：");
	while(true){
		BufferedReader inFromUser = new BufferedReader(
			new InputStreamReader(System.in));
		//创建客户端Socket，并指明需要连接的服务器的主机名和端口号
		Socket clientSocket = new Socket("localhost",10086);
		DataOutputStream outToServer = new BufferedReader(new InputStreamReader(clientSocket.getOutputStream));
		BufferedReader inFromServer = new BufferedReader(
			new InputStreamReader(clientSocket.getInputStream()));

		sentence = inFromUser.readLine();
		if(sentenet.equals("exit"))break;
			//向服务器发送数据
		outToServer.writeBytes(sentence+"\n");
			//接收服务器返回的数据
		modifiedSentence = inFromServer.readLine();
		System.out.prinln("from server"+modifiedSentence);
		clientSocket.close();

	}
}

//TCPServer demp
//服务器端
public static void main(String[] args){
	String clinetSentence;
	String capitalizedSentence;
	SimpleDateFormat df = new SimpleDateFormat("yyyy-MM-dd-HH:mm:ss");
	//创建服务器端的socket
	ServerSocket welcomeSocket = new ServerSocket(10086);
	while(true){
		Socket connectionSocket = welcomeSocket.accept();
		BufferedReader ifFromClient = new BufferedReader(
			new InputStreamReader(connectionSocket.getInputStream()));
		DataOutputStream outToClient = new DataOutputStram(
			connectionSocket.getOutputStream());
		//获取客户端传入的字符
		clinetSentence = inFromClient.readLine();
		if(clinetSemtence != null){
			System.out.println(df.format(new Date())+"from"+clinetSemtence);

		}
		capitalizedSentence = input.nextLine();
		outToClient.writeBytes(capitalizedSentence);
	}

}