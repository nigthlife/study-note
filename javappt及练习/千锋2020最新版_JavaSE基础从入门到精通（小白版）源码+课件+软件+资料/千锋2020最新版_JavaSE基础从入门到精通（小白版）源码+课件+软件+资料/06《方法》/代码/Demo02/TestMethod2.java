public class TestMethod2{
	
	public static void main(String[] args){
		
		//�����ڶ�ε���printSign����ʱ�����Դ�ӡ��ͬ�����ļ���
		
		System.out.println("��ǰ���¹�");
		
		printSign(5);

		System.out.println("���ǵ���˪");
		
		printSign(10);

		System.out.println("��ͷ������");
		
		printSign(15);

		System.out.println("��ͷ˼����");
		
		printSign(20);

	}

	public static void printSign(int count){
	
		for(int i = 1 ; i <= count ; i++){
			System.out.print("-");
		}
		System.out.println();
		
	}
	
}