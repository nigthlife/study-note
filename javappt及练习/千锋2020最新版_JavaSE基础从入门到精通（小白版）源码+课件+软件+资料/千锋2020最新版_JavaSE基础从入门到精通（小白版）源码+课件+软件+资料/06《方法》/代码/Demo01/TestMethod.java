public class TestMethod{
	
	public static void main(String[] args){
		
		System.out.println("��ǰ���¹�");
		
		printSign();//�Է����ĵ���

		System.out.println("���ǵ���˪");
		
		printSign();

		System.out.println("��ͷ������");
		
		printSign();

		System.out.println("��ͷ˼����");
		
		printSign();

	}
	
	//�Զ��巽������һ��������10�����ţ�����ָ�����
	public static void printSign(){

		for(int i = 1 ; i <= 10 ; i++){
			System.out.print("-");
		}
		System.out.println();
		
	}
	
	
}