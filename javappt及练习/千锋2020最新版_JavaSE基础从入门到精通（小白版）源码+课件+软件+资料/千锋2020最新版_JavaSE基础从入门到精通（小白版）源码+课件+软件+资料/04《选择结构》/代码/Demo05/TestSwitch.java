public class TestSwitch{
	
	public static void main(String[] args){
		
		/*
			ÿ��ʳ��
			
			����һ�����
			���ڶ�������
			������������
			�����ģ����
			�����壺����
			������������
			�����գ��ղ�
			
		*/
		
		int weekDay = 8;
		
		switch( weekDay ){ //����weekDay��ֵ���ҵ�ƥ���case����ִ���߼�����
			default:
				System.out.println("������1~7֮�������!");
				break;
			case 1:
				System.out.println("���");
				break;
			case 3:
				System.out.println("����");
				break;
			case 4:
				System.out.println("���");
				break;
			case 2:
			case 5:
			case 6:
				System.out.println("����");
				break;
			case 7:
				System.out.println("�ղ�");
				break;
		}
		
		System.out.println("�������...");
		
	}
}