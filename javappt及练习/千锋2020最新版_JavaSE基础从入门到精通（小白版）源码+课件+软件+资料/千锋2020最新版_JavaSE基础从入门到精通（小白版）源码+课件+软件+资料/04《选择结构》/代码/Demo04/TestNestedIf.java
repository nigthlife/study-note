public class TestNestedIf{
	
	public static void main(String[] args){
		
		/*
			�˶����������
			��ʱ10��֮�ڵ��˽����ܾ�����������̭
		*/
		
		int timer = 9;
		
		char sex = '��';
		
		if(timer <= 10){//�������
			
			//�����ܾ���
			if(sex == '��'){//�ڲ�����
				System.out.println("���������");
			}else{
				System.out.println("Ů�������");
			}
			
		}else{
			System.out.println("��̭");
		}
		
	}
}