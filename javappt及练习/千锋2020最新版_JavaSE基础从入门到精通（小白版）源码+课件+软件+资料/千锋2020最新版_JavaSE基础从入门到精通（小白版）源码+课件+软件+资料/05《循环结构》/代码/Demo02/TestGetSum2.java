public class TestGetSum2{
	
	public static void main(String[] args){
		
		//��1~100֮������ż���ĺ�
		
		
		//����һ����ȡ���е�ż����������
		
		
		//�����������ɻ�ȡ1~100֮���ÿһ�����֣�����ż�����жϣ���������֮��������
		
		int i = 1;
		
		int sum = 0;
		
		while( i <= 100 ){
			
			if( i % 2 != 0 ){//�ж�ż��
				//���
				sum = sum + i;
			}

			i++;
		}
		
		System.out.println("ż���ĺͣ�" + sum);
		
		
	}
}