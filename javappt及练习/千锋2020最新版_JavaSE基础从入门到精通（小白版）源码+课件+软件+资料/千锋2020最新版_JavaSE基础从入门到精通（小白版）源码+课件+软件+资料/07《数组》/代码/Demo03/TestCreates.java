public class TestCreates{
	
	public static void main(String[] args){
		
		//���������ٷ���ռ�
		int[] array1;
		
		array1 = new int[4];
		
		//System.out.println( array1[0] );
		
		//����������ռ�
		int[] array2 = new int[4];
		
		
		//��������ֵ������
		int[] array3;
		array3 = new int[]{ 11 , 22 , 33};
		
		for(int i = 0 ; i < array3.length ; i++){
			System.out.println( array3[i] );
		}
		
		//��������ֵ����
		int[] array4 = { 66,77,88,99 };//��֧�ֻ�����д
		
		for(int i = 0 ; i < array4.length ; i++){
			System.out.println( array4[i] );
		}
	}
}