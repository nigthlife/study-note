import java.util.Arrays;

public class TestSort{
	
	public static void main(String[] args){
		
		int[] nums = new int[]{4,3,5,2,1};
		
		//����JDK�ṩ�����鹤�ߣ���������
		Arrays.sort(nums);
		
		//��һ�α���������
		for(int i = 0 ; i < nums.length ; i++){
			System.out.println(nums[i]);
		}
		
		
		//������Ҫ�ֹ��ķ�ʽ���Ԫ�صĵ���  5 2 3 4 1
		
		for(int i = 0 ; i < nums.length / 2 ; i++){// i = 0
		
			int temp = nums[i];// int temp = 1;

			nums[i] = nums[ nums.length - 1 - i];

			nums[ nums.length - 1 - i] = temp;
			
		}
		
		//�ڶ��α���������
		for(int i = 0 ; i < nums.length ; i++){
			System.out.println(nums[i]);
		}
		
	

		//��ֵ������������������
		/*
		int a = 10;
		int b = 20;
		int c = a;//��a�е�ֵ������c��
		a = b;//��b�е�ֵ������a��
		b = c;//��c�е�ֵ������b��
		*/
	}
}