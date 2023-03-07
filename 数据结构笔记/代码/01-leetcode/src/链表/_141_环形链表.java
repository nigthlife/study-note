package ����;

/**
 * https://leetcode-cn.com/problems/linked-list-cycle/
 * @author ҹ����
 *
 */
public class _141_�������� {
	
	/**
	 * �ж�һ���������Ƿ��л�
	 * ����������ָ��
	 * @param head
	 * @return
	 */
	public boolean hasCycle(ListNode head) {
		
		/**
    	 * ������ĵ�һ���ڵ�Ϊ��ʱ������Ҫ��ת������Ϊ��������Ϊ��
    	 * ���ڶ����ڵ�Ϊ��ʱ������Ҫ��ת������Ϊ��������ֻ��һ��Ԫ��
    	 */
		if (head == null || head.next == null)
			return false;

		ListNode slow = head;
		ListNode fast = head.next;

		while (fast != null && fast.next != null) {
  
			// ��ָ�룺һ����һ��
			slow = slow.next;      
			// ��ָ�룺һ��������
			fast = fast.next.next;
			
			// �ж���ָ���Ƿ����ָ������
			if (slow == fast)
				return true;
		}
		
		// �п�ֵ˵��û�л�
		return false;
	}
}
