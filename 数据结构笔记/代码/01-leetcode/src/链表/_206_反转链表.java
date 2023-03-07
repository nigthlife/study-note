package ����;

/**
 * https://leetcode-cn.com/problems/reverse-linked-list/
 * @author ҹ����
 *
 */
public class _206_��ת���� {
	
	/**
	 * ������ʽ��ת����
	 * @param head
	 * @return
	 */
	public ListNode reverseList(ListNode head) {
			
		/**
    	 * ������ĵ�һ���ڵ�Ϊ��ʱ������Ҫ��ת������Ϊ��������Ϊ��
    	 * ���ڶ����ڵ�Ϊ��ʱ������Ҫ��ת������Ϊ��������ֻ��һ��Ԫ��
    	 */
		if (head == null || head.next == null)
			return head;

		ListNode newHead = null;

		while (head != null) {
			// ��ʱ�洢head����һ���ڵ��ֵ
			ListNode temp = head.next;
			
			// ���½ڵ��ֵ��ֵ����ǰ�ڵ�
			// ������head��next�ڵ��ֵ
			head.next = newHead;
			
			// ������head�ĵ�һ���ڵ�ֵ
			newHead = head;
			
			// ������head.next == null�ˣ��������½�head.nextָ������һ���ڵ�
			head.next = temp;
		}

		return newHead;
	}

    /**
     * �ݹ鷽ʽ��ת����
     * @param head
     * @return
     */
    public ListNode reverseList1(ListNode head) {
    	
    	/**
    	 * ������ĵ�һ���ڵ�Ϊ��ʱ������Ҫ��ת������Ϊ��������Ϊ��
    	 * ���ڶ����ڵ�Ϊ��ʱ������Ҫ��ת������Ϊ��������ֻ��һ��Ԫ��
    	 */
        if(head == null || head.next == null) return head;

        // ͨ��������һ���ڵ�����ȡ�½ڵ�
        // ÿ�εݹ鴫��Ĳ���ֵ��ǰ�ڵ�
        // newHead == �׽ڵ� ��ʱ������һ���ڵ��ֵΪnull
        // ���ǵݹ鴫��Ĳ���Ϊ��һ���ڵ㣬����Ϊ����Ϊ��ַ���ã�����ͨ����һ���ڵ��õ���һ���ڵ㣬Ȼ����и�ֵ 
        ListNode newHead = reverseList1(head.next);
        
        // ��ת����
        // head.next.next == ��һ���ڵ� == ������һ���ڵ�ֵΪ��ǰ�ڵ�
        // ��������һ����������ʱ�������׽ڵ����һ���ڵ�
        head.next.next = head;
        
        // ��ת��ͷ�����β���������踳ֵΪ��
        // head.next == ��ǰ�ڵ� == ���õ�ǰ�ڵ�ָ�� null 
        head.next = null;

        return newHead;
    }
}
