package ����;

public class _876_������м��� {
	
	/**
	 * ����ָ�뷽ʽ
	 * @param head
	 * @return
	 */
    public ListNode middleNode(ListNode head) {

        ListNode left = head;
        ListNode right = head;

        while(right != null && right.next != null) {                    
            left = left.next; 
            right = right.next.next;      
        }
        return left;
    }
}
