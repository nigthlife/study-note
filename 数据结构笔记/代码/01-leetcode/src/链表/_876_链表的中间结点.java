package 链表;

public class _876_链表的中间结点 {
	
	/**
	 * 快慢指针方式
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
