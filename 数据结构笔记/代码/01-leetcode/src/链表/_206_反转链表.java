package 链表;

/**
 * https://leetcode-cn.com/problems/reverse-linked-list/
 * @author 夜生情
 *
 */
public class _206_反转链表 {
	
	/**
	 * 遍历方式反转链表
	 * @param head
	 * @return
	 */
	public ListNode reverseList(ListNode head) {
			
		/**
    	 * 当传入的第一个节点为空时，不需要反转链表，因为整个链表都为空
    	 * 当第二个节点为空时，不需要反转链表，因为整个链表只有一个元素
    	 */
		if (head == null || head.next == null)
			return head;

		ListNode newHead = null;

		while (head != null) {
			// 临时存储head的下一个节点的值
			ListNode temp = head.next;
			
			// 将新节点的值赋值给当前节点
			// 设置新head的next节点的值
			head.next = newHead;
			
			// 设置新head的第一个节点值
			newHead = head;
			
			// 由于让head.next == null了，所以重新将head.next指向他下一个节点
			head.next = temp;
		}

		return newHead;
	}

    /**
     * 递归方式反转链表
     * @param head
     * @return
     */
    public ListNode reverseList1(ListNode head) {
    	
    	/**
    	 * 当传入的第一个节点为空时，不需要反转链表，因为整个链表都为空
    	 * 当第二个节点为空时，不需要反转链表，因为整个链表只有一个元素
    	 */
        if(head == null || head.next == null) return head;

        // 通过传入下一个节点来获取新节点
        // 每次递归传入的参数值当前节点
        // newHead == 首节点 此时他的下一个节点的值为null
        // 但是递归传入的参数为上一个节点，又因为链表为地址引用，可以通过上一个节点拿到下一个节点，然后进行赋值 
        ListNode newHead = reverseList1(head.next);
        
        // 反转链表
        // head.next.next == 下一个节点 == 设置下一个节点值为当前节点
        // 当结束第一个方法调用时，设置首节点的下一个节点
        head.next.next = head;
        
        // 反转后，头部变成尾部，所以需赋值为空
        // head.next == 当前节点 == 设置当前节点指向 null 
        head.next = null;

        return newHead;
    }
}
