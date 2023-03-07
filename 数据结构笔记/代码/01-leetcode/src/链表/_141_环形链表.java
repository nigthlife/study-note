package 链表;

/**
 * https://leetcode-cn.com/problems/linked-list-cycle/
 * @author 夜生情
 *
 */
public class _141_环形链表 {
	
	/**
	 * 判断一个链表中是否有环
	 * 方法：快慢指针
	 * @param head
	 * @return
	 */
	public boolean hasCycle(ListNode head) {
		
		/**
    	 * 当传入的第一个节点为空时，不需要反转链表，因为整个链表都为空
    	 * 当第二个节点为空时，不需要反转链表，因为整个链表只有一个元素
    	 */
		if (head == null || head.next == null)
			return false;

		ListNode slow = head;
		ListNode fast = head.next;

		while (fast != null && fast.next != null) {
  
			// 慢指针：一次走一步
			slow = slow.next;      
			// 快指针：一次走俩步
			fast = fast.next.next;
			
			// 判断慢指针是否与快指针相遇
			if (slow == fast)
				return true;
		}
		
		// 有空值说明没有环
		return false;
	}
}
