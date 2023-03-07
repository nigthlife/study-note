package 链表;

public class _83_删除排序链表中的重复元素 {

	/**
	 * 递归方式
	 * 
	 * @param head
	 * @return
	 */
	public ListNode deleteDuplicates1(ListNode head) {
		if (head == null || head.next == null)
			return head;

		head.next = deleteDuplicates1(head.next);
		if (head.val == head.next.val)
			head = head.next;
		return head;
	}

	/**
	 * 快慢指针方式
	 * @param head
	 * @return
	 */
	public ListNode deleteDuplicates(ListNode head) {
		// 每一个元素只出现一次，也就是说一个元素最多只有两个重复值
		// 使用快慢指针来处理

		// 定义一个虚拟头结点
		ListNode dummyHead = new ListNode(-101);
		dummyHead.next = head;

		// 定义快慢指针
		ListNode left = dummyHead;
		ListNode right = head;

		// 移动右指针，如果右指针的值和左指针的值相等，删除掉右指针所指向的结点
		// 如果两个指针指向的值是不同的，两根指针都向右移动
		while (left != null && right != null) {
			if (left.val == right.val) {
				// 设置当前对象存储的下一个节点值
				left.next = right.next;
			} else {
				// right比left快一步，
				// 不相当于时，left的值就应该等于right
				left = right;
			}
			// right指向下一个节点  
			right = right.next;

		}

		return dummyHead.next;
	}
	
	public static ListNode deleteDuplicates2(ListNode head) {
//        ListNode newHead = new ListNode(-1);

        ListNode left = head;
        ListNode right = head.next;

        while(left != null && right != null) {
            if (left.val == right.val) {
                left.next = right.next;
            }else {
                left = right;
            }
            right = right.next;
        }

        return left;
    }
	
	public static void main(String[] args) {
		ListNode test = new ListNode(1);
		test.next.val = 1;
		test.next.next.val = 2;
		deleteDuplicates2(test);
	}


}
