package ����;

public class _83_ɾ�����������е��ظ�Ԫ�� {

	/**
	 * �ݹ鷽ʽ
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
	 * ����ָ�뷽ʽ
	 * @param head
	 * @return
	 */
	public ListNode deleteDuplicates(ListNode head) {
		// ÿһ��Ԫ��ֻ����һ�Σ�Ҳ����˵һ��Ԫ�����ֻ�������ظ�ֵ
		// ʹ�ÿ���ָ��������

		// ����һ������ͷ���
		ListNode dummyHead = new ListNode(-101);
		dummyHead.next = head;

		// �������ָ��
		ListNode left = dummyHead;
		ListNode right = head;

		// �ƶ���ָ�룬�����ָ���ֵ����ָ���ֵ��ȣ�ɾ������ָ����ָ��Ľ��
		// �������ָ��ָ���ֵ�ǲ�ͬ�ģ�����ָ�붼�����ƶ�
		while (left != null && right != null) {
			if (left.val == right.val) {
				// ���õ�ǰ����洢����һ���ڵ�ֵ
				left.next = right.next;
			} else {
				// right��left��һ����
				// ���൱��ʱ��left��ֵ��Ӧ�õ���right
				left = right;
			}
			// rightָ����һ���ڵ�  
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
