package ����;

/**
 * https://leetcode-cn.com/problems/delete-node-in-a-linked-list/
 * @author ҹ����
 *
 */
public class _237_ɾ�������еĽڵ� {

    public void deleteNode(ListNode node) {
    	// ����ǰ�ڵ��ֵָ����һ���ڵ��ֵ
        node.val = node.next.val;
        
        // �ڽ���ǰ��һ���ڵ��ָ����һ���ڵ�
        node.next = node.next.next;

    }
}
