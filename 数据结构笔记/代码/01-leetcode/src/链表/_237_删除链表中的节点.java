package 链表;

/**
 * https://leetcode-cn.com/problems/delete-node-in-a-linked-list/
 * @author 夜生情
 *
 */
public class _237_删除链表中的节点 {

    public void deleteNode(ListNode node) {
    	// 将当前节点的值指向下一个节点的值
        node.val = node.next.val;
        
        // 在将当前下一个节点的指向下一个节点
        node.next = node.next.next;

    }
}
