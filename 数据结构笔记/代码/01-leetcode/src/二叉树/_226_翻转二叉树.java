package ������;

import java.util.LinkedList;
import java.util.Queue;

/**
 * ��ת������
 * https://leetcode-cn.com/problems/invert-binary-tree/
 * @author ҹ����
 *
 */
public class _226_��ת������ {
	
	/**
	 * �������
	 * @param root
	 * @return
	 */
	public TreeNode invertTree(TreeNode root) {

    	if( root == null)  return root;
    
    	Queue<TreeNode> queue = new LinkedList<>();
        queue.offer(root);

        while(!queue.isEmpty()) {
            TreeNode tree = queue.poll();

            TreeNode temp = tree.left;
    	    tree.left = tree.right;
    	    tree.right = temp;

            if(tree.left != null) queue.offer(tree.left);
			if(tree.right != null) queue.offer(tree.right);
        }


    	return root;
    }
	
	/**��
	 * �������
	 * @param root
	 * @return
	 */
    public TreeNode invertTree3(TreeNode root) {

    	if( root == null)  return root;
    
    	
    	invertTree3(root.left);
        TreeNode tree = root.left;
    	root.left = root.right;
    	root.right = tree;
    	
    	// ���������Ѿ������ҽڵ�����˽���������������ڵ�����ҽڵ�
    	invertTree3(root.left);


    	return root;
    }
	
	/**
	 * �������
	 * @param root
	 * @return
	 */
    public TreeNode invertTree2(TreeNode root) {

    	if( root == null)  return root;
    
    	
    	invertTree2(root.left);
    	invertTree2(root.right);
        
    	TreeNode tree = root.left;
    	root.left = root.right;
    	root.right = tree;
    	return root;
    }

	/**
	 * ǰ�����
	 * @param root
	 * @return
	 */
    public TreeNode invertTree1(TreeNode root) {

    	if( root == null)  return root;
    	
    	TreeNode tree = root.left;
    	root.left = root.right;
    	root.right = tree;
    	
    	invertTree1(root.left);
    	invertTree1(root.right);
    	
    	return root;
    }
}
