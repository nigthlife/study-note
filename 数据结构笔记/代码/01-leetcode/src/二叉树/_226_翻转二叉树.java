package 二叉树;

import java.util.LinkedList;
import java.util.Queue;

/**
 * 翻转二叉树
 * https://leetcode-cn.com/problems/invert-binary-tree/
 * @author 夜生情
 *
 */
public class _226_翻转二叉树 {
	
	/**
	 * 层序遍历
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
	
	/**】
	 * 中序遍历
	 * @param root
	 * @return
	 */
    public TreeNode invertTree3(TreeNode root) {

    	if( root == null)  return root;
    
    	
    	invertTree3(root.left);
        TreeNode tree = root.left;
    	root.left = root.right;
    	root.right = tree;
    	
    	// 由于上面已经将左右节点进行了交换，所以现在左节点的是右节点
    	invertTree3(root.left);


    	return root;
    }
	
	/**
	 * 后序遍历
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
	 * 前序遍历
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
