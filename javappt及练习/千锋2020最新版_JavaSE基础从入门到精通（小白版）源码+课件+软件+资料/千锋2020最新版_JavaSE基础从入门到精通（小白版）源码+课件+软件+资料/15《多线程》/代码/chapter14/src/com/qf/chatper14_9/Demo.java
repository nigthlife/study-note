package com.qf.chatper14_9;

import java.util.PriorityQueue;

public class Demo {
	public static void main(String[] args) {
		PriorityQueue<String> q = new PriorityQueue<String>();
        //ε₯ε
        q.offer("1");
        q.offer("2");
        q.offer("5");
        q.offer("3");
        q.offer("4");

        //εΊε
        System.out.println(q.poll());  //1
        System.out.println(q.poll());  //2
        System.out.println(q.poll());  //3
        System.out.println(q.poll());  //4
        System.out.println(q.poll());  //5
	}
}
