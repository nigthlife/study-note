package com.qf.chap16_4;

public class UserServer {
	public static void main(String[] args) {
		new RegistThread().start();
		new LoginThread().start();
	}
}
