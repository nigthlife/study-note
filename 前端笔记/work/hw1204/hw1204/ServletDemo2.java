package com.xf.controller;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Servlet implementation class ServletDemo2
 */
@WebServlet("/ServletDemo2")
public class ServletDemo2 extends HttpServlet {
	private static final long serialVersionUID = 1L;
       
    /**
     * @see HttpServlet#HttpServlet()
     */
    public ServletDemo2() {
        super();
        // TODO Auto-generated constructor stub
    }

	/**
	 * @see HttpServlet#doGet(HttpServletRequest request, HttpServletResponse response)
	 */
	protected void doGet(HttpServletRequest req, HttpServletResponse res) throws ServletException, IOException {
		
	    res.setContentType("text/html;charset=utf-8");
	    String name = null;
	    String pwd = null;

		// 查询用户名密码(Admin  888888)
		Cookie[] cks = req.getCookies();
		
		if(cks != null && cks.length > 0)
		{
			name = cks[1].getValue();
			pwd = cks[1].getValue();
		}
		
		// 获取服务器的真实路径(服务器在当前计算机的盘符路径)
		String path = req.getSession().getServletContext().getRealPath("MyProject.html");
		FileInputStream fs = new FileInputStream(path);
		BufferedReader br = new BufferedReader(new InputStreamReader(fs,"UTF-8"));
		
		StringBuilder sb = new StringBuilder();
		
		String htmlText = null;
		
		while((htmlText = br.readLine()) != null)
		{
			sb.append(htmlText);
		}
		
		htmlText = sb.toString();
		if(name != null)
		{
		    htmlText = htmlText.replace("{$userName}", name);
		}
        
        // 返回HTML页面内容
		res.getWriter().append(htmlText);

	}

	/**
	 * @see HttpServlet#doPost(HttpServletRequest request, HttpServletResponse response)
	 */
	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		// TODO Auto-generated method stub
		doGet(request, response);
	}

}
