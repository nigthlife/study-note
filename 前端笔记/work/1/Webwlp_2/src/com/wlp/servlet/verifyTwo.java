package com.wlp.servlet;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Servlet implementation class verifyTwo
 */
@WebServlet("/verifyTwo")
public class verifyTwo extends HttpServlet {
    private static final long serialVersionUID = 1L;

    /**
     * @see HttpServlet#HttpServlet()
     */
    public verifyTwo() {
	super();
	// TODO Auto-generated constructor stub
    }

    /**
     * @see HttpServlet#doGet(HttpServletRequest request, HttpServletResponse
     *      response)
     */
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
	    throws ServletException, IOException {

	this.doPost(request, response);// 调用doPost方法
    }

    /**
     * @see HttpServlet#doPost(HttpServletRequest request, HttpServletResponse
     *      response)
     */
    protected void doPost(HttpServletRequest req, HttpServletResponse res) throws ServletException, IOException {

	// 设置字符集
	res.setContentType("text/html;charset=gbk");
	res.setContentType("text/html");

	// 根Referer判断是否从登入之后页面退出的，如是清空cookie的值，并设置生命周期为0
	if ("http://localhost:8080/Webwlp_2/varify".equals(req.getHeader("referer"))) {

	    // 获取cookie的值
	    Cookie[] cookies = req.getCookies();

	    // 判断cookies的值不为空
	    if (cookies != null && cookies.length != 0) {

		// 将cookie的值设置为空
		for (int i = 0; i < cookies.length; i++) {

		    if (cookies[i].getName().equals("name")) {

			cookies[i] = new Cookie("name", null);// 删除cookie

			cookies[i].setMaxAge(0); // 设置生命周期为0

			res.addCookie(cookies[i]); // 重新添加cookie

		    } else if (cookies[i].getName().equals("password")) {

			cookies[i] = new Cookie("password", null);// 删除cookie

			cookies[i].setMaxAge(0); // 设置生命周期为0

			res.addCookie(cookies[i]); // 重新添加cookie
		    }
		}
	    }

	}

	// 获取登录错误页面的服务器真实路径
	String path = req.getSession().getServletContext().getRealPath("MyProjectLogin.html");

	// 创建一个文本流
	FileInputStream fs = new FileInputStream(path);

	// 获取HTML字符流
	BufferedReader br = new BufferedReader(new InputStreamReader(fs));

	// 存储html字符串
	StringBuilder sb = new StringBuilder();

	// 临时变量
	String htmlText = null;

	// 获得HTML文本字符串内容
	while ((htmlText = br.readLine()) != null) {

	    sb.append(htmlText);

	}

	// 最终HTML文件内容
	htmlText = sb.toString();

	// 响应页面
	res.getWriter().append(htmlText);

	// 读取cookie
	Cookie[] cs = req.getCookies();

	// 判断是不是有效的cookie
	if (cs != null && cs.length != 0) {

	    String cookieName = null;
	    String cookiePwd = null;

	    for (Cookie c : cs) {

		if (c.getName().equals("name")) {

		    // 得到用户名
		    cookieName = c.getValue();

		}
		if (c.getName().equals("pass")) {

		    // 得到密码
		    cookiePwd = c.getValue();
		}
	    }

	    // 判断用户名和密码都不能为空
	    if (cookieName != null && cookiePwd != null) {

		// 把姓名和密码发到LoginServlet2 进行验证,如果验证成功就跳转到登陆后的页面,否则跳回来
		res.sendRedirect("transpondLogin?name=" + cookieName + "&password=" + cookiePwd);

	    }
	}

    }

}
