package com.xf.sessions;

import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Servlet implementation class CookServlet
 */
@WebServlet("/CookServlet")
public class CookServlet extends HttpServlet {
	private static final long serialVersionUID = 1L;
       
    /**
     * @see HttpServlet#HttpServlet()
     */
    public CookServlet() {
        super();
        // TODO Auto-generated constructor stub
    }

	/**
	 * @see HttpServlet#doGet(HttpServletRequest request, HttpServletResponse response)
	 */
	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		
		/*1:http请求是无状态的
		 *2：会话技术：在多次请求中共享数据
		 *3：客户端会话技术(Cookie技术)
		 *
		 *
		 *4：服务端会话技术(Session技术)
		 *
		 * */

	
	
	}

	/**
	 * @see HttpServlet#doPost(HttpServletRequest request, HttpServletResponse response)
	 */
	protected void doPost(HttpServletRequest req, HttpServletResponse res) throws ServletException, IOException {
		
		// 1:获取用户名密码
		String name = req.getParameter("txtUserName");
		String pwd = req.getParameter("txtPassword");
		
		// 验证数据的正确性
		if("admin".equals(name) && "888888".equals(pwd))
		{
			// 获取cookie对象
			Cookie ck = new Cookie("JSESSIONID",req.getSession().getId());
			ck.setMaxAge(60 * 60 * 24);
					
			// 添加 Cookies
			Cookie ckName = new Cookie("name", name);
			Cookie ckPwd  = new Cookie("pwd",pwd);
			
			// 设置时限
			ckName.setMaxAge(60 * 60 * 24);
			ckPwd.setMaxAge(60 * 60 * 24);
			//ckPwd.setMaxAge(0);

			ckName.setPath("/"); // 使用范围
			ckPwd.setPath("/");
			res.addCookie(ckName);
			res.addCookie(ckPwd);
			
			// 重定向页面
			res.sendRedirect("/webProj1/ServletDemo2");
		}
		
		
		
	}

}
