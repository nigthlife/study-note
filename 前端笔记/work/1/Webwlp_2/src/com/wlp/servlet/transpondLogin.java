package com.wlp.servlet;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import com.wlp.servers.server;

/**
 * Servlet implementation class transpondLogin
 */
@WebServlet("/transpondLogin")
public class transpondLogin extends HttpServlet {
    private static final long serialVersionUID = 1L;

    /**
     * @see HttpServlet#HttpServlet()
     */
    public transpondLogin() {
	super();
	// TODO Auto-generated constructor stub
    }

    /**
     * @see HttpServlet#doGet(HttpServletRequest request, HttpServletResponse
     *      response)
     */
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
	    throws ServletException, IOException {
	// TODO Auto-generated method stub

	response.getWriter().append("Served at: ").append(request.getContextPath());
    }

    /**
     * @see HttpServlet#doPost(HttpServletRequest request, HttpServletResponse
     *      response)
     */
    protected void doPost(HttpServletRequest req, HttpServletResponse res) throws ServletException, IOException {
	// TODO Auto-generated method stub

	// 创建服务类对象
	server ser = new server();

	// 获取用户名
	String usName = req.getParameter("user");

	// 获取密码
	String usPaw = req.getParameter("pass");


	// 根据用户名和密码查询当前用户id
	int UserId = ser.selectUserId(usName, usPaw);

	// 当用户id不为0时表示当前用户存在
	if (UserId != 0) {

	    // 获取是否记住密码
	    String save = req.getParameter("save");

	    // 判断是否记住密码
	    if (save != null) {

		// 添加cookie记住账号密码
		Cookie coName = new Cookie("name", usName);
		Cookie coPaw = new Cookie("pass", usPaw);
		Cookie coId = new Cookie("usid",UserId+"");

		// 设置声明周期为一个小时
		coName.setMaxAge(60 * 60);
		coPaw.setMaxAge(60 * 60);
		coId.setMaxAge(60 * 60);

		// 添加cookie
		res.addCookie(coName);
		res.addCookie(coPaw);
		res.addCookie(coId);

	    }

	    // 向Session中写数据
	    HttpSession session = req.getSession();

	    session.setAttribute("name", usName);

	    session.setAttribute("pass", usPaw);
	    
	    session.setAttribute("usid", UserId+"");

	    // 登录后页面
//	    res.sendRedirect("http://127.0.0.1:8080/Webwlp_2/verify");
	    req.getRequestDispatcher("verify").forward(req, res);

	} else {

	    // 当用户不存在时设置转发
//	   res.sendRedirect("http://127.0.0.1:8080/Webwlp_2/verifyTwo");
	    req.getRequestDispatcher("verifyTwo").forward(req, res);

	}
    }

}
