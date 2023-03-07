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

	// �������������
	server ser = new server();

	// ��ȡ�û���
	String usName = req.getParameter("user");

	// ��ȡ����
	String usPaw = req.getParameter("pass");


	// �����û����������ѯ��ǰ�û�id
	int UserId = ser.selectUserId(usName, usPaw);

	// ���û�id��Ϊ0ʱ��ʾ��ǰ�û�����
	if (UserId != 0) {

	    // ��ȡ�Ƿ��ס����
	    String save = req.getParameter("save");

	    // �ж��Ƿ��ס����
	    if (save != null) {

		// ���cookie��ס�˺�����
		Cookie coName = new Cookie("name", usName);
		Cookie coPaw = new Cookie("pass", usPaw);
		Cookie coId = new Cookie("usid",UserId+"");

		// ������������Ϊһ��Сʱ
		coName.setMaxAge(60 * 60);
		coPaw.setMaxAge(60 * 60);
		coId.setMaxAge(60 * 60);

		// ���cookie
		res.addCookie(coName);
		res.addCookie(coPaw);
		res.addCookie(coId);

	    }

	    // ��Session��д����
	    HttpSession session = req.getSession();

	    session.setAttribute("name", usName);

	    session.setAttribute("pass", usPaw);
	    
	    session.setAttribute("usid", UserId+"");

	    // ��¼��ҳ��
//	    res.sendRedirect("http://127.0.0.1:8080/Webwlp_2/verify");
	    req.getRequestDispatcher("verify").forward(req, res);

	} else {

	    // ���û�������ʱ����ת��
//	   res.sendRedirect("http://127.0.0.1:8080/Webwlp_2/verifyTwo");
	    req.getRequestDispatcher("verifyTwo").forward(req, res);

	}
    }

}
