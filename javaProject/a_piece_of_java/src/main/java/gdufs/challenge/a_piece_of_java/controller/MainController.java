package gdufs.challenge.a_piece_of_java.controller;


import gdufs.challenge.a_piece_of_java.model.Info;
import gdufs.challenge.a_piece_of_java.model.UserInfo;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.Cookie;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;
import java.util.Base64;
import org.nibblesec.tools.SerialKiller;


/**
 * 功能：
 *
 * @author 长瀞同学
 * @ClassName MainController
 * @description
 * @date 2023-09-03 15:03
 * @Version 1.0
 */
public class MainController {
    @GetMapping({"/index"})
    public String index(@CookieValue(value = "data", required = false) String cookieData) {
        if (cookieData != null && !cookieData.equals(""))
            return "redirect:/hello";
        return "index";
    }


    @PostMapping({"/index"})
    public String index(@RequestParam("username") String username, @RequestParam("password") String password, HttpServletResponse response) {
        UserInfo userinfo = new UserInfo();
        userinfo.setUsername(username);
        userinfo.setPassword(password);
        Cookie cookie = new Cookie("data", serialize(userinfo));
        cookie.setMaxAge(2592000);
        response.addCookie(cookie);
        return "redirect:/hello";
    }

    @GetMapping({"/hello"})
    public String hello(@CookieValue(value = "data", required = false) String cookieData, Model model) {
        if (cookieData == null || cookieData.equals(""))
            return "redirect:/index";
        Info info = (Info)deserialize(cookieData);
        if (info != null)
            model.addAttribute("info", info.getAllInfo());
        return "hello";
    }

    private String serialize(Object obj) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try {
            ObjectOutputStream oos = new ObjectOutputStream(baos);
            oos.writeObject(obj);
            oos.close();
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
        return new String(Base64.getEncoder().encode(baos.toByteArray()));
    }

    private Object deserialize(String base64data) {
        Object obj;
        ByteArrayInputStream bais = new ByteArrayInputStream(Base64.getDecoder().decode(base64data));
        try {
            SerialKiller serialKiller = new SerialKiller(bais, "serialkiller.conf");
            obj = serialKiller.readObject();
            serialKiller.close();
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
        return obj;
    }
}
