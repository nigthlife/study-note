package gdufs.challenge.a_piece_of_java.model;

import java.io.Serializable;

/**
 * 功能：
 *
 * @author 长瀞同学
 * @ClassName UserInfo
 * @description
 * @date 2023-09-03 15:05
 * @Version 1.0
 */
public class UserInfo implements Serializable, Info{

    private String username;

    private String password;

    public void setUsername(String username) {
        this.username = username;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getUsername() {
        return this.username;
    }

    public String getPassword() {
        return this.password;
    }

    public Boolean checkAllInfo() {
        return Boolean.valueOf((this.username != null && this.password != null));
    }

    public String getAllInfo() {
        return "Your username is " + this.username + ", and your password is " + this.password + ".";
    }
}
