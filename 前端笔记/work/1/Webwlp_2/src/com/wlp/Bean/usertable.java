package com.wlp.Bean;

/**
 * @auuter：武乐萍
 * 功能描述：
 * 创建日期： 2020年12月5日 下午11:44:02
 * 包名：com.wlp.Bean
 * 
 */
public class usertable {
    
    // 用户id
    private int usId;
    
    // 用户名
    private String usName;
    
    // 用户密码
    private String usPaw;

    // 构造方法
    public usertable(int usId, String usName, String usPaw) {
	super();
	this.usId = usId;
	this.usName = usName;
	this.usPaw = usPaw;
    }

    // 空参构造方法
    public usertable() {
	super();
	// TODO Auto-generated constructor stub
    }

    public int getUsId() {
        return usId;
    }

    public void setUsId(int usId) {
        this.usId = usId;
    }

    public String getUsName() {
        return usName;
    }

    public void setUsName(String usName) {
        this.usName = usName;
    }

    public String getUsPaw() {
        return usPaw;
    }

    public void setUsPaw(String usPaw) {
        this.usPaw = usPaw;
    }

    @Override
    public String toString() {
	return "User [usId=" + usId + ", usName=" + usName + ", usPaw=" + usPaw + "]";
    }
    
    

}
