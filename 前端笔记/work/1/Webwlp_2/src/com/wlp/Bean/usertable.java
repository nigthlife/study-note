package com.wlp.Bean;

/**
 * @auuter������Ƽ
 * ����������
 * �������ڣ� 2020��12��5�� ����11:44:02
 * ������com.wlp.Bean
 * 
 */
public class usertable {
    
    // �û�id
    private int usId;
    
    // �û���
    private String usName;
    
    // �û�����
    private String usPaw;

    // ���췽��
    public usertable(int usId, String usName, String usPaw) {
	super();
	this.usId = usId;
	this.usName = usName;
	this.usPaw = usPaw;
    }

    // �ղι��췽��
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
