package com.wlp.Bean;

/**
 * @auuter������Ƽ
 * ����������
 * �������ڣ� 2020��12��5�� ����11:47:03
 * ������com.wlp.Bean
 * 
 */
public class task {
    
    // ����id
    private int taskid;
    
    // �û�id
    private int usId;
    
    // ��������
    private String taskName;
    
    // ����ϸ��
    private String taskDetail;
    
    // ����״̬
    private int taskState;
     
    // �������
    private String finishedDate;
    
    // �Ƿ�ɾ��
    private int isDelete;
    
    // ���񴴽��û�
    private int createUser;
    
    // ���񴴽�ʱ��
    private String createDate;
    
    // �����������û�
    private int lastUpdateUser;
    
    // ����������ʱ��
    private String lastUpdateDate;

    public task() {
	super();
	// TODO Auto-generated constructor stub
    }

  

    public task(int taskid, int usId, String taskName, String taskDetail, int taskState, String finishedDate,
	    int isDelete, int createUser, String createDate, int lastUpdateUser, String lastUpdateDate) {
	super();
	this.taskid = taskid;
	this.usId = usId;
	this.taskName = taskName;
	this.taskDetail = taskDetail;
	this.taskState = taskState;
	this.finishedDate = finishedDate;
	this.isDelete = isDelete;
	this.createUser = createUser;
	this.createDate = createDate;
	this.lastUpdateUser = lastUpdateUser;
	this.lastUpdateDate = lastUpdateDate;
    }



    public int getTaskid() {
        return taskid;
    }

    public void setTaskid(int taskid) {
        this.taskid = taskid;
    }

    public int getUsId() {
        return usId;
    }

    public void setUsId(int usId) {
        this.usId = usId;
    }

    public String getTaskName() {
        return taskName;
    }

    public void setTaskName(String taskName) {
        this.taskName = taskName;
    }

    public String getTaskDetail() {
        return taskDetail;
    }

    public void setTaskDetail(String taskDetail) {
        this.taskDetail = taskDetail;
    }

    public int getTaskState() {
        return taskState;
    }

    public void setTaskState(int taskState) {
        this.taskState = taskState;
    }

    public String getFinishedDate() {
        return finishedDate;
    }

    public void setFinishedDate(String finishedDate) {
        this.finishedDate = finishedDate;
    }

    public int getIsDelete() {
        return isDelete;
    }

    public void setIsDelete(int isDelete) {
        this.isDelete = isDelete;
    }

    

    public int getCreateUser() {
        return createUser;
    }



    public void setCreateUser(int createUser) {
        this.createUser = createUser;
    }



    public void setLastUpdateUser(int lastUpdateUser) {
        this.lastUpdateUser = lastUpdateUser;
    }



    public String getCreateDate() {
        return createDate;
    }

    public void setCreateDate(String createDate) {
        this.createDate = createDate;
    }

   
    public int getLastUpdateUser() {
        return lastUpdateUser;
    }



    public String getLastUpdateDate() {
        return lastUpdateDate;
    }

    public void setLastUpdateDate(String lastUpdateDate) {
        this.lastUpdateDate = lastUpdateDate;
    }

    @Override
    public String toString() {
	return "task [taskid=" + taskid + ", usId=" + usId + ", taskName=" + taskName + ", taskDetail=" + taskDetail
		+ ", taskState=" + taskState + ", finishedDate=" + finishedDate + ", isDelete=" + isDelete
		+ ", createUser=" + createUser + ", createDate=" + createDate + ", lastUpdateUser=" + lastUpdateUser
		+ ", lastUpdateDate=" + lastUpdateDate + "]";
    }
    
    

}
