package gdufs.challenge.a_piece_of_java.invocation;

import gdufs.challenge.a_piece_of_java.model.Info;

import java.io.Serializable;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;


/**
 * 功能：
 *
 * @author 长瀞同学
 * @ClassName InfoInvocationHandler
 * @description
 * @date 2023-09-03 15:05
 * @Version 1.0
 */
public class InfoInvocationHandler implements InvocationHandler, Serializable {
    private Info info;

    public InfoInvocationHandler(Info info) {
        this.info = info;
    }

    public Object invoke(Object proxy, Method method, Object[] args) {
        try {
            if (method.getName().equals("getAllInfo") &&
                    !this.info.checkAllInfo().booleanValue())
                return null;
            return method.invoke(this.info, args);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
}
