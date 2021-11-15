/**
 * @Company: 上海数慧系统技术有限公司
 * @Department: 数据中心
 * @Author: 郑家骜[ào]
 * @Email: zhengja@dist.com.cn
 * @Date: 2021-11-12 18:26
 * @Since:
 */
package com.zja.securypt;

import com.zja.security.AbstractEncrypt;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

/**
 *
 */
@SpringBootTest
public class AbstractEncryptTests {

    @Autowired
    private AbstractEncrypt abstractEncrypt;

    @Test
    public void test() {
        System.out.println(abstractEncrypt.getKeyType());

        String encrypt = abstractEncrypt.encrypt("pass123");
        System.out.println("加密结果：" + encrypt);
        System.out.println("解密结果：" + abstractEncrypt.decrypt(encrypt));
    }
}
