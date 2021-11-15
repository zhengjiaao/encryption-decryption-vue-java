/**
 * @Company: 上海数慧系统技术有限公司
 * @Department: 数据中心
 * @Author: 郑家骜[ào]
 * @Email: zhengja@dist.com.cn
 * @Date: 2021-11-09 16:34
 * @Since:
 */
package com.zja.hutool.crypto;

import cn.hutool.core.codec.Base64;
import cn.hutool.core.util.CharsetUtil;
import cn.hutool.core.util.StrUtil;
import cn.hutool.crypto.SecureUtil;
import cn.hutool.crypto.asymmetric.KeyType;
import cn.hutool.crypto.asymmetric.RSA;
import cn.hutool.crypto.symmetric.SymmetricAlgorithm;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;


/**
 * 加密解密工具：支持生成密钥
 */
public class SecureUtilTests {

    /**
     * 密钥生成: SecureUtil.generateKey 针对对称加密生成密钥
     */
    @Test
    public void generateKeyTest(){
        //随机生成密钥
        byte[] key = SecureUtil.generateKey(SymmetricAlgorithm.AES.getValue()).getEncoded();

        //示例：AES算法

    }

    /**
     * 密钥生成: SecureUtil.generateKeyPair  生成密钥对（用于非对称加密）
     */
    @Test
    public void generateKeyPairTest(){
        KeyPair pair = SecureUtil.generateKeyPair("RSA");
        PrivateKey privateKey = pair.getPrivate();
        PublicKey publicKey = pair.getPublic();

        //可以使用Base64.encode方法转为Base64，便于存储为文本
        System.out.println(Base64.encode(privateKey.getEncoded()));
        System.out.println(Base64.encode(publicKey.getEncoded()));

        //示例: RAS

        RSA rsa = new RSA(pair.getPrivate(), pair.getPublic());
        //公钥加密，私钥解密
        byte[] encrypt = rsa.encrypt(StrUtil.bytes("pass123", CharsetUtil.CHARSET_UTF_8), KeyType.PublicKey);
        byte[] decrypt = rsa.decrypt(encrypt, KeyType.PrivateKey);

        System.out.println(StrUtil.str(decrypt, CharsetUtil.CHARSET_UTF_8));
    }

    /**
     * 密钥生成: SecureUtil.generateSignature  生成签名（用于非对称加密）
     */
    @Test
    public void generateSignatureTest(){

    }

}
