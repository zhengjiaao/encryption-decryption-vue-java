/**
 * @Company: 上海数慧系统技术有限公司
 * @Department: 数据中心
 * @Author: 郑家骜[ào]
 * @Email: zhengja@dist.com.cn
 * @Date: 2021-11-10 16:54
 * @Since:
 */
package com.zja.security;

/**
 * 1、系统传输数据加解密
 * 2、数据库数据存储加解密 抽象类
 */
public interface IEncrypt {

    /**
     * 加密
     * @param data 明文
     * @return 密文
     */
    String encrypt(String data);

    /**
     * 加密
     * @param data 明文
     * @param publicKey 公钥
     * @return 密文
     */
    String encrypt(String data, String publicKey);

    /**
     * 解密
     * @param data 密文
     * @return 明文
     */
    String decrypt(String data);

    /**
     * 解密
     * @param data 密文
     * @param privateKey 私钥
     * @return 明文
     */
    String decrypt(String data, String privateKey);
}
