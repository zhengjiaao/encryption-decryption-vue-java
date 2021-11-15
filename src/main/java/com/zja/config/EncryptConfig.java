
package com.zja.config;

import com.zja.KeyPairDTO;
import com.zja.security.AbstractEncrypt;
import com.zja.security.KeyPairManage;
import com.zja.security.RSAEncrypt;
import com.zja.security.SM2Encrypt;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Scope;

/**
 * 加解密配置类
 */
@Slf4j
@Configuration
public class EncryptConfig {

    /**
     * 非对称加密方式: RSA、SM2
     */
    @Value("${system.encrypt.keytype}")
    public String keyType = "RSA";

    /**
     * 密钥格式：Base64、Hex(十六进制)
     */
    @Value("${system.encrypt.keyformat}")
    public String keyFormat = "Hex";

    /**
     * 密钥长度：推荐 大于2048位 例：4096
     */
    @Value("${system.encrypt.keysize}")
    public Integer keysize = 2048;

    /**
     * 密钥对是否动态变化：true 动态，false 非动态，会存储到本地中
     */
    @Value("${system.encrypt.keypairdynamic}")
    public Boolean keyPairDynamic = false;

    /**
     * 初始化非对称密钥对
     */
    @SneakyThrows
    @Bean
    @Scope(value = "singleton")
    public KeyPairDTO keyPairDTO() {
        return new KeyPairManage().generateKeyPair(keyType, keysize, keyFormat, keyPairDynamic);
    }

    @Bean
    public AbstractEncrypt abstractEncrypt() {
        if ("RSA".equalsIgnoreCase(keyType)) {
            return new RSAEncrypt(keyPairDTO());
        } else if ("SM2".equalsIgnoreCase(keyType)) {
            return new SM2Encrypt(keyPairDTO());
        }
        throw new RuntimeException("密钥类型 ${system.encrypt.keytype} 值必须是 【RSA】 or 【SM2】");
    }

    /*    @Bean
    public IEncrypt iEncrypt() {
        if ("RSA".equalsIgnoreCase(keyType)) {
            return new RSAEncrypt();
        } else if ("SM2".equalsIgnoreCase(keyType)) {
            return new SM2Encrypt();
        }
        throw new RuntimeException("密钥类型 ${system.encrypt.keytype} 值必须是 【RSA】 or 【SM2】");
    }*/
}
