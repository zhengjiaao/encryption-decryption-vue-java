/**
 * @Company: 上海数慧系统技术有限公司
 * @Department: 数据中心
 * @Author: 郑家骜[ào]
 * @Email: zhengja@dist.com.cn
 * @Date: 2021-11-15 9:15
 * @Since:
 */
package com.zja.security;

import cn.hutool.crypto.KeyUtil;
import cn.hutool.crypto.SecureUtil;
import com.zja.KeyPairDTO;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * 密钥对管理
 */
public final class KeyPairManage {

    /**
     * 密钥对 本地存储文件名称
     */
    private static final String privateKeyFileName = "privateKey.key";
    private static final String publicKeyFileName = "publicKey.key";

    public KeyPairDTO generateKeyPair(String keyType, Integer keysize, String keyFormat, Boolean keyPairDynamic) throws IOException {
        if (!"RSA".equalsIgnoreCase(keyType) && !"SM2".equalsIgnoreCase(keyType)) {
            throw new RuntimeException("密钥类型 ${system.encrypt.keytype} 值必须是 【RSA】 or 【SM2】");
        }

        //生成密钥
        KeyPair keyPair = SecureUtil.generateKeyPair(keyType, keysize);
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        //密钥对存储方式：内存、本地、缓存

        String webPath = this.getClass().getClassLoader().getResource("").getPath().replaceAll("%20", " ") + File.separator + "key";
        //如果动态获取被关了 那么就从文件中获取
        File priKeyFile = new File(webPath + File.separator + keyType + File.separator + privateKeyFileName);
        File pubKeyFile = new File(webPath + File.separator + keyType + File.separator + publicKeyFileName);

        //控制全局秘钥生成 fasle 则密钥对存储本地
        if (keyPairDynamic) {
            if (!priKeyFile.exists() || !pubKeyFile.exists()) {
                //如果任何一个文件不存在那么就重新创建
                priKeyFile.delete();
                pubKeyFile.delete();
                //写入本地文件或缓存redis中
                FileUtils.writeByteArrayToFile(priKeyFile, privateKey.getEncoded());
                FileUtils.writeByteArrayToFile(pubKeyFile, publicKey.getEncoded());
                return new KeyPairDTO(keyType, keyPair.getPrivate(), keyPair.getPublic(), keyFormat, keyPairDynamic);
            } else {
                PrivateKey privateKey1 = KeyUtil.generatePrivateKey(keyType, new PKCS8EncodedKeySpec(IOUtils.toByteArray(new FileInputStream(priKeyFile))));
                PublicKey publicKey1 = KeyUtil.generatePublicKey(keyType, new X509EncodedKeySpec(IOUtils.toByteArray(new FileInputStream(pubKeyFile))));
                //从文件中获取公钥以及私钥
                return new KeyPairDTO(keyType, privateKey1, publicKey1, keyFormat, keyPairDynamic);
            }
        }
        return new KeyPairDTO(keyType, keyPair.getPrivate(), keyPair.getPublic(), keyFormat, keyPairDynamic);
    }
}
