/**
 * @Company: 上海数慧系统技术有限公司
 * @Department: 数据中心
 * @Author: 郑家骜[ào]
 * @Email: zhengja@dist.com.cn
 * @Date: 2021-11-10 13:22
 * @Since:
 */
package com.zja;

import cn.hutool.core.codec.Base64;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.util.encoders.Hex;

import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * 密钥对
 */
@Slf4j
public final class KeyPairDTO {

    /**
     * 非对称加密类型: RSA、SM2
     */
    private String keyType;

    /**
     * 密钥格式：Base64、Hex(十六进制)
     */
    public String keyFormat;

    /**
     * 密钥对 是否动态变化
     * 若为true 密钥对是动态变化的，每次前端加密都需要从新获取公钥
     * 若为false，前端可以将公钥缓存至本地，后台一般不会变动密钥对，注意，更换服务器，或重新部署后台密钥对可能会变动
     */
    private boolean keyPairDynamic;

    //私钥
    private PrivateKey privateKey;
    //公钥
    private PublicKey publicKey;

    public KeyPairDTO(String keyType, PrivateKey privateKey, PublicKey publicKey, String keyFormat, boolean keyPairDynamic) {
        log.info("密钥类型：{}", keyType);
        this.keyType = keyType;
        this.privateKey = privateKey;
        this.publicKey = publicKey;
        this.keyFormat = keyFormat;
        this.keyPairDynamic = keyPairDynamic;
    }

    /**
     * 获取密钥对类型
     * @return 类型 ：SM2、RSA等
     */
    public String getKeyType() {
        return keyType;
    }

    /**
     * 动太变化
     * @return true 是动态变化的
     */
    public boolean getKeyPairDynamic() {
        return keyPairDynamic;
    }

    /**
     * 密钥格式
     * @return
     */
    public String getKeyFormat() {
        return keyFormat;
    }

    /**
     * 获取公钥
     * @return 公钥
     */
    public PublicKey getPublicKey() {
        return publicKey;
    }

    /**
     * 获取私钥
     * @return 私钥
     */
    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    /**
     * 获取十六进制公钥
     * @return 公钥
     */
    public String getPublicKeyHex() {
        String publicKeyHex = null;
        if (publicKey instanceof BCECPublicKey) {
            //SM2比较特殊，前端需要十六进制格式
            //获取65字节非压缩缩的十六进制公钥串(0x04)
            publicKeyHex = Hex.toHexString(((BCECPublicKey) publicKey).getQ().getEncoded(false));
        } else {
            //如：RSA 等
            publicKeyHex = Hex.toHexString(publicKey.getEncoded());
        }
        return publicKeyHex;
    }

    /**
     * 获取十六进制私钥
     * @return 私钥
     */
    public String getPrivateKeyHex() {
        String privateKeyHex = null;
        if (privateKey instanceof BCECPrivateKey) {
            //SM2比较特殊，前端需要十六进制格式
            //获取32字节十六进制私钥串
            privateKeyHex = ((BCECPrivateKey) privateKey).getD().toString(16);
        } else {
            //如：RSA 等
            privateKeyHex = Hex.toHexString(privateKey.getEncoded());
        }
        return privateKeyHex;
    }

    /**
     * 获取Base64编码的公钥
     * @return 公钥
     */
    public String getPublicKeyBase64() {
        return (null == publicKey) ? null : Base64.encode(publicKey.getEncoded());
    }

    /**
     * 获取Base64编码的私钥
     * @return 私钥
     */
    public String getPrivateKeyBase64() {
        return (null == privateKey) ? null : Base64.encode(privateKey.getEncoded());
    }

}
