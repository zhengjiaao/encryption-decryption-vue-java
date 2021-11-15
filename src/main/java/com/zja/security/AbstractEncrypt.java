/**
 * @Company: 上海数慧系统技术有限公司
 * @Department: 数据中心
 * @Author: 郑家骜[ào]
 * @Email: zhengja@dist.com.cn
 * @Date: 2021-11-12 18:12
 * @Since:
 */
package com.zja.security;

import cn.hutool.core.codec.Base64;
import com.zja.KeyPairDTO;
import com.zja.PublicKeyDTO;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.util.encoders.Hex;

import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * 支持加解密方式：RSA、SM2
 * 方式：公钥加密，私钥解密
 */
public abstract class AbstractEncrypt {

    public KeyPairDTO keyPairDTO;

    public AbstractEncrypt(KeyPairDTO keyPairDTO) {
        this.keyPairDTO = keyPairDTO;
    }


    /**
     * 加密
     * @param data 明文
     * @return 密文：Base64包装
     */
    public abstract String encrypt(String data);

    /**
     * 加密
     * @param data 明文
     * @param publicKey 公钥：支持 Base64、Hex
     * @return 密文：Base64包装
     */
    public abstract String encrypt(String data, String publicKey);

    /**
     * 解密
     * @param data 密文：支持 Base64、Hex
     * @return 明文
     */
    public abstract String decrypt(String data);

    /**
     * 解密
     * @param data 密文：支持 Base64、Hex
     * @param privateKey 私钥：支持 Base64、Hex
     * @return 明文
     */
    public abstract String decrypt(String data, String privateKey);


    /*********************************下面是密钥操作*********************************/


    /**
     * 获取密钥对类型
     * @return 类型 ：SM2、RSA等
     */
    public String getKeyType() {
        return keyPairDTO.getKeyType();
    }

    /**
     * 动太变化
     * @return true 是动态变化的
     */
    public boolean getKeyPairDynamic() {
        return keyPairDTO.getKeyPairDynamic();
    }

    /**
     * 获取公钥
     * @return 公钥
     */
    public PublicKey getPublicKey() {
        return keyPairDTO.getPublicKey();
    }

    /**
     * 获取私钥
     * @return 私钥
     */
    public PrivateKey getPrivateKey() {
        return keyPairDTO.getPrivateKey();
    }

    /**
     * 获取十六进制公钥
     * @return 公钥
     */
    public String getPublicKeyHex() {
        String publicKeyHex = null;
        if (getPublicKey() instanceof BCECPublicKey) {
            //SM2比较特殊，前端需要十六进制格式 为了适配前端sm-crypto组件公钥格式
            //获取65字节非压缩缩的十六进制公钥串(0x04)
            publicKeyHex = Hex.toHexString(((BCECPublicKey) getPublicKey()).getQ().getEncoded(false));
        } else {
            //如：RSA 等
            publicKeyHex = Hex.toHexString(getPublicKey().getEncoded());
        }
        return publicKeyHex;
    }

    /**
     * 获取十六进制私钥
     * @return 私钥
     */
    public String getPrivateKeyHex() {
        String privateKeyHex = null;
        if (getPrivateKey() instanceof BCECPrivateKey) {
            //SM2比较特殊，前端需要十六进制格式 为了适配前端sm-crypto组件公钥格式
            //获取32字节十六进制私钥串
            privateKeyHex = ((BCECPrivateKey) getPrivateKey()).getD().toString(16);
        } else {
            //如：RSA 等
            privateKeyHex = Hex.toHexString(getPrivateKey().getEncoded());
        }
        return privateKeyHex;
    }

    /**
     * 获取Base64编码的公钥
     * @return 公钥
     */
    public String getPublicKeyBase64() {
        return (null == getPublicKey()) ? null : Base64.encode(getPublicKey().getEncoded());
    }

    /**
     * 获取Base64编码的私钥
     * @return 私钥
     */
    public String getPrivateKeyBase64() {
        return (null == getPrivateKey()) ? null : Base64.encode(getPrivateKey().getEncoded());
    }

    /**
     * 获取公钥信息(提供给前端使用)
     * @return 公钥信息
     */
    public PublicKeyDTO getPublicKeyInfo() {
        if ("Hex".equalsIgnoreCase(keyPairDTO.getKeyFormat())) {
            return new PublicKeyDTO(keyPairDTO.getKeyType(), getPublicKeyHex(), keyPairDTO.getKeyFormat(), keyPairDTO.getKeyPairDynamic());
        }
        return new PublicKeyDTO(keyPairDTO.getKeyType(), getPublicKeyBase64(), keyPairDTO.getKeyFormat(), keyPairDTO.getKeyPairDynamic());
    }
}
