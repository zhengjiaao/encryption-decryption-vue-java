package com.zja.security;

import cn.hutool.crypto.asymmetric.KeyType;
import cn.hutool.crypto.asymmetric.RSA;
import com.zja.KeyPairDTO;
import lombok.extern.slf4j.Slf4j;

/**
 * RSA 非对称加解密：公钥加密，私钥解密
 */
@Slf4j
public class RSAEncrypt /*implements IEncrypt*/ extends AbstractEncrypt {

    public RSAEncrypt(KeyPairDTO keyPairDTO) {
        super(keyPairDTO);
    }

    /**
     * 加密
     * @param data 明文
     * @return 密文
     */
    @Override
    public String encrypt(String data) {
        return encrypt(data, keyPairDTO.getPublicKeyBase64());
    }

    /**
     * 加密
     * @param data 明文
     * @param publicKey 公钥
     * @return 密文
     */
    @Override
    public String encrypt(String data, String publicKey) {
        try {
            RSA rsa = new RSA(null, publicKey);
            return rsa.encryptBase64(data, KeyType.PublicKey);
        } catch (Exception e) {
            log.error("{} 公钥加密失败", keyPairDTO.getKeyType());
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 解密
     * @param data 密文
     * @return 明文
     */
    @Override
    public String decrypt(String data) {
        return decrypt(data, keyPairDTO.getPrivateKeyBase64());
    }

    /**
     * 解密
     * @param data 密文
     * @param privateKey 私钥
     * @return 明文
     */
    @Override
    public String decrypt(String data, String privateKey) {
        try {
            RSA rsa = new RSA(privateKey, null);
            return rsa.decryptStr(data, KeyType.PrivateKey);
        } catch (Exception e) {
            log.error("{} 私钥解密失败", keyPairDTO.getKeyType());
            e.printStackTrace();
        }
        return null;
    }
}
