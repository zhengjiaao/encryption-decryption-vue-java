/**
 * @Company: 上海数慧系统技术有限公司
 * @Department: 数据中心
 * @Author: 郑家骜[ào]
 * @Email: zhengja@dist.com.cn
 * @Date: 2021-11-09 17:16
 * @Since:
 */
package com.zja.security;

import cn.hutool.crypto.SmUtil;
import cn.hutool.crypto.asymmetric.KeyType;
import cn.hutool.crypto.asymmetric.SM2;
import com.zja.KeyPairDTO;
import lombok.extern.slf4j.Slf4j;

/**
 * 国密加密：SM2 公钥加密，私钥解密
 */
@Slf4j
public class SM2Encrypt /*implements IEncrypt*/ extends AbstractEncrypt {

    public SM2Encrypt(KeyPairDTO keyPairDTO) {
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
            SM2 sm2 = SmUtil.sm2(null, publicKey);
            return sm2.encryptBase64(data, KeyType.PublicKey);
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
            SM2 sm2 = SmUtil.sm2(privateKey, null);
            return sm2.decryptStr(data, KeyType.PrivateKey);
        } catch (Exception e) {
            log.error("{} 私钥解密失败", keyPairDTO.getKeyType());
            e.printStackTrace();
        }
        return null;
    }
}
