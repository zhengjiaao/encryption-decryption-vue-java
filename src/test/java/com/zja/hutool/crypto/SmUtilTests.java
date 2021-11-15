/**
 * @Company: 上海数慧系统技术有限公司
 * @Department: 数据中心
 * @Author: 郑家骜[ào]
 * @Email: zhengja@dist.com.cn
 * @Date: 2021-11-09 14:30
 * @Since:
 */
package com.zja.hutool.crypto;

import cn.hutool.core.codec.Base64;
import cn.hutool.core.util.CharsetUtil;
import cn.hutool.core.util.HexUtil;
import cn.hutool.core.util.StrUtil;
import cn.hutool.crypto.SecureUtil;
import cn.hutool.crypto.SmUtil;
import cn.hutool.crypto.asymmetric.KeyType;
import cn.hutool.crypto.asymmetric.SM2;
import cn.hutool.crypto.symmetric.SymmetricCrypto;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;
import org.springframework.util.Base64Utils;

import java.io.UnsupportedEncodingException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;

/**
 * 国密算法：加解密-推荐
 */
public class SmUtilTests {

    /**
     * 非对称加密SM2: 使用随机生成的密钥对加密或解密
     * SM2类似：RSA 但比RSA更安全，更快速
     */
    @Test
    public void sm2_1() {
        String text = "我是一段测试aaaa";

        //默认，动态随机生成公钥与私钥
        SM2 sm2 = SmUtil.sm2();
        // 公钥加密，私钥解密
        String encryptStr = sm2.encryptBcd(text, KeyType.PublicKey);
        String decryptStr = StrUtil.utf8Str(sm2.decryptFromBcd(encryptStr, KeyType.PrivateKey));

        System.out.println(encryptStr);
        System.out.println(decryptStr);
    }

    /**
     * 非对称加密SM2: 使用自定义密钥对加密或解密
     */
    @Test
    public void sm2_2() throws UnsupportedEncodingException {
        String text = "我是一段测试aaaa";

        //自定义生产公钥与私钥
        KeyPair pair = SecureUtil.generateKeyPair("SM2");
        byte[] privateKey = pair.getPrivate().getEncoded();
        byte[] publicKey = pair.getPublic().getEncoded();

        SM2 sm2 = SmUtil.sm2(privateKey, publicKey);

        // 公钥加密，私钥解密
        String encryptStr = sm2.encryptBcd(text, KeyType.PublicKey);
        String decryptStr = StrUtil.utf8Str(sm2.decryptFromBcd(encryptStr, KeyType.PrivateKey));

        System.out.println(encryptStr);
        System.out.println(decryptStr);
    }

    /**
     * 非对称加密SM2: SM2签名和验签
     */
    @Test
    public void sm2_3() throws UnsupportedEncodingException {
        String content = "我是Hanley.";
        //随机生成密钥对
        final SM2 sm2 = SmUtil.sm2();
        String sign = sm2.signHex(HexUtil.encodeHexStr(content));
        System.out.println(sign);

        // true
        boolean verify = sm2.verifyHex(HexUtil.encodeHexStr(content), sign);

        System.out.println(verify);
    }

    /**
     * 非对称加密SM2: SM2签名和验签
     */
    @Test
    public void sm2_4() throws UnsupportedEncodingException {
        String content = "我是Hanley.";
        //自定义密钥对
        KeyPair pair = SecureUtil.generateKeyPair("SM2");
        final SM2 sm2 = new SM2(pair.getPrivate(), pair.getPublic());

        byte[] sign = sm2.sign(content.getBytes());

        // true
        boolean verify = sm2.verify(content.getBytes(), sign);

        System.out.println(verify);
    }

    /**
     * 摘要加密算法SM3: 类似MD5，但是比md5更安全，更快速
     */
    @Test
    public void sm3() {
        String text = "我是一段测试aaaa";

        String sm3 = SmUtil.sm3(text);
        System.out.println(sm3);
    }

    /**
     * 对称加密SM4:
     */
    @Test
    public void sm4() {
        String content = "test中文";
        SymmetricCrypto sm4 = SmUtil.sm4();

        String encryptHex = sm4.encryptHex(content);
        String decryptStr = sm4.decryptStr(encryptHex, CharsetUtil.CHARSET_UTF_8);

        System.out.println(encryptHex);
        System.out.println(decryptStr);
    }

    @Test
    public void sm2_key() {
        String text = "我是一段测试aaaa";

        //自定义生产公钥与私钥
        KeyPair pair = SecureUtil.generateKeyPair("SM2");
        byte[] privateKey = pair.getPrivate().getEncoded();
        byte[] publicKey = pair.getPublic().getEncoded();

        System.out.println("Base64编码");
        //Base64编码
        String encode = Base64.encode(pair.getPrivate().getEncoded());
        String encode1 = Base64.encode(pair.getPublic().getEncoded());
        System.out.println(encode);
        System.out.println(encode1);
        System.out.println("Base64解码");
        //Base64解码
        byte[] decode = Base64.decode(encode);
        byte[] decode1 = Base64.decode(encode1);
        System.out.println(decode);
        System.out.println(decode1);

        System.out.println(Base64Utils.encode(pair.getPrivate().getEncoded()));
        System.out.println(Base64Utils.encode(pair.getPublic().getEncoded()));

        System.out.println();

        //十六进制格式
        System.out.println(HexUtil.encodeHexStr(pair.getPublic().getEncoded()));
        System.out.println(HexUtil.encodeHexStr(pair.getPrivate().getEncoded()));


        SM2 sm2 = SmUtil.sm2(privateKey, publicKey);
        sm2.getPrivateKeyBase64();
        sm2.getPublicKeyBase64();

        // 公钥加密，私钥解密
        String encryptStr = sm2.encryptBcd(text, KeyType.PublicKey);
        String decryptStr = StrUtil.utf8Str(sm2.decryptFromBcd(encryptStr, KeyType.PrivateKey));
        System.out.println("加密：");
        System.out.println(encryptStr);
        System.out.println("解密：");
        System.out.println(decryptStr);

    }


    @Test
    public void sm2_key_1() {
        String text = "我是一段测试aaaa";

        KeyPair keyPair = generateSm2KeyPair();
        SM2 sm2 = SmUtil.sm2(keyPair.getPrivate(), keyPair.getPublic());
        // 公钥加密，私钥解密
        String encryptStr = sm2.encryptBcd(text, KeyType.PublicKey);
        String decryptStr = StrUtil.utf8Str(sm2.decryptFromBcd(encryptStr, KeyType.PrivateKey));
        System.out.println("加密：");
        System.out.println(encryptStr);
        System.out.println("解密：");
        System.out.println(decryptStr);

        System.out.println("Base64");
        System.out.println(Base64.encode(keyPair.getPrivate().getEncoded()));
        System.out.println(Base64.encode(keyPair.getPublic().getEncoded()));

        System.out.println("十六进制格式");
        //十六进制格式
        System.out.println(HexUtil.encodeHexStr(keyPair.getPrivate().getEncoded()));
        System.out.println(HexUtil.encodeHexStr(keyPair.getPublic().getEncoded()));

        System.out.println("公钥");
        System.out.println(keyPair.getPublic());

        String Pri = "308193020100301306072a8648ce3d020106082a811ccf5501822d0479307702010104200b0b37873f5d940aa4a6da744dd7080849b1bbde408b174c3b06b5e23963ef5ea00a06082a811ccf5501822da144034200049edae0afb36df29b2dd354e98bca3031d3deb157b8a287dcb669d27e7d4264694b5683b26bb47aa503812dd1af8bf54d42b2a2bc040c8b7f228dd111b6b2ec71";
        String Pub = "";

//        String base64PrivateKey = "MIGTAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBHkwdwIBAQQgCws3hz9dlAqkptp0TdcICEmxu95AixdMOwa14jlj716gCgYIKoEcz1UBgi2hRANCAASe2uCvs23ymy3TVOmLyjAx096xV7iih9y2adJ+fUJkaUtWg7JrtHqlA4Et0a+L9U1CsqK8BAyLfyKN0RG2suxx";
//        String base64PublicKey = '04'+"MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEntrgr7Nt8pst01Tpi8owMdPesVe4oofctmnSfn1CZGlLVoOya7R6pQOBLdGvi/VNQrKivAQMi38ijdERtrLscQ==";


        SM2 sm22 = SmUtil.sm2(Pri, null);

        // 公钥加密，私钥解密
//        String encryptStr2 = sm22.encryptBcd(text, KeyType.PublicKey);
//        String encryptStr2 = sm22.encryptBcd("58ad344c0bc65af3ec3dc9e26d570c17b44d845a7a006ee60c805a6c6f0120fdbc1af91ab2b430557ba6e9cc39d089942cee6e86ec9a52404365ad5f74f59baed3e1c65c57ac30c80b4283dce03019d60d4cba41e91987bc7c33e40f8316860fcad7fe976a4eff19aac5a99a29dd", KeyType.PublicKey);
        String decryptStr2 = StrUtil.utf8Str(sm22.decryptFromBcd("0458AD344C0BC65AF3EC3DC9E26D570C17B44D845A7A006EE60C805A6C6F0120FDBC1AF91AB2B430557BA6E9CC39D089942CEE6E86EC9A52404365AD5F74F59BAED3E1C65C57AC30C80B4283DCE03019D60D4CBA41E91987BC7C33E40F8316860FCAD7FE976A4EFF19AAC5A99A29DD", KeyType.PrivateKey));
        System.out.println("加密：");
//        System.out.println(encryptStr2);
        System.out.println("解密：");
        System.out.println(decryptStr2);
    }

    /**
     * SM2算法生成密钥对
     * @return 密钥对信息
     */
    public static KeyPair generateSm2KeyPair() {
        try {
            final ECGenParameterSpec sm2Spec = new ECGenParameterSpec("sm2p256v1");
            // 获取一个椭圆曲线类型的密钥对生成器
            final KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", new BouncyCastleProvider());
            SecureRandom random = new SecureRandom();
            // 使用SM2的算法区域初始化密钥生成器
            kpg.initialize(sm2Spec, random);
            // 获取密钥对
            KeyPair keyPair = kpg.generateKeyPair();
            return keyPair;
        } catch (Exception e) {
            System.out.println("生成密钥对失败");
        }
        return null;
    }

    @Test
    public void sm2_key_2() {
        //明文
        String data = "pass123";

        //密钥对-前端生成-前后端都可用
        String publicKey = "04c0a90dc19469d0e842bb6e47546951e5827c959476f87299e03152fda52e4ba44a84bcfe797586db444715a00f45007c01f26db0cdf807e85a88ac5c86ebbeff";
        String privateKey = "0e0993a5e7d9584cb78e44cd0f74b0eb21614aa8dddf54893df466097b4b4233";

        //base64 密钥对-后端生成-后端可用  但前端无法使用后端生成的密钥对
        String base64PrivateKey = "MIGTAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBHkwdwIBAQQgCws3hz9dlAqkptp0TdcICEmxu95AixdMOwa14jlj716gCgYIKoEcz1UBgi2hRANCAASe2uCvs23ymy3TVOmLyjAx096xV7iih9y2adJ+fUJkaUtWg7JrtHqlA4Et0a+L9U1CsqK8BAyLfyKN0RG2suxx";
        String base64PublicKey = "MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEntrgr7Nt8pst01Tpi8owMdPesVe4oofctmnSfn1CZGlLVoOya7R6pQOBLdGvi/VNQrKivAQMi38ijdERtrLscQ==";

        //hex 密钥对-后端生成-后端可用  但前端无法使用后端生成的密钥对
        String hexPrivateKey = "308193020100301306072a8648ce3d020106082a811ccf5501822d0479307702010104200b0b37873f5d940aa4a6da744dd7080849b1bbde408b174c3b06b5e23963ef5ea00a06082a811ccf5501822da144034200049edae0afb36df29b2dd354e98bca3031d3deb157b8a287dcb669d27e7d4264694b5683b26bb47aa503812dd1af8bf54d42b2a2bc040c8b7f228dd111b6b2ec71";
        String hexPublicKey = "3059301306072a8648ce3d020106082a811ccf5501822d034200049edae0afb36df29b2dd354e98bca3031d3deb157b8a287dcb669d27e7d4264694b5683b26bb47aa503812dd1af8bf54d42b2a2bc040c8b7f228dd111b6b2ec71";

        SM2 sm2 = SmUtil.sm2(hexPrivateKey, hexPublicKey);

        //不可用
        //获取65字节非压缩缩的十六进制公钥串(0x04)
        /*String publicKeyHex1 = Hex.toHexString(((BCECPublicKey) sm2.getPublicKey()).getQ().getEncoded(false));
        //获取32字节十六进制私钥串
        String privateKeyHex1 = ((BCECPrivateKey) sm2.getPrivateKey()).getD().toString(16);*/

        //可用
        //十六进制 密钥对-后台生成-前后端都可用  前端公钥加密，传给后端私钥解密(密文前必须加04 格式：04+密文=要解密的密文)
        //获取65字节非压缩缩的十六进制公钥串(0x04)
        String publicKeyHex = Hex.toHexString(sm2.getQ(false));
        //获取32字节十六进制私钥串
        String privateKeyHex = Hex.toHexString(sm2.getD());

        System.out.println("publicKeyHex：" + publicKeyHex);
        System.out.println("privateKeyHex：" + privateKeyHex);

        sm2.getPublicKeyBase64();
        sm2.getPrivateKeyBase64();

        //公钥加密
        String encryptStr = sm2.encryptBcd(data, KeyType.PublicKey);
        System.out.println("加密：" + encryptStr);
        //私钥解密
        String decryptStr = StrUtil.utf8Str(sm2.decryptFromBcd(encryptStr, KeyType.PrivateKey));
        System.out.println("解密：" + decryptStr);

        System.out.println("前端加密后解密：");

        //密文 前端公钥加密的密文，后端私钥解密需要加上 04 才能解密成功
        String str = "04" + "018377a7d7c11bd335db129f1bd9d76f9bc7c0de28be1f96deeeb5c880293b87b5a74dd8a6780e5f79fa0f63754ea4ea59c1f6e7c1cc704cf9cea1786ad51deab1927d7ef6534aecb20681029a85ff85ae16dd4a25045aec6330cfd17de607211c45dd083c35e4";

        //可用
        byte[] decrypt = sm2.decrypt(str, KeyType.PrivateKey);
        System.out.println(StrUtil.utf8Str(decrypt));

    }

}
