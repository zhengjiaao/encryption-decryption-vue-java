/**
 * @Company: 上海数慧系统技术有限公司
 * @Department: 数据中心
 * @Author: 郑家骜[ào]
 * @Email: zhengja@dist.com.cn
 * @Date: 2021-11-12 15:59
 * @Since:
 */
package com.zja.hutool.crypto;

import cn.hutool.core.codec.Base64;
import cn.hutool.core.util.CharsetUtil;
import cn.hutool.core.util.StrUtil;
import cn.hutool.crypto.SmUtil;
import cn.hutool.crypto.asymmetric.KeyType;
import cn.hutool.crypto.asymmetric.RSA;
import cn.hutool.crypto.asymmetric.SM2;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;

import java.security.PrivateKey;
import java.security.PublicKey;

/**
 *
 */
public class RsaAndSm2Tests {


    /**
     * 自定义密钥加解密：国密算法SM2
     */
    @Test
    public void test_sm2() {
        //明文
        String data = "pass123";

        //----Hex----
        String PrivateKeyHex = "b6fb5a6fb1f304bb109f03add08096bb2d51b3a089e7c50dfe0fb5390a19bfc1";
        String PublicKeyHex = "04a272c2a59aa133ae3e79b0634cee68f05f419f46cf1704e61c6e783aef64037f7d86cd6b49f174f089657a2aec9ae7ff7e147a244074ebe1537f3ca2608bdc66";
        //----Base64----
        String PrivateKeyBase64 = "MIGTAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBHkwdwIBAQQgtvtab7HzBLsQnwOt0ICWuy1Rs6CJ58UN/g+1OQoZv8GgCgYIKoEcz1UBgi2hRANCAASicsKlmqEzrj55sGNM7mjwX0GfRs8XBOYcbng672QDf32GzWtJ8XTwiWV6Kuya5/9+FHokQHTr4VN/PKJgi9xm";
        String PublicKeyBase64 = "MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEonLCpZqhM64+ebBjTO5o8F9Bn0bPFwTmHG54Ou9kA399hs1rSfF08Illeirsmuf/fhR6JEB06+FTfzyiYIvcZg==";

        SM2 sm2 = SmUtil.sm2(PrivateKeyHex, PublicKeyHex);

        //公钥加密
        String encryptStr = sm2.encryptBcd(data, KeyType.PublicKey);
        System.out.println("加密：" + encryptStr);
        //私钥解密
        String decryptStr = StrUtil.utf8Str(sm2.decryptFromBcd(encryptStr, KeyType.PrivateKey));
        System.out.println("解密：" + decryptStr);

        //密文 前端公钥加密的密文
        //后端私钥解密需要加上 04 才能解密成功
        String str = "04" + "31befa4f77e4e964eaebc42e2a90542938c821036c0b38060ab8c8754b567d2b608123bdf6d4faf9da05bef1b34bbd93f99cfd94a408091fae9ea6093662df18a688a8c56460179b5dd235314a1b25e43a08d48eca556cf64a2704e1d1369fbb4f94689a94b4e4";

        //可用
        byte[] decrypt = sm2.decrypt(str, KeyType.PrivateKey);
        System.out.println("前端加密后解密结果：" + StrUtil.utf8Str(decrypt));
    }

    /**
     * 自定义密钥加解密: RSA算法
     */
    @Test
    public void test_rsa() {
        //明文
        String data = "pass123";

        //RSA 密钥对
        //----Hex----
        String PrivateKeyHex = "308204bd020100300d06092a864886f70d0101010500048204a7308204a30201000282010100c46e42376bd27561f6e6c97c1e39f991c1a35fc217375c4ae2773aca2912ab6f11ad8851311f0aee27c8b2a2d67500229d3ee5c13ebeca45007df0ed98955133298b01d6ebc29547e9bce3487dafaee78399f87d9a3e3d5a9842b80fe200ed69a109fc660c9962660e4a0b9878a0eb003283308532fa385c8739d52737b2972b14b8a8fb552fd3ebb9225a0bdc48100b9d15b2c835652e8372ae0f36c90fef15b7d839e0fa17a61c04d0822bbe515176297832bd46785445a511343651b047bc1aa9ba533a84eb3eb2d78e8704284c5700c956d8a4702ace9ca463bd69ef8f6814ca7fd183a580650caeb130eb0bb46101a3bc1f35fad34b1296c3baa2f2482302030100010282010029c5086fa08df04814a89ecfb5ddbe243078fd33d89bfd142f740b1c51ff9654d7fd7eaf4532c4b03fe57d9702e37e53ddfc31ff15c89c5a6ff057fb2e27124d3ed8405be3664d382d8bed08cd313e901c7bf14b443157fa9bc6143dcc61461ae013af8843c59a16f992e54456e2611679a74bfa070d0e4f1eb23d914956c0ae18913eb6fa361f6c8adb188cdcf6848d48827e397512923626b5bcb4cc6fe3898a5bebfd8c79f088fd7fd000dbbffd1e367001c5065cac4f4283f3fcba971c6d67be86c4c9e94813c9abd4ef9e0ce2d26a79d638f49e3ddeede7bf5f6aac63bfa15b242a3e9ee171a4be9bdbead93777ff207e79e564cd3ca4d673b5807c1d8102818100fae09e99c5ee56de3ef252303db3c08f49c1f8f9ac4dcd3c1c3dbfcb9930cc3d30bd571383a903041094d10301d00f3d1deb4cb6b8b177488647be33fbd71256af2efad05e927e34f90880c6b44ce972170a505e2fc837efd61f09c2f8dd8d1aae161c5a018fc95cb5beb14b6607b4b9bee054d5fd5b8596463979c1a40be22d02818100c87109592a7f089d034e3dcac3d82d525980dd71e4472782d6a94459ad94c6ad5c63128969a80162f0402589832d093c81bca7eac6c3e000ab3825c1fe7c33d7f856eaf31f49f9e08babcf3b1d12eb93d797a0bb8174c30397aa6f4d6f6246db8ff2e41a49310c42208eff1d88be0119c4394eb340e035df60bc110706ce558f02818022e573aa3819fb03570625e087f4a4e8497e2dbfacf3f58452f953e06222a3862f6d66db5409025e626010e2b631d6accda899372161ae11ec7bb63d4cde91b27513b7d79c100c7619ddd0ebd2d08ff84ab42891b15bcc4c1420a51ef5b6fb95a67974e0202f7bf6e560ed106bd4ce92b7b64496af733795bb96eb14c058d6d1028180465b4708c15dedcc0f48fb6f9ce6d8a1bb40fc79e9c3001f70f1e1480921dbcb264eb047038b3151653b5ef1b1d5b1144805cc7b2061c8d2f346b61a2e15b2acf042b21dbcb1debfeec6d3eacffdc02b18d5e4596ccb6b586b782bb166937c83bd3768d1c137323253f35da1244a6d6079fc139fdff9d36f21296260b106e40902818100ae3c5bfd77624d3857c290fd1dc5d211b7832a0398aaef60497f38214e89561f67fb1933f70cd6d8897905a23e2028cf7c3b8ad1a0c47d7db32f69242ae43b08c23c7defe226648f47de134f933c3949860c8aeed4c630d6b55b1d9994c5a47b222b8e52b223b413d70e45da44aa171e9964b46fce7048af42d733f98df60831";
        String PublicKeyHex = "30820122300d06092a864886f70d01010105000382010f003082010a0282010100c46e42376bd27561f6e6c97c1e39f991c1a35fc217375c4ae2773aca2912ab6f11ad8851311f0aee27c8b2a2d67500229d3ee5c13ebeca45007df0ed98955133298b01d6ebc29547e9bce3487dafaee78399f87d9a3e3d5a9842b80fe200ed69a109fc660c9962660e4a0b9878a0eb003283308532fa385c8739d52737b2972b14b8a8fb552fd3ebb9225a0bdc48100b9d15b2c835652e8372ae0f36c90fef15b7d839e0fa17a61c04d0822bbe515176297832bd46785445a511343651b047bc1aa9ba533a84eb3eb2d78e8704284c5700c956d8a4702ace9ca463bd69ef8f6814ca7fd183a580650caeb130eb0bb46101a3bc1f35fad34b1296c3baa2f248230203010001";
        //----Base64----
        String PrivateKeyBase64 = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDEbkI3a9J1YfbmyXweOfmRwaNfwhc3XEridzrKKRKrbxGtiFExHwruJ8iyotZ1ACKdPuXBPr7KRQB98O2YlVEzKYsB1uvClUfpvONIfa+u54OZ+H2aPj1amEK4D+IA7WmhCfxmDJliZg5KC5h4oOsAMoMwhTL6OFyHOdUnN7KXKxS4qPtVL9PruSJaC9xIEAudFbLINWUug3KuDzbJD+8Vt9g54PoXphwE0IIrvlFRdil4Mr1GeFRFpRE0NlGwR7waqbpTOoTrPrLXjocEKExXAMlW2KRwKs6cpGO9ae+PaBTKf9GDpYBlDK6xMOsLtGEBo7wfNfrTSxKWw7qi8kgjAgMBAAECggEAKcUIb6CN8EgUqJ7Ptd2+JDB4/TPYm/0UL3QLHFH/llTX/X6vRTLEsD/lfZcC435T3fwx/xXInFpv8Ff7LicSTT7YQFvjZk04LYvtCM0xPpAce/FLRDFX+pvGFD3MYUYa4BOviEPFmhb5kuVEVuJhFnmnS/oHDQ5PHrI9kUlWwK4YkT62+jYfbIrbGIzc9oSNSIJ+OXUSkjYmtby0zG/jiYpb6/2MefCI/X/QANu//R42cAHFBlysT0KD8/y6lxxtZ76GxMnpSBPJq9Tvngzi0mp51jj0nj3e7ee/X2qsY7+hWyQqPp7hcaS+m9vq2Td3/yB+eeVkzTyk1nO1gHwdgQKBgQD64J6Zxe5W3j7yUjA9s8CPScH4+axNzTwcPb/LmTDMPTC9VxODqQMEEJTRAwHQDz0d60y2uLF3SIZHvjP71xJWry760F6SfjT5CIDGtEzpchcKUF4vyDfv1h8JwvjdjRquFhxaAY/JXLW+sUtmB7S5vuBU1f1bhZZGOXnBpAviLQKBgQDIcQlZKn8InQNOPcrD2C1SWYDdceRHJ4LWqURZrZTGrVxjEolpqAFi8EAliYMtCTyBvKfqxsPgAKs4JcH+fDPX+Fbq8x9J+eCLq887HRLrk9eXoLuBdMMDl6pvTW9iRtuP8uQaSTEMQiCO/x2IvgEZxDlOs0DgNd9gvBEHBs5VjwKBgCLlc6o4GfsDVwYl4If0pOhJfi2/rPP1hFL5U+BiIqOGL21m21QJAl5iYBDitjHWrM2omTchYa4R7Hu2PUzekbJ1E7fXnBAMdhnd0OvS0I/4SrQokbFbzEwUIKUe9bb7laZ5dOAgL3v25WDtEGvUzpK3tkSWr3M3lbuW6xTAWNbRAoGARltHCMFd7cwPSPtvnObYobtA/HnpwwAfcPHhSAkh28smTrBHA4sxUWU7XvGx1bEUSAXMeyBhyNLzRrYaLhWyrPBCsh28sd6/7sbT6s/9wCsY1eRZbMtrWGt4K7Fmk3yDvTdo0cE3MjJT812hJEptYHn8E5/f+dNvISliYLEG5AkCgYEArjxb/XdiTThXwpD9HcXSEbeDKgOYqu9gSX84IU6JVh9n+xkz9wzW2Il5BaI+ICjPfDuK0aDEfX2zL2kkKuQ7CMI8fe/iJmSPR94TT5M8OUmGDIru1MYw1rVbHZmUxaR7IiuOUrIjtBPXDkXaRKoXHplktG/OcEivQtcz+Y32CDE=";
        String PublicKeyBase64 = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxG5CN2vSdWH25sl8Hjn5kcGjX8IXN1xK4nc6yikSq28RrYhRMR8K7ifIsqLWdQAinT7lwT6+ykUAffDtmJVRMymLAdbrwpVH6bzjSH2vrueDmfh9mj49WphCuA/iAO1poQn8ZgyZYmYOSguYeKDrADKDMIUy+jhchznVJzeylysUuKj7VS/T67kiWgvcSBALnRWyyDVlLoNyrg82yQ/vFbfYOeD6F6YcBNCCK75RUXYpeDK9RnhURaURNDZRsEe8Gqm6UzqE6z6y146HBChMVwDJVtikcCrOnKRjvWnvj2gUyn/Rg6WAZQyusTDrC7RhAaO8HzX600sSlsO6ovJIIwIDAQAB";

        RSA rsa = new RSA(PrivateKeyHex, PublicKeyHex);

        //公钥加密
        byte[] encrypt = rsa.encrypt(data, KeyType.PublicKey);
        System.out.println("加密：" + StrUtil.str(encrypt, CharsetUtil.CHARSET_UTF_8));
        //私钥解密
        byte[] decrypt = rsa.decrypt(encrypt, KeyType.PrivateKey);
        System.out.println("解密：" + StrUtil.str(decrypt, CharsetUtil.CHARSET_UTF_8));

        //密文：前端公钥加密的密文
        String str = "FOZNHZkRpfl6MUIQVJ6ZUX/16sG+8yEZpdd54G8p5+VpSAZQyKqtU72k9v4grHDyD3/cxew3b9wTO1oMvyHuieg68lngdK8YlJMP4jyY4IJHIgsp8IoLEielz+m4rMK5ASxaeYbRdU0bIZ3qkioE4XfEYPJQdKdsOOyZJKjehDwcI7ZOaPqXVB6c50pQOK9pCtimNaQOXL+1FLOlVBbOUGbvanzBdBmWGHYz3DerbScQBR8rC4viHPLXlhQhjZuaWOkhYKsroYzox3rl65d5o4dH8u8Zr3uXC+Px6KPOLhpXBDy6ini0JgTKc07i84nW96OAuBnuP3GRg6EaNODJ7g==";

        //可用
        byte[] decrypt2 = rsa.decrypt(str, KeyType.PrivateKey);
        System.out.println("前端加密后解密结果：" + StrUtil.utf8Str(decrypt2));
    }

    /**
     * 密钥对生成：国密算法SM2
     */
    @Test
    public void test_key_sm2() {
        SM2 sm2 = SmUtil.sm2();
        //密钥对
        PrivateKey privateKey = sm2.getPrivateKey();
        PublicKey publicKey = sm2.getPublicKey();

        System.out.println("SM2");
        //Base64 密钥对
        System.out.println("---Base64---");
        String privateKeyBase64 = Base64.encode(privateKey.getEncoded());
        String publicKeyBase64 = Base64.encode(publicKey.getEncoded());
        System.out.println("privateKeyBase64：" +privateKeyBase64);
        System.out.println("publicKeyBase64：" +publicKeyBase64);

        //十六进制密钥对
        System.out.println("---Hex---");
        String privateKeyHex = Hex.toHexString(((BCECPublicKey) publicKey).getQ().getEncoded(false));
        String publicKeyHex = ((BCECPrivateKey) privateKey).getD().toString(16);
        System.out.println("privateKeyHex：" +privateKeyHex);
        System.out.println("publicKeyHex：" +publicKeyHex);
    }

    /**
     * 密钥对生成：RSA算法
     */
    @Test
    public void test_key_rsa() {
        RSA rsa = new RSA();
        //密钥对
        PrivateKey privateKey = rsa.getPrivateKey();
        PublicKey publicKey = rsa.getPublicKey();

        System.out.println("RSA");
        //Base64 密钥对
        System.out.println("---Base64---");
        String privateKeyBase64 = Base64.encode(privateKey.getEncoded());
        String publicKeyBase64 = Base64.encode(publicKey.getEncoded());
        System.out.println("privateKeyBase64：" +privateKeyBase64);
        System.out.println("publicKeyBase64：" +publicKeyBase64);

        //十六进制密钥对
        System.out.println("---Hex---");
        String privateKeyHex = Hex.toHexString(privateKey.getEncoded());
        String publicKeyHex = Hex.toHexString(publicKey.getEncoded());
        System.out.println("privateKeyHex：" +privateKeyHex);
        System.out.println("publicKeyHex：" +publicKeyHex);
    }

}
