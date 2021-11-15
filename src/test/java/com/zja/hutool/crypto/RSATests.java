/**
 * @Company: 上海数慧系统技术有限公司
 * @Department: 数据中心
 * @Author: 郑家骜[ào]
 * @Email: zhengja@dist.com.cn
 * @Date: 2021-11-09 15:23
 * @Since:
 */
package com.zja.hutool.crypto;

import cn.hutool.core.codec.Base64;
import cn.hutool.core.util.CharsetUtil;
import cn.hutool.core.util.HexUtil;
import cn.hutool.core.util.StrUtil;
import cn.hutool.crypto.asymmetric.KeyType;
import cn.hutool.crypto.asymmetric.RSA;
import org.junit.jupiter.api.Test;
import org.testng.Assert;

import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * RSA 非对称加解密
 */
public class RSATests {

    /**
     * RSA加密和解密: 使用无参构造方法时,自动生成随机的公钥私钥密钥对
     */
    @Test
    public void RSA_1() {
        String data = "pass123";

        //默认 生成随机密钥对
        RSA rsa = new RSA();

        //获得私钥
        PrivateKey privateKey = rsa.getPrivateKey();
        //获得公钥
        PublicKey publicKey = rsa.getPublicKey();

        //Base64编码密钥对
        System.out.println("--------Base64 密钥对-------");
        System.out.println("PrivateKeyBase64：" + rsa.getPrivateKeyBase64());
        System.out.println("PublicKeyBase64：" + rsa.getPublicKeyBase64());

        System.out.println("--------公钥加密，私钥解密-------");
        //公钥加密，私钥解密
        byte[] encrypt = rsa.encrypt(StrUtil.bytes(data, CharsetUtil.CHARSET_UTF_8), KeyType.PublicKey);
        byte[] decrypt = rsa.decrypt(encrypt, KeyType.PrivateKey);
        //Junit单元测试
        Assert.assertEquals(data, StrUtil.str(decrypt, CharsetUtil.CHARSET_UTF_8));
        System.out.println(StrUtil.str(encrypt, CharsetUtil.CHARSET_UTF_8));
        System.out.println(Base64.encode(encrypt));
        System.out.println(StrUtil.str(decrypt, CharsetUtil.CHARSET_UTF_8));

        System.out.println("--------私钥加密，公钥解密-------");
        //私钥加密，公钥解密
        byte[] encrypt2 = rsa.encrypt(StrUtil.bytes(data, CharsetUtil.CHARSET_UTF_8), KeyType.PrivateKey);
        byte[] decrypt2 = rsa.decrypt(encrypt2, KeyType.PublicKey);
        //Junit单元测试
        Assert.assertEquals(data, StrUtil.str(decrypt2, CharsetUtil.CHARSET_UTF_8));
        System.out.println(StrUtil.str(encrypt2, CharsetUtil.CHARSET_UTF_8));
        System.out.println(Base64.encode(encrypt2));
        System.out.println(StrUtil.str(decrypt2, CharsetUtil.CHARSET_UTF_8));
    }


    /**
     * RSA解密：
     */
    @Test
    public void RSA_3() {

        String content = "虎头闯杭州,多抬头看天,切勿只管种地";

        String PRIVATE_KEY = "MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAIL7pbQ+5KKGYRhw7jE31hmA"
                + "f8Q60ybd+xZuRmuO5kOFBRqXGxKTQ9TfQI+aMW+0lw/kibKzaD/EKV91107xE384qOy6IcuBfaR5lv39OcoqNZ"
                + "5l+Dah5ABGnVkBP9fKOFhPgghBknTRo0/rZFGI6Q1UHXb+4atP++LNFlDymJcPAgMBAAECgYBammGb1alndta"
                + "xBmTtLLdveoBmp14p04D8mhkiC33iFKBcLUvvxGg2Vpuc+cbagyu/NZG+R/WDrlgEDUp6861M5BeFN0L9O4hz"
                + "GAEn8xyTE96f8sh4VlRmBOvVdwZqRO+ilkOM96+KL88A9RKdp8V2tna7TM6oI3LHDyf/JBoXaQJBAMcVN7fKlYP"
                + "Skzfh/yZzW2fmC0ZNg/qaW8Oa/wfDxlWjgnS0p/EKWZ8BxjR/d199L3i/KMaGdfpaWbYZLvYENqUCQQCobjsuCW"
                + "nlZhcWajjzpsSuy8/bICVEpUax1fUZ58Mq69CQXfaZemD9Ar4omzuEAAs2/uee3kt3AvCBaeq05NyjAkBme8SwB0iK"
                + "kLcaeGuJlq7CQIkjSrobIqUEf+CzVZPe+AorG+isS+Cw2w/2bHu+G0p5xSYvdH59P0+ZT0N+f9LFAkA6v3Ae56OrI"
                + "wfMhrJksfeKbIaMjNLS9b8JynIaXg9iCiyOHmgkMl5gAbPoH/ULXqSKwzBw5mJ2GW1gBlyaSfV3AkA/RJC+adIjsRGg"
                + "JOkiRjSmPpGv3FOhl9fsBPjupZBEIuoMWOC8GXK/73DHxwmfNmN7C9+sIi4RBcjEeQ5F5FHZ";

        RSA rsa = new RSA(PRIVATE_KEY, null);

        String a = "2707F9FD4288CEF302C972058712F24A5F3EC62C5A14AD2FC59DAB93503AA0FA17113A020EE4EA35EB53F"
                + "75F36564BA1DABAA20F3B90FD39315C30E68FE8A1803B36C29029B23EB612C06ACF3A34BE815074F5EB5AA3A"
                + "C0C8832EC42DA725B4E1C38EF4EA1B85904F8B10B2D62EA782B813229F9090E6F7394E42E6F44494BB8";

        byte[] aByte = HexUtil.decodeHex(a);
        byte[] decrypt = rsa.decrypt(aByte, KeyType.PrivateKey);

        //Junit单元测试
        Assert.assertEquals(content, StrUtil.str(decrypt, CharsetUtil.CHARSET_UTF_8));
        System.out.println(StrUtil.str(decrypt, CharsetUtil.CHARSET_UTF_8));
    }

}
