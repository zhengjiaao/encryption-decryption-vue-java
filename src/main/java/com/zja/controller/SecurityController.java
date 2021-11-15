/**
 * @Company: 上海数慧系统技术有限公司
 * @Department: 数据中心
 * @Author: 郑家骜[ào]
 * @Email: zhengja@dist.com.cn
 * @Date: 2021-11-12 16:21
 * @Since:
 */
package com.zja.controller;

import com.zja.security.AbstractEncrypt;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * http://localhost:18082/swagger-ui/index.html#/
 */
@Api(tags = {"安全服务-密钥管理"})
@RestController
@RequestMapping
public class SecurityController {

    @Autowired
    private AbstractEncrypt abstractEncrypt;

    @ApiOperation(value = "获取非对称公钥 V1", notes = "支持前端动态切换加密方式")
    @GetMapping(value = "/publickey/v1")
    public Object getPublicKeyV2() {
        return abstractEncrypt.getPublicKeyInfo();
    }

    @ApiOperation(value = "服务端通过公钥加密-内测接口")
    @GetMapping(value = "/encrypt/v1")
    public Object encryptV1(@ApiParam("明文字符串") @RequestParam String data) {
        return abstractEncrypt.encrypt(data);
    }

    @ApiOperation(value = "服务端通过公钥加密-内测接口")
    @GetMapping(value = "/encrypt/v2")
    public Object encryptV2(@ApiParam("明文字符串") @RequestParam String data,
                            @ApiParam("公钥 格式支持 Base64、Hex") @RequestParam String publicKey) {
        return abstractEncrypt.encrypt(data, publicKey);
    }

    @ApiOperation(value = "服务端通过私钥解密-内测接口", notes = "RSA 密文中存在'/'特殊符号，使用@PathVariable注解会出现问题")
    @GetMapping(value = "/decrypt/v1")
    public Object decryptV1(@ApiParam("密文字符串") @RequestParam String data) {
        return abstractEncrypt.decrypt(data);
    }

    @ApiOperation(value = "服务端通过私钥解密-内测接口", notes = "RSA 密文中存在'/'特殊符号，使用@PathVariable注解会出现问题")
    @GetMapping(value = "/decrypt/v2")
    public Object decryptV2(@ApiParam("密文字符串") @RequestParam String data,
                            @ApiParam("私钥 格式支持 Base64、Hex") @RequestParam String privateKey) {
        return abstractEncrypt.decrypt(data, privateKey);
    }
}
