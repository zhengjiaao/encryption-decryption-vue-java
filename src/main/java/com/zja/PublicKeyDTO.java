/**
 * @Company: 上海数慧系统技术有限公司
 * @Department: 数据中心
 * @Author: 郑家骜[ào]
 * @Email: zhengja@dist.com.cn
 * @Date: 2021-11-11 9:51
 * @Since:
 */
package com.zja;

import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.Getter;

import java.io.Serializable;

/**
 * 提供前端的公钥
 */
@Getter
@ApiModel("公钥")
public class PublicKeyDTO implements Serializable {

    public PublicKeyDTO() {
    }

    /**
     * 设置公钥
     * @param keyType 密钥类型
     * @param publicKey 公钥 一般是Base64编码或十六进制
     * @param publicKeyFormat
     * @param keyIsDynamic
     */
    public PublicKeyDTO(String keyType, String publicKey, String publicKeyFormat, boolean keyIsDynamic) {
        this.keyType = keyType;
        this.publicKey = publicKey;
        this.publicKeyFormat = publicKeyFormat;
        this.keyIsDynamic = keyIsDynamic;
    }

    /**
     * 密钥类型：支持 RSA、SM2等
     * 作用：前端根据密钥类型判断加密方式，由后台配置动态切换加解密 例 RSA
     */
    @ApiModelProperty("密钥格式类型 如：RSA、SM2等")
    private String keyType;

    /**
     * 密钥对 是否动态变化
     * 若为true 密钥对是动态变化的，每次前端加密都需要从新获取公钥
     * 若为false，前端可以将公钥缓存至本地，后台一般不会变动密钥对，注意，更换服务器，或重新部署后台密钥对可能会变动
     */
    @ApiModelProperty("密钥对状态，若为true 密钥对是动态变化的，每次前端加密都需要从新获取公钥")
    private boolean keyIsDynamic;

    /**
     * Base64编码原因：源公钥中可能有特殊字符，tomcat会忽略特殊字符
     * 例：前端获取Base64编码的公钥，再通过Base64解码获取到真正的公钥，通过公钥进行加密明文字符串
     */
    @ApiModelProperty("公钥-Base64编码或Hex十六进制的密钥")
    private String publicKey;

    /**
     * 公钥格式：Hex或Base64
     */
    @ApiModelProperty("公钥格式-标识Base64编码或Hex十六进制的公钥")
    private String publicKeyFormat;

}
