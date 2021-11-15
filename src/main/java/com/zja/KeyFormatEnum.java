/**
 * @Company: 上海数慧系统技术有限公司
 * @Department: 数据中心
 * @Author: 郑家骜[ào]
 * @Email: zhengja@dist.com.cn
 * @Date: 2021-11-12 17:44
 * @Since:
 */
package com.zja;

/**
 * 密钥格式
 */
public enum KeyFormatEnum {
    /**
     * 密钥格式为：十六进制 推荐
     * 推荐原因：rsa前端支持 Hex、Base64，但 sm2 仅支持 Hex
     */
    Hex,
    /**
     * 密钥格式为：Base64编码
     */
    Base64
}
