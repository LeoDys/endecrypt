package com.dongang.endecrypt.util;

import com.dongang.endecrypt.base.HexStringUtil;
import com.dongang.endecrypt.base.Util;

/**
 * @author LeoDys E-mail:changwen.sun@inossem.com 2020/4/23 11:04
 * @version 1.0.8
 * @since 1.0.8
 */

public class AESUtil {

    // 以下为AES加密

    /**
     * AES加密
     *
     * @param key            需要为16位
     * @param iv             需要为16位
     * @param transformation AES/CBC/PKCS5Padding
     * @return AES加密的byte[]
     */
    public static byte[] encryptAES(final byte[] data, final byte[] key, final String transformation, final byte[] iv) throws Throwable {
        return Util.symmetricTemplate(data, key, "AES", transformation, iv, true);
    }

    /**
     * AES加密
     *
     * @param key            需要为16位
     * @param iv             需要为16位
     * @param transformation AES/CBC/PKCS5Padding
     * @return AES加密的base64编码byte[]
     */
    public static byte[] encryptAES2Base64(final byte[] data, final byte[] key, final String transformation, final byte[] iv) throws Throwable {
        return Base64Util.base64Encode(encryptAES(data, key, transformation, iv));
    }

    /**
     * AES加密
     *
     * @param key            需要为16位
     * @param iv             需要为16位
     * @param transformation AES/CBC/PKCS5Padding
     * @return AES加密的十六进制字符串
     */
    public static String encryptAES2HexString(final byte[] data, final byte[] key, final String transformation, final byte[] iv) throws Throwable {
        return HexStringUtil.bytes2HexString(encryptAES(data, key, transformation, iv));
    }

    // 以下为AES解密

    /**
     * AES解密
     *
     * @param key            需要为16位
     * @param iv             需要为16位
     * @param transformation AES/CBC/PKCS5Padding
     * @return AES解密的byte[]
     */
    public static byte[] decryptAES(final byte[] data, final byte[] key, final String transformation, final byte[] iv) throws Throwable {
        return Util.symmetricTemplate(data, key, "AES", transformation, iv, false);
    }

    /**
     * AES解密
     *
     * @param key            需要为16位
     * @param iv             需要为16位
     * @param transformation AES/CBC/PKCS5Padding
     * @return 用于base64编码byte[]的AES解密byte[]
     */
    public static byte[] decryptBase64AES(final byte[] data, final byte[] key, final String transformation, final byte[] iv) throws Throwable {
        return decryptAES(Base64Util.base64Decode(data), key, transformation, iv);
    }

    /**
     * AES解密
     *
     * @param key            需要为16位
     * @param iv             需要为16位
     * @param transformation AES/CBC/PKCS5Padding
     * @return 十六进制字符串的AES解密byte[]
     */
    public static byte[] decryptHexStringAES(final String data, final byte[] key, final String transformation, final byte[] iv) throws Throwable {
        return decryptAES(HexStringUtil.hexString2Bytes(data), key, transformation, iv);
    }

}
