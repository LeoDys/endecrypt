package com.dongang.endecrypt.base;

import com.dongang.endecrypt.constant.EncryptConstant;

/**
 * 十六进制加密\解密
 *
 * @author LeoDys E-mail:changwen.sun@inossem.com 2020/4/23 11:01
 * @version 1.0.8
 * @since 1.0.8
 */

public class HexStringUtil {

    /**
     * 十六进制加密
     *
     * @param hexString 数据
     * @return 加密数据
     */
    public static byte[] hexString2Bytes(String hexString) {
        if (Util.isSpace(hexString)) {
            return null;
        }
        int len = hexString.length();
        if (len % 2 != 0) {
            hexString = "0" + hexString;
            len = len + 1;
        }
        char[] hexBytes = hexString.toUpperCase().toCharArray();
        byte[] ret = new byte[len >> 1];
        for (int i = 0; i < len; i += 2) {
            ret[i >> 1] = (byte) (hex2Dec(hexBytes[i]) << 4 | hex2Dec(hexBytes[i + 1]));
        }
        return ret;
    }

    private static int hex2Dec(final char hexChar) {
        if (hexChar >= '0' && hexChar <= '9') {
            return hexChar - '0';
        } else if (hexChar >= 'A' && hexChar <= 'F') {
            return hexChar - 'A' + 10;
        } else {
            throw new IllegalArgumentException();
        }
    }

    /**
     * 十六进制解密
     *
     * @param bytes 数据
     * @return 解密数据
     */
    public static String bytes2HexString(final byte[] bytes) {
        if (bytes == null) {
            return "";
        }
        int len = bytes.length;
        if (len <= 0) {
            return "";
        }
        char[] ret = new char[len << 1];
        for (int i = 0, j = 0; i < len; i++) {
            ret[j++] = EncryptConstant.HEX_DIGITS[bytes[i] >> 4 & 0x0f];
            ret[j++] = EncryptConstant.HEX_DIGITS[bytes[i] & 0x0f];
        }
        return new String(ret);
    }

}
