package ens.util;

import ens.base.HexStringUtil;
import ens.base.Util;
import ens.constant.EncryptConstant;

/**
 * SHA1加密
 *
 * @author LeoDys E-mail:changwen.sun@inossem.com 2020/4/23 10:44
 * @version 1.0.8
 * @since 1.0.8
 */

public class SHA1Util {
    /**
     * SHA1加密
     *
     * @param data 数据
     * @return SHA1加密的十六进制字符串
     */
    public static String encryptSHA1ToString(final String data) throws Throwable {
        if (Util.isEmpty(data)) {
            return "";
        }
        return encryptSHA1ToString(data.getBytes(EncryptConstant.ENCODING));
    }

    /**
     * SHA1加密
     *
     * @param data 数据
     * @return SHA1加密的十六进制字符串
     */
    private static String encryptSHA1ToString(final byte[] data) throws Throwable {
        return HexStringUtil.bytes2HexString(encryptSHA1(data));
    }

    /**
     * SHA1加密
     *
     * @param data 数据
     * @return SHA1加密的byte[]
     */
    private static byte[] encryptSHA1(final byte[] data) throws Throwable {
        return Util.hashTemplate(data, "SHA-1");
    }

}
