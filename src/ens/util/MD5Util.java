package ens.util;


import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import ens.base.HexStringUtil;
import ens.base.Util;
import ens.constant.EncryptConstant;

/**
 * MD5加密
 *
 * @author LeoDys E-mail:changwen.sun@inossem.com 2020/4/23 10:38
 * @version 1.0.8
 * @since 1.0.8
 */

public class MD5Util {
    /**
     * MD5加密
     *
     * @param data 数据
     * @return MD5加密的十六进制字符串
     */
    public static String encryptMD5ToString(final String data) throws Throwable {
        if (Util.isEmpty(data)) {
            return "";
        }
        return encryptMD5ToString(data.getBytes(EncryptConstant.ENCODING));
    }

    /**
     * MD5加盐加密
     *
     * @param data 数据
     * @param salt 盐值 防止系统底层权限反查
     *             <a>https://www.cnblogs.com/yangyi9343/p/5775743.html</a>
     * @return MD5加密的十六进制字符串
     */
    public static String encryptMD5ToString(final String data, final String salt) throws Throwable {
        if (data == null && salt == null) {
            return "";
        }
        if (salt == null) {
            return HexStringUtil.bytes2HexString(encryptMD5(data.getBytes(EncryptConstant.ENCODING)));
        }
        if (data == null) {
            return HexStringUtil.bytes2HexString(encryptMD5(salt.getBytes(EncryptConstant.ENCODING)));
        }
        return HexStringUtil.bytes2HexString(encryptMD5((data + salt).getBytes(EncryptConstant.ENCODING)));
    }

    /**
     * MD5加密
     *
     * @param data 数据
     * @return MD5加密的十六进制字符串
     */
    public static String encryptMD5ToString(final byte[] data) throws Throwable {
        return HexStringUtil.bytes2HexString(encryptMD5(data));
    }

    /**
     * MD5加盐加密
     *
     * @param data 数据
     * @param salt 盐值 防止系统底层权限反查
     * @return MD5加密的十六进制字符串
     */
    public static String encryptMD5ToString(final byte[] data, final byte[] salt) throws Throwable {
        if (data == null && salt == null) {
            return "";
        }
        if (salt == null) {
            return HexStringUtil.bytes2HexString(encryptMD5(data));
        }
        if (data == null) {
            return HexStringUtil.bytes2HexString(encryptMD5(salt));
        }
        byte[] dataSalt = new byte[data.length + salt.length];
        System.arraycopy(data, 0, dataSalt, 0, data.length);
        System.arraycopy(salt, 0, dataSalt, data.length, salt.length);
        return HexStringUtil.bytes2HexString(encryptMD5(dataSalt));
    }


    /**
     * MD5加密
     *
     * @param data 数据
     * @return MD5加密的十六进制字符串
     */
    public static byte[] encryptMD5(final byte[] data) throws Throwable {
        return Util.hashTemplate(data, "MD5");
    }

    /**
     * 返回文件MD5加密的十六进制字符串
     *
     * @param filePath 文件的路径
     * @return 文件MD5加密的十六进制字符串
     */
    public static String encryptMD5File2String(final String filePath) {
        File file = Util.isSpace(filePath) ? null : new File(filePath);
        return encryptMD5File2String(file);
    }

    /**
     * MD5加密
     *
     * @param filePath 文件的路径
     * @return 文件MD5加密的byte[]
     */
    public static byte[] encryptMD5File(final String filePath) {
        File file = Util.isSpace(filePath) ? null : new File(filePath);
        return encryptMD5File(file);
    }

    /**
     * MD5加密
     *
     * @param file 文件
     * @return 文件MD5加密的十六进制字符串
     */
    public static String encryptMD5File2String(final File file) {
        return HexStringUtil.bytes2HexString(encryptMD5File(file));
    }

    /**
     * MD5加密
     *
     * @param file 文件
     * @return 文件MD5加密的byte[]
     */
    public static byte[] encryptMD5File(final File file) {
        if (file == null) {
            return null;
        }
        FileInputStream fis = null;
        DigestInputStream digestInputStream;
        try {
            fis = new FileInputStream(file);
            MessageDigest md = MessageDigest.getInstance("MD5");
            digestInputStream = new DigestInputStream(fis, md);
            byte[] buffer = new byte[256 * 1024];
            while (true) {
                if (digestInputStream.read(buffer) <= 0) {
                    break;
                }
            }
            md = digestInputStream.getMessageDigest();
            return md.digest();
        } catch (NoSuchAlgorithmException | IOException e) {
            e.printStackTrace();
            return null;
        } finally {
            try {
                if (fis != null) {
                    fis.close();
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }
}
