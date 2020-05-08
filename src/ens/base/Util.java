package ens.base;

import com.sun.istack.internal.Nullable;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * base加密
 *
 * @author LeoDys E-mail:changwen.sun@inossem.com 2020/4/23 10:38
 * @version 1.0.8
 * @since 1.0.8
 */

public class Util {
    public static boolean isSpace(final String s) {
        if (s == null) {
            return true;
        }
        for (int i = 0, len = s.length(); i < len; ++i) {
            if (!Character.isWhitespace(s.charAt(i))) {
                return false;
            }
        }
        return true;
    }

    public static boolean isEmpty(@Nullable CharSequence str) {
        return str == null || str.length() == 0;
    }

    /**
     * 哈希加密
     *
     * @param data      数据
     * @param algorithm 哈希加密的名称
     * @return 哈希加密的byte[]
     */
    public static byte[] hashTemplate(final byte[] data, final String algorithm) throws Throwable {
        if (data == null || data.length <= 0) {
            return null;
        }
        MessageDigest md = MessageDigest.getInstance(algorithm);
        md.update(data);
        return md.digest();
    }

    /**
     * 对称加密或解密的byte[] 用于DES和AES使用
     *
     * @param isEncrypt True是加密,False是解密.
     * @return 对称加密或解密的byte[]
     */
    public static byte[] symmetricTemplate(final byte[] data, final byte[] key, final String algorithm,
                                           final String transformation, final byte[] iv, final boolean isEncrypt) throws Throwable {
        if (data == null || data.length == 0 || key == null || key.length == 0) {
            return null;
        }
        SecretKey secretKey;
        if ("DES".equals(algorithm)) {
            // DES
            DESKeySpec desKey = new DESKeySpec(key);
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(algorithm);
            secretKey = keyFactory.generateSecret(desKey);
        } else {
            // AES
            secretKey = new SecretKeySpec(key, algorithm);
        }
        Cipher cipher = Cipher.getInstance(transformation);
        if (iv == null || iv.length == 0) {
            cipher.init(isEncrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE, secretKey);
        } else {
            AlgorithmParameterSpec params = new IvParameterSpec(iv);
            cipher.init(isEncrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE, secretKey, params);
        }
        return cipher.doFinal(data);
    }

    /**
     * 获取加密iv向量
     *
     * @return iv向量
     */
    public static byte[] getIv() {
        byte[] iv = new byte[16];
        SecureRandom r = new SecureRandom();//{@link SecureRandom 随机数类}
        r.nextBytes(iv);//{@link SecureRandom#nextBytes(byte[])}生成用户指定的随机byte}
        IvParameterSpec spec = new IvParameterSpec(iv);
        return spec.getIV();
    }

}
