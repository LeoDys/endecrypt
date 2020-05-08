package com.dongang.endecrypt;

import com.dongang.endecrypt.util.*;

import java.util.Map;

/**
 * 测试类
 *
 * @author LeoDys E-mail:changwen.sun@inossem.com 2020/4/23 11:16
 * @version 1.0.8
 * @since 1.0.8
 */

public class TestMain {

    public static final String ENCODE_STR = "我要加密!@#123./abc";


    /*DES常量*/
    public static final String DES_TRANSFORMATION = "DES/CBC/PKCS5Padding";
    public static final String DES_ENCODE_KEY = "abcd0000abcd0000";// 必须为8或8的整数倍位数
    public static final String DES_IV = "DES_IV00";     // 必须为8位

    /*AES常量*/
    public static final String AES_TRANSFORMATION = "AES/CBC/PKCS5Padding";
    public static final String ES_ENCODE_KEY = "abcd0000ABCD1111abcd0000ABCD1111";// 必须是16位或16的整数倍数位
    public static final String AES_IV = "AES_IV00ABCD1111";     // 必须是16位


    public static void main(String[] args) throws Throwable {
//        testMD5();
        testBase64();
//        testDES();
//        test3DES();
//        testAES();
//        testRSA();
    }

    /**
     * 3DES测试
     */
    private static void test3DES() {
        String encrypt = DES3Util.encrypt(ENCODE_STR, DES_ENCODE_KEY);
        System.out.println("3DES加密结果:" + encrypt);

        String decrypt = DES3Util.decrypt(encrypt, DES_ENCODE_KEY);
        System.out.println("3DES解密结果:" + decrypt);
    }

    /**
     * RSA测试
     */
    private static void testRSA() throws Throwable {
        // 获取公钥和私钥
        Map<String, Object> keyMap = RSAUtil.genKeyPair();
        String publicKey = RSAUtil.getPublicKey(keyMap);
        String privateKey = RSAUtil.getPrivateKey(keyMap);

        System.out.println("==============publicKey===============");
        System.out.println(publicKey);
        System.out.println("==============privateKey===============");
        System.out.println(privateKey);

        /*下面是公钥加密  私钥解密*/
        System.out.println("=====================公钥加密  私钥解密===========================");
        // 加密
        byte[] encryptBytes = RSAUtil.encryptByPublicKey(ENCODE_STR.getBytes(), publicKey);
        String encode = "";
        for (byte bytesDE : encryptBytes) {
            encode += (bytesDE + ",");
        }
        System.out.println("公钥加密结果:" + encode);
        // 解密
        byte[] decryptBytes = RSAUtil.decryptByPrivateKey(encryptBytes, privateKey);
        System.out.println("私钥解密结果:" + new String(decryptBytes));

        /*下面是私钥加密  公钥解密*/
        System.out.println("=====================私钥加密  公钥解密===========================");
        // 加密
        byte[] encryptBytes2 = RSAUtil.encryptByPrivateKey(ENCODE_STR.getBytes(), privateKey);
        String encode2 = "";
        for (byte bytesDE : encryptBytes2) {
            encode2 += (bytesDE + ",");
        }
        System.out.println("私钥加密结果:" + encode2);
        // 解密
        byte[] decryptBytes2 = RSAUtil.decryptByPublicKey(encryptBytes2, publicKey);
        System.out.println("公钥解密结果:" + new String(decryptBytes2));

    }

    /**
     * AES测试
     */
    private static void testAES() throws Throwable {
        // 加密
        byte[] bytesDES = AESUtil.encryptAES(ENCODE_STR.getBytes(), ES_ENCODE_KEY.getBytes(), AES_TRANSFORMATION, AES_IV.getBytes());
        String encode = "";
        for (byte bytesDE : bytesDES) {
            encode += (bytesDE + ",");
        }
        System.out.println("AES加密:" + encode);

        // 解密
        byte[] bytes = AESUtil.decryptAES(bytesDES, ES_ENCODE_KEY.getBytes(), AES_TRANSFORMATION, AES_IV.getBytes());
        System.out.println("AES解密:" + new String(bytes));
    }

    /**
     * DES测试
     */
    private static void testDES() throws Throwable {
        // 加密
        byte[] bytesDES = DESUtil.encryptDES(ENCODE_STR.getBytes(), DES_ENCODE_KEY.getBytes(), DES_TRANSFORMATION, DES_IV.getBytes());
        String encode = "";
        for (byte bytesDE : bytesDES) {
            encode += (bytesDE + ",");
        }
        System.out.println("DES加密:" + encode);

        // 解密
        byte[] bytes = DESUtil.decryptDES(bytesDES, DES_ENCODE_KEY.getBytes(), DES_TRANSFORMATION, DES_IV.getBytes());
        System.out.println("DES解密:" + new String(bytes));
    }

    /**
     * Base64测试
     */
    private static void testBase64() throws Exception {
        String str = Base64Util.base64Encode(ENCODE_STR);
        System.out.println("Base64加密:" + str);

        String str1 = Base64Util.base64Decode(str);
        System.out.println("Base64解密:" + str1);

        // 5oiR6KaB5Yqg5a+GIUAjMTIzLi9hYmM=
    }

    /**
     * MD5测试
     */
    private static void testMD5() throws Throwable {
        String bytes = MD5Util.encryptMD5ToString(ENCODE_STR);
        System.out.println("MD5加密:" + bytes);
        // B0A2D64756CDD5D360B9B45A69DBDAB7
        // b0a2d64756cdd5d360b9b45a69dbdab7
    }

}
