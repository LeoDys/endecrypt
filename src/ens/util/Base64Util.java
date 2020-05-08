package ens.util;


import ens.constant.EncryptConstant;
import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

/**
 * BASE64加密\解密
 *
 * @author LeoDys E-mail:changwen.sun@inossem.com 2020/4/23 10:52
 * @version 1.0.8
 * @since 1.0.8
 */

public class Base64Util {
    /**
     * BASE64加密
     */
    public static byte[] base64Encode(byte[] data) throws Exception {
        return (new BASE64Encoder()).encodeBuffer(data).getBytes(EncryptConstant.ENCODING);
    }

    /**
     * BASE64加密
     */
    public static String base64Encode(String data) throws Exception {
        byte[] bytes = data.getBytes(EncryptConstant.ENCODING);
        return (new BASE64Encoder()).encodeBuffer(bytes);
    }

    /**
     * BASE64解密
     *
     * @throws Exception
     */
    public static String base64Decode(String data) throws Exception {
        return new String((new BASE64Decoder()).decodeBuffer(data));
    }

    /**
     * BASE64解密
     *
     * @throws Exception
     */
    public static byte[] base64Decode(byte[] input) throws Exception {
        String data = new String(input, EncryptConstant.ENCODING);
        return (new BASE64Decoder()).decodeBuffer(data);
    }

    /**
     * java8的base64使用方式
     *
     * @param data
     * @return
     */
//    public static String base64Encode(byte[] data) {
//        Base64.Encoder encoder = Base64.getEncoder();
//        return encoder.encodeToString(data);
//    }

//    public static byte[] base64Decode(String data) {
//        Base64.Decoder decoder = Base64.getDecoder();
//        return decoder.decode(data);
//    }
}
