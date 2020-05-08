package ens.util;

import java.security.KeyFactory;
import java.security.SecureRandom;

import ens.base.HexStringUtil;
import ens.base.Util;

/**
 * DES加密\解密
 *
 * @author LeoDys E-mail:changwen.sun@inossem.com 2020/4/23 10:49
 * @version 1.0.8
 * @since 1.0.8
 */

public class DESUtil {

    //以下为加密


    /**
     * DES加密 转为十六进制返回
     *
     * @param key 需要为8位 密钥
     * @param iv  需要为8位 向量iv,可增加加密算法的强度
     * @return DES加密的十六进制字符串
     */
    public static String encryptDES2HexString(final byte[] data, final byte[] key, final String transformation, final byte[] iv) throws Throwable {
        return HexStringUtil.bytes2HexString(encryptDES(data, key, transformation, iv));
    }

    /**
     * @param data           数据 需要为8位
     * @param key            密钥 需要为8位
     * @param transformation 块加密的模式以及数据填充
     *                       <p>样例"DES/CBC/PKCS5Padding"
     *                       Cipher加密器初始化需要一个字符串,字符串里提供了三种设置.
     *                       <p>一是,加解密算法;二是,加解密模式;三是,是否需要填充.
     *                       <p>
     *                       <p>第二个参数是:
     *                       ECB(电码本模式),CBC(加密块链模式),OFB(输出反馈模式),CFB(加密反馈模式){@link // KeyProperties}
     *                       {@link // KeyGenerator} {@link // KeyPairGenerator}都是javax.crypto包的，生成的key主要是提供给AES，DES，3DES，MD5，SHA1等 对称 和 单向 加密算法
     *                       {@link KeyFactory}{@link // SecretKeyFactory}都是java.security包的，生成的key主要是提供给DSA，RSA， EC等 非对称加密算法
     *                       ECB模式简单,缺点是块加密的内容容易重复,会被统计分析攻击;
     *                       CBC,OFB,CFB三个模式,都是根据前面加密块的内容,对key进行新一轮处理后再,再对下一数据块进行处理,如此类推下去,这样一来,加密的强度也有所增强.
     *                       他们都需要用到初始化向量IV,英文是Initialization Vector的缩写.
     *                       <p>
     *                       <p>第三个参数是:
     *                       ZeroPadding,数据长度不对齐时使用0填充,否则不填充.
     *                       PKCS7Padding,假设数据长度需要填充n(n>0)个字节才对齐,那么填充n个字节,每个字节都是n;如果数据本身就已经对齐了,则填充一块长度为块大小的数据,每个字节都是块大小.
     *                       PKCS5Padding,PKCS7Padding的子集,块大小固定为8字节.
     *                       DES为快加密,只能使用PKCS5Padding.
     *                       <a>https://blog.csdn.net/qq_18870023/article/details/52180768</a>
     * @param iv             使用CBC,OFB,CFB三个模式,需要一个向量iv,可增加加密算法的强度
     *                       <p>
     *                       <p>样例
     *                       byte[] iv = new byte[16];
     *                       SecureRandom r = new SecureRandom();{@link SecureRandom 随机数类}
     *                       r.nextBytes(iv);{@link SecureRandom#nextBytes(byte[])}生成用户指定的随机byte}
     *                       IvParameterSpec iv = new IvParameterSpec(iv);
     *                       System.out.println(iv.getIV());
     *                       <p>
     *                       <p>错误样例
     *                       IvParameterSpec iv = new IvParameterSpec("1234567890123456".getBytes());不要写""固定值
     *                       <p>
     *                       <p>修复建议:
     *                       禁止使用常量初始化矢量参数构建IvParameterSpec
     * @return DES加密的base64编码byte[]
     */
    public static byte[] encryptDES(final byte[] data, final byte[] key, final String transformation, final byte[] iv) throws Throwable {
        return Util.symmetricTemplate(data, key, "DES", transformation, iv, true);
    }

    /**
     * DES加密 转为base64返回
     *
     * @param key 需要为8位 密钥
     * @param iv  需要为8位 向量iv,可增加加密算法的强度
     * @return DES加密的base64字符串
     */
    public static byte[] encryptDES2Base64(final byte[] data, final byte[] key, final String transformation, final byte[] iv) throws Throwable {
        return Base64Util.base64Encode(encryptDES(data, key, transformation, iv));
    }

    //以下为解密


    /**
     * DES解密
     *
     * @param key 需要为8位
     * @param iv  需要为8位
     * @return DES解密的byte[]
     */
    public static byte[] decryptDES(final byte[] data, final byte[] key, final String transformation, final byte[] iv) throws Throwable {
        return Util.symmetricTemplate(data, key, "DES", transformation, iv, false);
    }

    /**
     * DES解密
     *
     * @param key 需要为8位
     * @param iv  需要为8位
     * @return 使用了base64编码的DES解密byte[]
     */
    public static byte[] decryptBase64DES(final byte[] data, final byte[] key, final String transformation, final byte[] iv) throws Throwable {
        return decryptDES(Base64Util.base64Decode(data), key, transformation, iv);
    }

    /**
     * DES解密
     *
     * @param key 需要为8位
     * @param iv  需要为8位
     * @return 十六进制字符串的DES解密byte[]
     */
    public static byte[] decryptHexStringDES(final String data, final byte[] key, final String transformation, final byte[] iv) throws Throwable {
        return decryptDES(HexStringUtil.hexString2Bytes(data), key, transformation, iv);
    }

}
