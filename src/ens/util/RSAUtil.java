package ens.util;

import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Cipher;

/**
 * RSA 加密解密 公钥私钥生成
 *
 * @author LeoDys E-mail:changwen.sun@inossem.com 2020/4/23 11:07
 * @version 1.0.8
 * @since 1.0.8
 */

public class RSAUtil {

    // 以下为获取公钥私钥
    public static final String KEY_ALGORITHM = "RSA";
    private static final String PUBLIC_KEY = "RSAPublicKey";
    private static final String PRIVATE_KEY = "RSAPrivateKey";

    // 生成的key的位数
    private static final int KEYSIZE = 1024;
    public static final String RSA_TRANSFORMATION = "RSA/ECB/PKCS1Padding";

    private static final Base64.Encoder encoder = Base64.getEncoder();
    private static final Base64.Decoder decoder = Base64.getDecoder();

    public static Map<String, Object> genKeyPair() throws Exception {
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance(KEY_ALGORITHM);
        keyPairGen.initialize(KEYSIZE);//2048
        KeyPair keyPair = keyPairGen.generateKeyPair();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        Map<String, Object> keyMap = new HashMap<String, Object>(2);
        keyMap.put(PUBLIC_KEY, publicKey);
        keyMap.put(PRIVATE_KEY, privateKey);
        return keyMap;
    }

    //获得公钥
    public static String getPublicKey(Map<String, Object> keyMap) throws Exception {
        //获得map中的公钥对象 转为key对象
        Key key = (Key) keyMap.get(PUBLIC_KEY);
        //byte[] publicKey = key.getEncoded();
        //编码返回字符串
        return encoder.encodeToString(key.getEncoded());
    }

    //获得私钥
    public static String getPrivateKey(Map<String, Object> keyMap) throws Exception {
        //获得map中的私钥对象 转为key对象
        Key key = (Key) keyMap.get(PRIVATE_KEY);
        //byte[] privateKey = key.getEncoded();
        //编码返回字符串
        return encoder.encodeToString(key.getEncoded());
    }

    /**
     * 公钥加密
     *
     * @param data      要加密的数据
     * @param publicKey 公钥
     * @return 加密完成的数据
     * @throws Exception
     */
    public static byte[] encryptByPublicKey(byte[] data, String publicKey) throws Exception {
        try {
            byte[] decodeKey = decoder.decode(publicKey.getBytes());
            KeyFactory mykeyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
            X509EncodedKeySpec pub_spec = new X509EncodedKeySpec(decodeKey);
            PublicKey pubKey = mykeyFactory.generatePublic(pub_spec);
            Cipher cipher = Cipher.getInstance(RSA_TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, pubKey);
            return cipher.doFinal(data);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * 私钥解密
     *
     * @param data       要解密的数据
     * @param privateKey 私钥
     * @return 加密完成的数据
     * @throws Exception
     */
    public static byte[] decryptByPrivateKey(byte[] data, String privateKey) throws Exception {
        try {
            byte[] decodeKey = decoder.decode(privateKey.getBytes());
            PKCS8EncodedKeySpec priv_spec = new PKCS8EncodedKeySpec(decodeKey);
            KeyFactory mykeyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
            PrivateKey privKey = mykeyFactory.generatePrivate(priv_spec);
            Cipher cipher = Cipher.getInstance(RSA_TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, privKey);
            return cipher.doFinal(data);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * 使用RSA私钥加密数据
     *
     * @param privateKey 打包的形式私钥
     * @param data       要加密的数据
     * @return 加密数据
     */
    public static byte[] encryptByPrivateKey(byte[] data, String privateKey) {
        try {
            byte[] decodeKey = decoder.decode(privateKey.getBytes());
            PKCS8EncodedKeySpec priv_spec = new PKCS8EncodedKeySpec(
                    decodeKey);
            KeyFactory mykeyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
            PrivateKey privKey = mykeyFactory.generatePrivate(priv_spec);
            Cipher cipher = Cipher.getInstance(mykeyFactory.getAlgorithm());
            cipher.init(Cipher.ENCRYPT_MODE, privKey);
            return cipher.doFinal(data);
        } catch (Exception e) {
            return null;
        }

    }

    /**
     * 用RSA公钥解密
     *
     * @param publicKey 公钥打包成byte[]形式
     * @param data      要解密的数据
     * @return 解密数据
     */
    public static byte[] decryptByPublicKey(byte[] data, String publicKey) {
        try {
            byte[] decodeKey = decoder.decode(publicKey.getBytes());
            KeyFactory mykeyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
            X509EncodedKeySpec pub_spec = new X509EncodedKeySpec(decodeKey);
            PublicKey pubKey = mykeyFactory.generatePublic(pub_spec);
            Cipher cipher = Cipher.getInstance(mykeyFactory.getAlgorithm());
            cipher.init(Cipher.DECRYPT_MODE, pubKey);
            return cipher.doFinal(data);
        } catch (Exception e) {
            return null;
        }
    }


}
