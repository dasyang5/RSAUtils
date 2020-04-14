package pers.alex.utils.rsa.rsa;

import javax.servlet.http.HttpSession;
import java.security.KeyPair;
import java.security.PrivateKey;

/**
 * @author Alex
 * @date 4/13/2020 5:28 PM
 */
public class RSASessionUtil {

    public static final String SESSION_KEY_NAME = "MY_RSA_PRIVATE_KEY";

    public static String getPublicKey(HttpSession session) {

        KeyPair keyPair = RSAUtil.generateKeyPair();

        session.setAttribute(SESSION_KEY_NAME, keyPair.getPrivate());

        return RSAUtil.getKeyString(keyPair.getPublic());
    }

    public static PrivateKey getPrivateKey(HttpSession session) {

        return (PrivateKey) session.getAttribute(SESSION_KEY_NAME);

    }

}
