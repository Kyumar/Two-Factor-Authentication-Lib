package it.marco.tfalib;

import it.marco.tfalib.codes.TOTP;
import org.apache.commons.codec.binary.Base32;
import org.apache.commons.codec.binary.Hex;

import java.security.SecureRandom;

public class TFALib {
    /**
     * totp declaration
     */
    private final TOTP totp;

    /**
     * instantiate TOTP
     */
    public TFALib(){
        totp = new TOTP();
    }

    /**
     * Generate a secretKey codificated by String base32
     * @param size number of bits user to encode a single character
     * @return secretKey generated.
     *
     * Total size (in Bytes) = ((number of bits used to encode a single character) * (number of characters))/8
     */
    public String generateSecretKey(int size) {
        SecureRandom secureRandom = new SecureRandom();
        /*
          buffer = (number of bits used to encode a single character) * (number of characters)) / 8
          using ASCII encoding
          need 8 bits to encode each character, number of bits to encode a char = 8
         */
        byte[] buffer = new byte[(size * 8) / 8];
        secureRandom.nextBytes(buffer);
        Base32 codec = new Base32();
        return new String(codec.encode(buffer));
    }

    /**
     * get secretkey's code.
     * @param secretKey
     * @return actually code generated for secretKey (param)
     */
    public String getCode(String secretKey) {
        Base32 base32 = new Base32();
        byte[] bytes = base32.decode(secretKey);
        String hexKey = Hex.encodeHexString(bytes);
        return totp.getOTP(hexKey);
    }

    /**
     *
     * @param actCode
     * @return if the actCode (param) it's the same of the code of secretkey'code
     */
    public boolean compareCode(String key, String actCode) {
        String code = getCode(key);
        return code.equals(actCode);
    }
}
