package it.marco.tfalib;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.MultiFormatWriter;
import com.google.zxing.WriterException;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import it.marco.tfalib.codes.TOTP;
import org.apache.commons.codec.binary.Base32;
import org.apache.commons.codec.binary.Hex;

import java.awt.image.BufferedImage;
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
     * Generates a secret key encoded in Base32 format.
     * @param numCharacters The desired length of the generated key in characters.
     * @return A randomly generated Base32 encoded secret key of the specified length.
     *
     * The total size in bytes is calculated as: ceil((numCharacters * 5) / 8).
     */
    public String generateSecretKey(int numCharacters) {
        int numBytes = (int) Math.ceil((numCharacters * 5) / 8.0);
        SecureRandom secureRandom = new SecureRandom();
        byte[] buffer = new byte[numBytes];
        secureRandom.nextBytes(buffer);

        Base32 codec = new Base32();
        return codec.encodeToString(buffer).replace("=", "").substring(0, numCharacters);
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
     * Generates a simple QR code image based on the provided key.
     * The key is encoded into a QR code format, which is then converted into a BufferedImage.
     *
     * @param key the text (usually a secret or URL) to encode into the QR code
     * @param size the size of the qrcode
     * @return a BufferedImage representing the generated QR code, or null if the encoding fails
     */
    public static BufferedImage generateSimpleQRCode(String key, int size) {
        try {
            BitMatrix matrix = new MultiFormatWriter().encode(key, BarcodeFormat.QR_CODE, size, size);
            return MatrixToImageWriter.toBufferedImage(matrix);
        } catch (WriterException e) {
            e.printStackTrace();
            return null;
        }
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
