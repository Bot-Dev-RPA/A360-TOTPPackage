package otp;

import org.apache.commons.codec.binary.Hex;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.util.Date;
import java.util.concurrent.TimeUnit;

public class Authentication {

	public Authentication() {};

	private String truncateHash(byte[] hash,int hashLength) {
		String hashString = new String(hash);
		int offset = Integer.parseInt(hashString.substring(hashString.length() - 1), 16);

		String truncatedHash = hashString.substring(offset * 2, offset * 2 + 8);

		int val = Integer.parseUnsignedInt(truncatedHash, 16) & 0x7FFFFFFF;

		String finalHash = String.valueOf(val);
		finalHash = finalHash.substring(finalHash.length() - hashLength);

		return finalHash;
	}

	private byte[] hmacSha1(byte[] value, byte[] keyBytes) {
		SecretKeySpec signKey = new SecretKeySpec(keyBytes, "HmacSHA1");
		try {
			Mac mac = Mac.getInstance("HmacSHA1");

			mac.init(signKey);

			byte[] rawHmac = mac.doFinal(value);

			return new Hex().encode(rawHmac);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	public String GoogleAuthenticatorCode(String secret, int duration ,int hashLength) throws Exception {
		if (secret == null || secret.equals("")) {
			throw new Exception("Secret key does not exist.");
		}
		long value = new Date().getTime() / TimeUnit.SECONDS.toMillis(duration);

		Base32 base = new Base32(Base32.Alphabet.BASE32, false, true);
		byte[] key = base.fromString(secret);

		byte[] data = new byte[8];
		for (int i = 8; i-- > 0; value >>>= 8) {
			data[i] = (byte) value;
		}

		byte[] hash = hmacSha1(data, key);

		return truncateHash(hash,hashLength);
	}

}
