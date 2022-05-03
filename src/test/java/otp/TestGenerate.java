
package otp;

import org.testng.Assert;
import org.testng.annotations.Test;

public class TestGenerate {
	@Test
	private void generate() throws Exception {
		Authentication auth = new Authentication();
		String sampleSecret="WP5QU24YKAJWHADLDMZTYMQVHR7VLDAX";
		int period = 30;
		int digits = 6;
		String authCode = auth.GoogleAuthenticatorCode(sampleSecret, period, digits);
		Assert.assertNotNull(authCode);
		Assert.assertEquals(authCode.length(),6);
	}
}