package com.automationanywhere.botcommand.Actions;

import com.automationanywhere.botcommand.data.impl.StringValue;
import com.automationanywhere.botcommand.exception.BotCommandException;
import com.automationanywhere.commandsdk.annotations.*;
import com.automationanywhere.commandsdk.annotations.rules.CredentialAllowPassword;
import com.automationanywhere.commandsdk.annotations.rules.GreaterThan;
import com.automationanywhere.commandsdk.annotations.rules.NotEmpty;
import com.automationanywhere.commandsdk.annotations.rules.NumberInteger;
import com.automationanywhere.commandsdk.model.DataType;
import com.automationanywhere.core.security.SecureString;
import otp.Authentication;

import static com.automationanywhere.commandsdk.model.AttributeType.CREDENTIAL;
import static com.automationanywhere.commandsdk.model.AttributeType.NUMBER;

//BotCommand makes a class eligible for being considered as an action.
@BotCommand

@CommandPkg(
		name = "TOTP", label = "TOTP Generator",
		node_label = "Generate TOTP and assign to {{returnTo}}", description = "Generate time based one time passwords", icon = "TOTP.svg",comment = true,
		text_color =  "#0c2a7a",
		return_label = "Assign generated token to", return_type = DataType.STRING, return_required = true)
public class GenerateTOTP {
	@Execute
	public StringValue  action(
			@Idx(index = "1", type = CREDENTIAL)
			@Pkg(label = "Enter your secret key", description = "Base32-encoded secret, shared by your provider")
					@NotEmpty
					@CredentialAllowPassword SecureString SecretKey,

			@Idx(index = "2", type = NUMBER)
			@Pkg(label = "Number of digits", description = "Number of digits in token, shared by your provider",default_value = "6",default_value_type = DataType.NUMBER)
			@NotEmpty
			@NumberInteger
			@GreaterThan("0") Double digits,

			@Idx(index = "3", type = NUMBER)
			@Pkg(label = "Period in seconds", description = "Frequency of token refresh, shared by your provider",default_value = "30",default_value_type = DataType.NUMBER)
			@NotEmpty
			@NumberInteger
			@GreaterThan("0") Double period) throws Exception {

		//Internal validation, to disallow empty strings. No null check needed as we have NotEmpty on firstString.
		String secret = SecretKey.getInsecureString();
		if (secret == null || "".equals(secret.trim()))
			throw new BotCommandException("Please select a valid key, provided key is empty");

		Authentication auth = new Authentication();
		String authCode = auth.GoogleAuthenticatorCode(secret, period.intValue(), digits.intValue());

		return new StringValue(authCode);

	}


}
