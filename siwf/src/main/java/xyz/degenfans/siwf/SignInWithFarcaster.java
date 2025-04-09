package xyz.degenfans.siwf;

import java.math.BigInteger;

import org.web3j.crypto.ECDSASignature;
import org.web3j.crypto.Hash;
import org.web3j.crypto.Keys;
import org.web3j.crypto.Sign;
import org.web3j.crypto.Sign.SignatureData;
import org.web3j.utils.Numeric;

public class SignInWithFarcaster {
	
	/**
	 * you have also to verify this address with the fid custody addres:
	 * e.g. https://docs.neynar.com/reference/fetch-bulk-users
	 * @param signature
	 * @param message
	 * @return
	 */
	public static String validateSignatureAndGetAddress(String signature, String message) {
		SignatureData sd = splitSignature(signature);
		return recoverAddress(sd, message);
	}
	public static final String PERSONAL_MESSAGE_PREFIX = "\u0019Ethereum Signed Message:\n";
	public static String recoverAddress(SignatureData signatureData,
			String message) {

		String prefix = PERSONAL_MESSAGE_PREFIX + message.length();
		byte[] digest = Hash.sha3((prefix + message).getBytes());
		int header = 0;
		for (byte b : signatureData.getV()) {
			header = (header << 8) + (b & 0xFF);
		}
		if (header < 27 || header > 34) {
			return null;
		}
		int recId = header - 27;
		BigInteger key = Sign.recoverFromSignature(recId,
				new ECDSASignature(new BigInteger(1, signatureData.getR()),
						new BigInteger(1, signatureData.getS())),
				digest);
		if (key == null) {
			return null;
		}
		return ("0x" + Keys.getAddress(key)).trim();
	}

	private static Sign.SignatureData splitSignature(String signatureHex) {
		// Remove the '0x' prefix if present
		if (signatureHex.startsWith("0x")) {
			signatureHex = signatureHex.substring(2);
		}

		// Signature should be 130 characters long (65 bytes)
		if (signatureHex.length() != 130) {
			throw new IllegalArgumentException("Invalid signature length");
		}

		// Extract r, s, and v
		String rHex = signatureHex.substring(0, 64);
		String sHex = signatureHex.substring(64, 128);
		String vHex = signatureHex.substring(128, 130); // v is usually 1 byte

		// Convert v from hex to int, adding 27 to match the Ethereum signature
		// standard
		int v = Integer.parseInt(vHex, 16);
		if (v < 27) {
			v += 27;
		}

		// Convert r and s from hex to byte arrays
		byte[] r = Numeric.hexStringToByteArray("0x" + rHex);
		byte[] s = Numeric.hexStringToByteArray("0x" + sHex);

		return new Sign.SignatureData(new byte[]{(byte) v}, r, s);
	}
}
