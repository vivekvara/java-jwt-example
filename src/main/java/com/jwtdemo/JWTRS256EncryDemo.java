package com.jwtdemo;

import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.text.ParseException;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;

public class JWTRS256EncryDemo
{

	public static void main(String args[]) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException, URISyntaxException, NoSuchProviderException, JOSEException, ParseException
	{
		String id = UUID.randomUUID().toString();
		String issuer = "JWT Issuer";
		String subject = "Test JWT";
		int ttlMillis = 3600;

		JWTRS256EncryDemo jwtrs256Demo = new JWTRS256EncryDemo();
		jwtrs256Demo.testJWTWithRsa(id, issuer, subject, ttlMillis);
	}

	public void testJWTWithRsa(String id, String issuer, String subject, long ttlMillis) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException, URISyntaxException, NoSuchProviderException, JOSEException, ParseException
	{
		Security.addProvider(new BouncyCastleProvider());

		KeyFactory kf = KeyFactory.getInstance("RSA", "BC");

		String publicKeyContent = new String(Files.readAllBytes(Paths.get(ClassLoader.getSystemResource("public_key.pem").toURI())));
		publicKeyContent = publicKeyContent.replaceAll("\\n", "").replace("-----BEGIN PUBLIC KEY-----", "").replace("-----END PUBLIC KEY-----", "");
		X509EncodedKeySpec keySpecX509 = new X509EncodedKeySpec(Base64.getDecoder().decode(publicKeyContent));
		RSAPublicKey publicKey = (RSAPublicKey) kf.generatePublic(keySpecX509);

		long nowMillis = System.currentTimeMillis();
		Date now = new Date(nowMillis);

		// Compose the JWT claims set
		JWTClaimsSet jwtClaims = new JWTClaimsSet.Builder()
				.issueTime(now)
				.subject(subject)
				.issuer(issuer)
				.expirationTime(new Date(System.currentTimeMillis() + ttlMillis))
				.jwtID(id)
				.build();
		System.out.println("################ SIGNED JWT #######################");
		System.out.println("JWT Claims  : " + jwtClaims.toJSONObject());

		// Request JWT encrypted with RSA-OAEP-256 and 128-bit AES/GCM
		JWEHeader header = new JWEHeader(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A128GCM);

		// Create the encrypted JWT object
		EncryptedJWT jwt = new EncryptedJWT(header, jwtClaims);

		// Create an encrypter with the specified public RSA key
		RSAEncrypter encrypter = new RSAEncrypter(publicKey);

		// Do the actual encryption
		jwt.encrypt(encrypter);

		// Serialise to JWT compact form
		String jwtToken = jwt.serialize();
		System.out.println("JWT Token  : " + jwtToken);
		System.out.println("\n\n\n");

		String privateKeyContent = new String(Files.readAllBytes(Paths.get(ClassLoader.getSystemResource("private_key_pkcs8.pem").toURI())));
		privateKeyContent = privateKeyContent.replaceAll("\\n", "").replace("-----BEGIN PRIVATE KEY-----", "").replace("-----END PRIVATE KEY-----", "");
		PKCS8EncodedKeySpec keySpecPKCS8 = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKeyContent));
		PrivateKey privateKey = kf.generatePrivate(keySpecPKCS8);

		// Parse back
		jwt = EncryptedJWT.parse(jwtToken);

		// Create a decrypter with the specified private RSA key
		RSADecrypter decrypter = new RSADecrypter(privateKey);

		// Decrypt
		jwt.decrypt(decrypter);

		JWTClaimsSet claimsJws = jwt.getJWTClaimsSet();
		System.out.println("################ PARSED JWT #######################");
		System.out.println("Header     : " + jwt.getHeader().toString());
		System.out.println("Body       : " + claimsJws.toJSONObject());
	}
}
