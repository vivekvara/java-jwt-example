package com.jwtdemo;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URISyntaxException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.text.ParseException;
import java.util.Date;
import java.util.UUID;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.io.pem.PemReader;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;

public class JWTRS256JWEEncryDemo
{

	public static void main(String args[]) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException, URISyntaxException, NoSuchProviderException, JOSEException, ParseException, CertificateException
	{
		String id = UUID.randomUUID().toString();
		String issuer = "JWT Issuer";
		String subject = "Test JWT";
		int ttlMillis = 3600;

		JWTRS256JWEEncryDemo jwtrs256Demo = new JWTRS256JWEEncryDemo();
		jwtrs256Demo.testJWTWithRsa(id, issuer, subject, ttlMillis);
	}

	public void testJWTWithRsa(String id, String issuer, String subject, long ttlMillis) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException, URISyntaxException, NoSuchProviderException, JOSEException, ParseException, CertificateException
	{
		Security.addProvider(new BouncyCastleProvider());

		KeyFactory keyFactory = KeyFactory.getInstance("RSA", "BC");

		CertificateFactory f = CertificateFactory.getInstance("X.509");
		X509Certificate certificate = (X509Certificate) f.generateCertificate(new FileInputStream(ClassLoader.getSystemResource("kub.cer").toURI().getPath()));
		RSAPublicKey publicKey = (RSAPublicKey) certificate.getPublicKey();

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

		PemReader pemReader = new PemReader(new InputStreamReader(new FileInputStream(ClassLoader.getSystemResource("kub.key").getPath())));
		PKCS8EncodedKeySpec ks = new PKCS8EncodedKeySpec(pemReader.readPemObject().getContent());
		pemReader.close();
		PrivateKey privateKey = keyFactory.generatePrivate(ks);

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
