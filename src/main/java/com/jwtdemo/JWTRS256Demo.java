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
import java.util.Base64;
import java.util.Date;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

public class JWTRS256Demo
{

	public static void main(String args[]) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException, URISyntaxException, NoSuchProviderException
	{
		String id = "ANYID1234-IFREQUIRED";
		String issuer = "JWT Issuer";
		String subject = "Test JWT";
		int ttlMillis = 3600;

		JWTRS256Demo jwtrs256Demo = new JWTRS256Demo();
		jwtrs256Demo.testJWTWithRsa(id, issuer, subject, ttlMillis);
	}

	public void testJWTWithRsa(String id, String issuer, String subject, long ttlMillis) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException, URISyntaxException, NoSuchProviderException
	{
		Security.addProvider(new BouncyCastleProvider());

		KeyFactory kf = KeyFactory.getInstance("RSA", "BC");

		String privateKeyContent = new String(Files.readAllBytes(Paths.get(ClassLoader.getSystemResource("private_key_pkcs8.pem").toURI())));
		privateKeyContent = privateKeyContent.replaceAll("\\n", "").replace("-----BEGIN PRIVATE KEY-----", "").replace("-----END PRIVATE KEY-----", "");
		PKCS8EncodedKeySpec keySpecPKCS8 = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKeyContent));
		PrivateKey privateKey = kf.generatePrivate(keySpecPKCS8);

		String publicKeyContent = new String(Files.readAllBytes(Paths.get(ClassLoader.getSystemResource("public_key.pem").toURI())));
		publicKeyContent = publicKeyContent.replaceAll("\\n", "").replace("-----BEGIN PUBLIC KEY-----", "").replace("-----END PUBLIC KEY-----", "");
		X509EncodedKeySpec keySpecX509 = new X509EncodedKeySpec(Base64.getDecoder().decode(publicKeyContent));
		RSAPublicKey publicKey = (RSAPublicKey) kf.generatePublic(keySpecX509);

		long nowMillis = System.currentTimeMillis();
		Date now = new Date(nowMillis);

		String jwtToken = Jwts.builder().setId(id)
				.setIssuedAt(now)
				.setSubject(subject)
				.setIssuer(issuer)
				.setExpiration(new Date(System.currentTimeMillis() + ttlMillis))
				.signWith(SignatureAlgorithm.RS256, privateKey).compact();
		System.out.println("################ SIGNED JWT #######################");
		System.out.println("JWT Token  : " + jwtToken);
		System.out.println("\n\n\n");

		Jws<Claims> claimsJws = Jwts.parser()
				.setSigningKey(publicKey)
				.parseClaimsJws(jwtToken);
		System.out.println("################ PARSED JWT #######################");
		System.out.println("Header     : " + claimsJws.getHeader());
		System.out.println("Body       : " + claimsJws.getBody());
		System.out.println("Signature  : " + claimsJws.getSignature());
	}
}
