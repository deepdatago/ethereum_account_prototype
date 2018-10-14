package com.example.tnnd.messageexchange;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;

public interface KeyManager {
	/**
	 * Generate PrivateKey and Certificate 
	 *
	 * @param  privKeyFileName  output file name of private key 
	 * @param  publicKeyFileName  output file name of public key 
	 * @param  certFileName output file name of certificate, could be null
	 * @return      None
	 */	
	public void generateKeyCertificate(String privKeyFileName, String publicKeyFileName, String certFileName);
	
	/**
	 * Generate public key from a RSA X.509 certificate file 
	 *
	 * @param  certFileName input file name of certificate
	 * @return      PublicKey
	 */	
	public PublicKey loadPublicKeyFromRSA_X509_CertificatePEM(String certFileName) 
			throws IOException, NoSuchProviderException, NoSuchAlgorithmException;

	/**
	 * Generate private key from a RSA PEM file 
	 *
	 * @param  privateKeyFileName input file name of private key
	 * @return      PrivateKey
	 */		
	public PrivateKey loadPrivateKeyFromRSAPEM(String privateKeyFileName) 
			throws IOException, NoSuchProviderException, NoSuchAlgorithmException;
	
	/**
	 * Generate public key from a RSA public key PEM file
	 *
	 * @param  fileName  input file name of a public key 
	 * @return      PublicKey
	 */		
	public PublicKey loadPublicKeyFromRSAPEM(String fileName) throws
		FileNotFoundException,
		IOException,
		NoSuchAlgorithmException,
		NoSuchProviderException,
		InvalidKeySpecException;

	/**
	 * Generate public key from a RSA public key PEM string format
	 *
	 * @param  publicKeyStr  public key as String
	 * @return      PublicKey
	 */
	public PublicKey loadPublicKeyFromRSAPEMString(String publicKeyStr);

	/**
	 * Encrypt a byte[] with given public key, and encode it with Base64
	 *
	 * @param  text input byte[] from text that needs to be encrypted
	 * @param  key public key that is used to encrypt the given byte[]
	 * @return      Base64 encoded string of encrypted byte[]
	 */	
    public String encryptTextBase64(byte[] text, PublicKey key) throws Exception;

	/**
	 * Decrypt a byte[] which is Base64 encoded with given private key
	 *
	 * @param  text input byte[] that is Base64 encoded, which needs to be decrypted
	 * @param  key private key that is used to decrypt the given byte[]
	 * @return      Plain text of the encrypted byte[]
	 */	    
    public String decryptTextBase64(byte[] text, PrivateKey key) throws Exception;

	/**
	 * Decrypt a byte[] which is Base64 encoded with given private key
	 *
	 * @param  keyFileName file name for the public/private key
	 * @return      Plain text of the content of the key file
	 */
	public String getKeyPEM(String keyFileName);

}
