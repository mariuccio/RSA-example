package com.polytech;


import java.security.*;
import javax.crypto.*;

import java.io.*;

public class SqueletonEntity{

	// keypair
	public PublicKey thePublicKey;
	private PrivateKey thePrivateKey;
	
	/**
	  * Entity Constructor
	  * Public / Private Key generation
	 **/
	public SqueletonEntity(){
		// INITIALIZATION

		// generate a public/private key
		try{
			// get an instance of KeyPairGenerator  for RSA	
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			
			// Initialize the key pair generator for 1024 length
			keyPairGenerator.initialize(1024);
			
			// Generate the key pair
			KeyPair keyPair = keyPairGenerator.genKeyPair();
			
			// save the public/private key
			this.thePrivateKey = keyPair.getPrivate();
			this.thePublicKey = keyPair.getPublic();
			
		}catch(Exception e){
			System.out.println("Signature error");
			e.printStackTrace();
		}
	}

	/**
	  * Sign a message
	  * Parameters
	  * aMessage : byte[] to be signed
	  * Result : signature in byte[] 
	  **/
	public byte[] sign(byte[] aMessage){
		
		try{
			// use of java.security.Signature
			// Init the signature with the private key
			Signature sig = Signature.getInstance("MD5withRSA");
			sig.initSign(thePrivateKey);
			
			// update the message
			sig.update(aMessage);
			
			// sign
			byte[] signatureBytes = sig.sign();
			
			return signatureBytes;
		}catch(Exception e){
			System.out.println("Signature error");
			e.printStackTrace();
			return null;
		}
		
	}
	
	/**
	  * Check aSignature is the signature of aMessage with aPK
	  * Parameters
	  * aMessage : byte[] to be signed
	  * aSignature : byte[] associated to the signature
	  * aPK : a public key used for the message signature
	  * Result : signature true or false
	  **/
	public boolean checkSignature(byte[] aMessage, byte[] aSignature, PublicKey aPK){
		try{
			// use of java.security.Signature
			// init the signature verification with the public key
			Signature sig = Signature.getInstance("MD5withRSA");
			sig.initVerify(aPK);
			
			// update the message
			sig.update(aMessage);
			
			// check the signature
			return (sig.verify(aSignature));
		}catch(Exception e){
			System.out.println("Verify signature error");
			e.printStackTrace();
			return false;
		}
	}
	
	
	/**
	  * Sign a message
	  * Parameters
	  * aMessage : byte[] to be signed
	  * Result : signature in byte[] 
	  **/
	public byte[] mySign(byte[] aMessage){
		
		try{
			// get an instance of a cipher with RSA with ENCRYPT_MODE
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.ENCRYPT_MODE, thePrivateKey);
			
			// Init the signature with the private key
			//Signature sig = Signature.getInstance("MD5withRSA");
			//sig.initSign(thePrivateKey);
			
			// get an instance of the java.security.MessageDigest with MD5
			MessageDigest md5 = MessageDigest.getInstance("MD5");
			
			// process the digest
		    byte[] msgDigest = md5.digest(aMessage);
		    
			// return the encrypted digest
		    byte[] ciphered = cipher.doFinal(msgDigest);
			return ciphered;
			
		}catch(Exception e){
			System.out.println("Signature error");
			e.printStackTrace();
			return null;
		}
		
	}
	
	/**
	  * Check aSignature is the signature of aMessage with aPK
	  * Parameters
	  * aMessage : byte[] to be signed
	  * aSignature : byte[] associated to the signature
	  * aPK : a public key used for the message signature
	  * Result : signature true or false
	  **/
	public boolean myCheckSignature(byte[] aMessage, byte[] aSignature, PublicKey aPK){
		try{
			// get an instance of a cipher with RSA with DECRYPT_MODE
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.DECRYPT_MODE, aPK);
			
			// decrypt the signature
			byte[] deciphered = cipher.doFinal(aSignature);
			
			// get an instance of the java.security.MessageDigest with MD5
			MessageDigest md5 = MessageDigest.getInstance("MD5");
			
			// process the digest
			md5.update(aMessage);
            byte[] msgDigest = md5.digest();
			
			// check if digest1 == digest2
            return (deciphered.equals(msgDigest));

		}catch(Exception e){
			System.out.println("Verify signature error");
			e.printStackTrace();
			return false;
		}
	}	
	
	
	/**
	  * Encrypt aMessage with aPK
	  * Parameters
	  * aMessage : byte[] to be encrypted
	  * aPK : a public key used for the message encryption
	  * Result : byte[] ciphered message
	  **/
	public byte[] encrypt(byte[] aMessage, PublicKey aPK){
		try{
			// get an instance of RSA Cipher
			Cipher cipher = Cipher.getInstance("RSA");
			
			// init the Cipher in ENCRYPT_MODE and aPK
			cipher.init(Cipher.ENCRYPT_MODE, aPK);
			
			// use doFinal on the byte[] and return the ciphered byte[]
			byte[] ciphered = cipher.doFinal(aMessage);
			
			return ciphered;
			
		}catch(Exception e){
			System.out.println("Encryption error");
			e.printStackTrace();
			return null;
		}
	}

	/**
	  * Decrypt aMessage with the entity private key
	  * Parameters
	  * aMessage : byte[] to be encrypted
	  * Result : byte[] deciphered message
	  **/
	public byte[] decrypt(byte[] aMessage){
		try{
			// get an instance of RSA Cipher
			Cipher cipher = Cipher.getInstance("RSA");
			
			// init the Cipher in DECRYPT_MODE and aPK
			cipher.init(Cipher.DECRYPT_MODE, thePrivateKey);
			
			// use doFinal on the byte[] and return the deciphered byte[]
			byte[] deciphered = cipher.doFinal(aMessage);
			
			return deciphered;
			
		}catch(Exception e){
			System.out.println("Decryption error");
			e.printStackTrace();
			return null;
		}

	}


}