/*
*******************************************************************************
*  This file is part of the
*  
*  de.fac2 - FIDO U2F Authenticator Applet v1.0
*  copyright (c) 2017 Tobias Senger
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
*******************************************************************************
*/

package de.tsenger.u2f;

import com.gieseckedevrient.javacard.libraries.genericcrypto.GenericCryptoFactory;
import com.gieseckedevrient.javacard.libraries.securemessaging.GDKeyAgreement;
import com.gieseckedevrient.javacard.libraries.security.Security;

import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.ECKey;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyAgreement;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.MessageDigest;
import javacard.security.RandomData;
import javacard.security.Signature;;

/**
 * @author Tobias Senger
 * @version 1.34
 *
 */
public class FIDOCCImplementation {

    private static KeyPair keyPair;
    private static AESKey kdfSeed;
    private static AESKey macKey;
    private static RandomData random;
    private static byte[] scratch;    
    private static KeyAgreement ecMultiplyHelper;
    private static Signature kdFunction;
    private static Signature macFunction;
    
    private static AESKey inputBlindingBlock;
    private static MessageDigest blindingSHA;



    /**
     *  constructor for FIDO crypto functions. Following steps will be performed during instantiation:
     * <ul>
  	 *		<li> 
  	 *		initialize random number generator (DRNG according SP800-90A (DRG.4)) 
     * 		</li>
     * 		<li>
	 *		initialize transient byte array as buffer for different operations
	 *		</li>
	 *		<li>
	 *		initialize {@link KeyPair} for storing deviated FIDO keys 
	 *		</li>
	 *		<li>
	 *		initialize  {@link AESKey} object for seed used in KDF 
	 *		</li>
	 *		<li>
	 *		get CMAC {@link Signature} instance for KDF 
	 *		</li>
	 *		<li>
	 *		initialize {@link AESKey} object for MACKey used for MAC
	 *		</li>
	 *		<li>
	 *		get CMAC {@link Signature} instance for MAC
	 *		</li>
	 *		<li>
	 *		get {@link GDKeyAgreement} instance for EC point multiplication used for FIDO public key generation
	 *		</li>
	 *		<li>
	 *		initialize {@link AESKey} object for storing input blinding block
	 *		</li>
	 *		<li>
	 *		get {@link MessageDigest} instance with algorithm {@link GenericCryptoFactory#ALG_SEC_SHA256} for secure SHA256 output blinding
	 *		</li>
	 * </ul>
     */
    public FIDOCCImplementation() {
    	
    	random = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM); // DRNG according SP800-90A (DRG.4)
    	
        scratch = JCSystem.makeTransientByteArray((short)128, JCSystem.CLEAR_ON_DESELECT);
        
        keyPair = new KeyPair(
            (ECPublicKey)KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, KeyBuilder.LENGTH_EC_FP_256, false),
            (ECPrivateKey)KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, KeyBuilder.LENGTH_EC_FP_256, false));
        Secp256r1.setCommonCurveParameters((ECKey)keyPair.getPrivate());
        Secp256r1.setCommonCurveParameters((ECKey)keyPair.getPublic());
                
        
        // Initialize the unique seed for KDF function       
        kdfSeed = (AESKey)KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);

        // CMAC Signature instance for KDF
        kdFunction = GenericCryptoFactory.getSignatureInstance(MessageDigest.ALG_NULL, Signature.SIG_CIPHER_AES_MAC128, GenericCryptoFactory.PAD_CMAC, false);
        
        // Initialize the unique key for MAC function
        macKey = (AESKey)KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);

        // CMAC Signature instance for MAC
        macFunction = GenericCryptoFactory.getSignatureInstance(MessageDigest.ALG_NULL, Signature.SIG_CIPHER_AES_MAC128, GenericCryptoFactory.PAD_CMAC, false);

        // Initialize ecMultiplier 
        ecMultiplyHelper = GDKeyAgreement.getInstance(GDKeyAgreement.ALG_EC_SVDP_DH_PLAIN_XY, false);  
       
        // One 16 Byte block (stored in AESKey object) for input blinding
        inputBlindingBlock =  (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
        
        // Secure SHA256 for output blinding 
        blindingSHA = GenericCryptoFactory.getMessageDigestInstance(GenericCryptoFactory.ALG_SEC_SHA256, false);

    }
    
    
	/**
	 * Initialize KDF Seed Key, the MAC key and the inputBlindingBlock.
	 * Only initialize the keys if the given actual state is {@value States#DELIVERY_STATE}. Otherwise doesn't touch any keys. 
	 * The keys are generated by filling the key objects with random data from platforms TRNG using the function {@link RandomData#generateData(byte[], short, short)}.
	 * After setting the random key values into the key objects the transients scratch which was used as temporary key buffer is cleared by filling it with zeros using the method
	 * {@link Security#arrayFill(Object, short, short, short)}
	 * The key generation and clearing of the scratch is a transaction which will be perform complete or canceled (no keys are touched) if any unexpected error occurs.
	 * 
	 * @param actualState expects the actual security state of the applet (from class States)
	 * @return new security state, {@value States#READY_FOR_USE} if successful initialized keys otherwise the given actual state (parameter actualState)
	 */
	public short initializeKeys(short actualState) {
		
		if (actualState == States.DELIVERY_STATE) {
			
			JCSystem.beginTransaction();
			
			random.generateData(scratch, (short) 0, (short) 48);
			
			// set KDF seed
			kdfSeed.setKey(scratch, (short) 0);			
			kdFunction.init(kdfSeed, Signature.MODE_SIGN);

			// Set MAC key
			macKey.setKey(scratch, (short) 16);
			macFunction.init(macKey, Signature.MODE_SIGN);
			
			// Save secret input blinding Block in AESKey object
			inputBlindingBlock.setKey(scratch, (short) 32);

			Security.arrayFill(scratch, (short)0, (short)48, Security.FILL_ZEROES);
			short newState = States.READY_FOR_USE;
			
			JCSystem.commitTransaction();
			
			return newState;
			
		} else
			return actualState;
	}
	
    
	/**
	 * Clears the KDF seed key and the MAC key and the inputBlindingBlock
	 * This method will only clear the keys if the actual state is {@value States#READY_FOR_USE}. Otherwise the keys keeps untouched.
	 * The clearing of the keys is performed one transaction by using the platforms method {@link AESKey#clearKey()}. If all keys are cleared this method will return the new state {@value States#DELIVERY_STATE}
	 * @param actualState actualState expects the actual security state of the applet. Only clears keys if given actual state is {@value States#READY_FOR_USE}
	 * @return new security state, {@value States#DELIVERY_STATE} if successful cleared keys otherwise the given actual state (parameter actualState)
	 */
	public short eraseKeys(short actualState) {
		if (actualState == States.READY_FOR_USE) {
			
			JCSystem.beginTransaction();
				kdfSeed.clearKey();
				macKey.clearKey();
				inputBlindingBlock.clearKey();
				short newState = States.DELIVERY_STATE; 
			JCSystem.commitTransaction();
			
			return newState;

		} else
			return actualState;
	}
	
	
	/**
	 * Generates FIDO User Public Key and FIDO KeyHandle with the given parameters
	 * This method will first generate 32 byte nonce for the keyHandle by using {@link RandomData#generateData(byte[], short, short)}. Then the FIDO EC private key will be generated by calling the method {@link #generatePrivateKey(byte[], short, byte[], short, ECPrivateKey)}
	 * with the generate nonce and the parameter applicationParameter as input. The returned FIDO EC private key will be used to generate the FIDO EC public key by calling the method {@link #generatePublicKeyPoint(ECPrivateKey, byte[], short)}
	 * After generating the public key, the private key will be securely cleared by using method {@link AESKey#clearKey()}. Then the MAC over the applicationParameter and the nonce will be generated by calling the 
	 * method {@link #calcMAC(byte[], short, byte[], short, byte[], short)}. The returned key handle is the nonce and the MAC over applicationParameter and nonce.
	 * 
     * @param applicationParameter byte array that contains concatenated 32 bytes application parameter as specified in FIDO U2F Raw Message Formats 
     * @param applicationParameterOffset offset in byte array where applicationParamter starts
     * @param publicKey byte array that returns the FIDO User Public Key 
     * @param publicKeyOffset offset in byte array where FIDO User Public Key starts
     * @param keyHandle byte array that returns the FIDO key handle
     * @param keyHandleOffset offset in byte array where FIDO key handle starts
     * @return key handle length (fixed length 64)
     */
    public short getPubKeyAndKeyHandle(byte[] applicationParameter, short applicationParameterOffset, byte[] publicKey, short publicKeyOffset, byte[] keyHandle, short keyHandleOffset) {
        //KeyHandle is 32 bytes nonce and 32 bytes MAC over AppId and nonce. So lets first fill the nonce:
    	random.generateData(keyHandle, keyHandleOffset, (short) 32);
    	        	
    	//Generate Private Key 
    	generatePrivateKey(applicationParameter, applicationParameterOffset, keyHandle, keyHandleOffset, (ECPrivateKey)keyPair.getPrivate());

    	//Generate Public Key
    	generatePublicKeyPoint((ECPrivateKey)keyPair.getPrivate(), publicKey, publicKeyOffset);
    	
    	// erase Private Key
    	keyPair.getPrivate().clearKey();
    	
    	calcMAC(applicationParameter, applicationParameterOffset, keyHandle, keyHandleOffset, scratch, (short) 96);
    	Util.arrayCopyNonAtomic(scratch, (short) 96, keyHandle, (short) (keyHandleOffset + 32), (short) 32);
        
        return (short)64;
    }
    

    /**
     * Generates the FIDO private key with the given parameters. KDF will be only executed if MAC verifies.
     * This method will first check if the MAC in key KeyHandle is correct by calculating the MAC over applicationParameter and nonce with method {@link #calcMAC(byte[], short, byte[], short, byte[], short)}.
     * Then the given MAC is compared with the calculated MAC by using the method {@link Security#secureCompare(Object, short, Object, short, short)}. Only if the MACs are equal the FIDO EC private key is generate by 
     * calling method {@link #generatePrivateKey(byte[], short, byte[], short, ECPrivateKey)} with the given applicationParameter and the nonce from the given keyHandle. 
     * The private key will be returned to the calling method in parameter regeneratedPrivateKey
     * @param keyHandle byte array that keeps the FIDO key handle
     * @param keyHandleOffset offset in byte array where FIDO key handle starts
     * @param keyHandleLength length of key handle
     * @param applicationParameter byte array that contains 32 bytes application parameter as specified in FIDO U2F Raw Message Formats 
     * @param applicationParameterOffset offset in byte array where applicationParamter starts
     * @param regeneratedPrivateKey ECPrivateKey object will be filled with the calculated FIDO EC private key
     * @return returns false if MAC couldn't verified. Then the private EC will not be calculated. Otherwise true will be returned and regeneratedPrivateKey will be filled.
     */
    public short getSigningKey(byte[] keyHandle, short keyHandleOffset, short keyHandleLength, byte[] applicationParameter, short applicationParameterOffset, ECPrivateKey regeneratedPrivateKey) {
    	
    	short returnValue = Bool.TRUE;
    	short macLen = calcMAC(applicationParameter, applicationParameterOffset, keyHandle, keyHandleOffset, scratch, (short) 96);
    	
    	//add some random delay 
    	Security.randomDelay(Security.RANDOM_DELAY_MEDIUM);
    	
    	//Compare MAC
    	if (Security.secureCompare(scratch,(short) 96, keyHandle, (short)(keyHandleOffset+32), macLen)==Security.SECURE_COMPARE_NOT_EQUAL) {
    		returnValue = Bool.FALSE;
    	}
    	
    	//additional security check of MAC compare 
    	if  (returnValue == Bool.TRUE) {
    		Security.checkLastOperation(Security.OPERATION_SECURITY_SECURE_COMPARE, (short) 96, (short)(keyHandleOffset+32),macLen, Security.SECURE_COMPARE_EQUAL, Security.ACTION_MUTE);
    	}
    	else if (returnValue == Bool.FALSE) {
        	Security.checkLastOperation(Security.OPERATION_SECURITY_SECURE_COMPARE, (short) 96, (short)(keyHandleOffset+32),macLen, Security.SECURE_COMPARE_NOT_EQUAL, Security.ACTION_MUTE);
        }
    	
    	//only get key if signing is required
        if (returnValue == Bool.TRUE && regeneratedPrivateKey != null) {
        	//Regenerate PrivKey 
        	generatePrivateKey(applicationParameter, applicationParameterOffset, keyHandle, keyHandleOffset, regeneratedPrivateKey);        	
        }
        
        return returnValue;
    }
		
    
    /**
	 * Generate Public Key from given Private Key. 
	 * This function uses the the {@link KeyAgreement#generateSecret(byte[], short, short, byte[], short)} method using {@link GDKeyAgreement#ALG_EC_SVDP_DH_PLAIN_XY} for getting public key to the given private key.
	 * 
	 * @param privKey Private Key object
	 * @param pointOutputBuffer Output buffer for Public Key as uncompressed EC point
	 * @param offset Offset in the output buffer where Public key begins
	 * @return Length size of generated Public Key
	 */
	private short generatePublicKeyPoint(ECPrivateKey privKey, byte[] pointOutputBuffer, short offset){
		ecMultiplyHelper.init(privKey);
		return ecMultiplyHelper.generateSecret(Secp256r1.SECP256R1_G, (short) 0, (short) 65, pointOutputBuffer, offset);
	}
	

	/**
	 * Generates a private ECDSA Key (on curve secp256r1) based on on the given input parameters applicationParameter and nonce. 
	 * This method uses the method {@link Signature#sign(byte[], short, short, byte[], short)} initialized with {@link Signature#SIG_CIPHER_AES_MAC128} for key derivation. 
	 * The first input block for AES CMAC will be blinded with a secret {@link #inputBlindingBlock} to avoid known plaintext attacks to the AES engine. 
	 * To get 32 byte EC private key from AES 128 CMAC (which will only return 16 Byte) we will use two rounds of CMAC with different counter as additional input which is 
	 * know as KDF in counter method.
	 * 
	 * @param applicationParameter byte array with AppID data from relaying party
	 * @param applicationParameterOffset offset in byte array where AppID data starts
	 * @param nonceBuffer byte array with nonce 
	 * @param nonceBufferOffset offset in byte array where nonce start
	 * @param privKey expects an initialized (set curve parameter) ECPrivateKey object and fills this object with the secret key component S 
	 */
	private void generatePrivateKey(byte[] applicationParameter, short applicationParameterOffset, byte[] nonceBuffer, short nonceBufferOffset, ECPrivateKey privKey) {
		
		Util.arrayCopy(applicationParameter, applicationParameterOffset, scratch, (short) 0, (short)  32);
		Util.arrayCopy(nonceBuffer, nonceBufferOffset, scratch, (short) 32, (short) 32); // First 32 byte in KeyHandle are nonce
				
		Secp256r1.setCommonCurveParameters(privKey);		

		Security.enterSensitiveSection(Security.CONFIDENTIALITY);
		
		//Set counter for KDF counter mode
		Util.arrayFillNonAtomic(scratch, (short)64, (short)16, (byte)0);
		scratch[79] = (byte)0x31;
		
		inputBlindingBlock.getKey(scratch, (short)80);
		kdFunction.update(scratch, (short)80, (short)16);
		
		//Get first 16 bytes for EC private key
		kdFunction.sign(scratch, (short) 0, (short) 80, scratch, (short) 96); 
				
		kdFunction.update(scratch, (short)80, (short)16);
		Security.arrayFill(scratch, (short)80, (short)16, Security.FILL_ZEROES);
		
		//Set counter for KDF counter mode
		Util.arrayFillNonAtomic(scratch, (short)64, (short)16, (byte)0);
		scratch[79] = (byte)0x52;
		
		//Get second 16 bytes for EC private key
		kdFunction.sign(scratch, (short) 0, (short) 80, scratch, (short) 112); 
		
		
		//set private key bytes to secure store
		privKey.setS(scratch, (short) 96, (short) 32);
		
		//clear private keys bytes in scratch
		Security.arrayFill(scratch, (short)96, (short)32, Security.FILL_ZEROES);
		
		Security.exitSensitiveSection();
	}
	
    
    /**
     * Calculates 32 Byte MAC over given applicationParameter and given nonce. 
     * This method uses the method {@link Signature#sign(byte[], short, short, byte[], short)} initialized with {@link Signature#SIG_CIPHER_AES_MAC128} for MAC calculation. 
	 * The first input block for AES CMAC will be blinded with a secret {@link #inputBlindingBlock} to avoid known plaintext attacks to the AES engine. 
	 * To get 32 byte MAC from AES 128 CMAC (which will only return 16 Byte) we will use two rounds of CMAC with different counter as additional input which is 
	 * know as KDF in counter method. The 32 Byte MAC will post processed by calculating the SHA256 value of this MAC to avoid know cipher text attacks to the AES engine.
	 * A secure SHA256 implementation is used by calling method {@link MessageDigest#doFinal(byte[], short, short, byte[], short)} initialized with {@link GenericCryptoFactory#ALG_SEC_SHA256} 
	 * 
     * @param applicationParameter array that stores the application parameter (AppID)
     * @param applicationParameterOffset offset in array where application parameter (AppID) starts
     * @param nonceBuffer array that stores the nonce
     * @param nonceBufferOffset offset in array where nonce starts
     * @param mac array to store the result
     * @param macOffset offset in array where result shall starts
     * @return size of MAC in bytes (always 32)
     */
    private short calcMAC(byte[] applicationParameter, short applicationParameterOffset, byte[] nonceBuffer, short nonceBufferOffset, byte[] mac, short macOffset) {
				
    	Util.arrayCopyNonAtomic(applicationParameter, applicationParameterOffset, scratch, (short) 0, (short)  32);
    	//blinder.blindIt(inputBlindingKey, applicationParameter, applicationParameterOffset, scratch, (short) 0);
		Util.arrayCopyNonAtomic(nonceBuffer, nonceBufferOffset, scratch, (short) 32, (short) 32); 
		
		Security.enterSensitiveSection(Security.INTEGRITY);
		
		/////// First CMAC ///////////
		
		//Set counter for KDF counter mode
		Util.arrayFillNonAtomic(scratch, (short)64, (short)16, (byte)0);
		scratch[79] = (byte)0xA6;
		
		//First input block of AES-CMAC should be unknown to possible attacker 
		inputBlindingBlock.getKey(scratch, (short)80);
		macFunction.update(scratch, (short)80, (short)16);
				
		//Get first 16 bytes for MAC
		macFunction.sign(scratch, (short) 0, (short) 80, mac, macOffset);  
		
		/////// Second CMAC ///////////
		
		//First input block of AES-CMAC should be unknown to possible attacker 
		macFunction.update(scratch, (short)80, (short)16);
		Security.arrayFill(scratch, (short)80, (short)16, Security.FILL_ZEROES); //clear inputBlindingBlock in scratch
				
		//Set counter for KDF counter mode
		Util.arrayFillNonAtomic(scratch, (short)64, (short)16, (byte)0);
		scratch[79] = (byte)0xAC;
			
		//Get second 16 bytes for MAC
		macFunction.sign(scratch, (short) 0, (short) 80, mac, (short) (macOffset+16)); 
		
		// blind last AES-CMAC cipher output to be unknown to possible attacker by using secure SHA256
		blindingSHA.doFinal(mac, (short) 0, (short)32 , mac, (short) 0);
		
		Security.exitSensitiveSection();

		return (short)32;
	}
    
    

  

}