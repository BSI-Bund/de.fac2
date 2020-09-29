/*
*******************************************************************************
*  This file is part of the
*  
*  de.fac2 - FIDO U2F Authenticator Applet
*  copyright (c) 2017 Tobias Senger
*  
*  based on Ledger U2F Applet
*  (c) 2015 Ledger
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

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.ECPrivateKey;
import javacard.security.KeyBuilder;
import javacard.security.Signature;
import javacardx.apdu.ExtendedLength;

/**
 * @author Tobias Senger
 * @version 1.33
 * 
 *
 */
public class U2FApplet extends Applet implements ExtendedLength {
	
	/**
	 * security state can be {@link States#UNINITIALIZED}, {@link States#DELIVERY_STATE} or {@link States#READY_FOR_USE}
	 * @see States
	 */
	private static short securityState;

    /**
     * provide 0x00 for normal operation at installation, or 0x01 to disable user presence check (for automated FIDO interoperability tests)
     * @see #U2FApplet(byte[], short, byte)
     */
    private static byte flags; 
    
    /**
     * counts FIDO signing operations with EC private Key
     */
    private static byte[] fidoSigningCounter;
    
    /**
     * saves status of user presence
     */
    private static byte[] scratchPersistent;
    
    /**
     * working buffer for reading commands, building responses and temporary data
     */
    private static byte[] scratch; 
    
    /**
     * permanent store for the attestation certificate 
     * @see #handleSetAttestationCert(APDU)
     */
    private static byte[] attestationCertificate; 
        
    /**
     * stores the private key of the attestation certificate
     * @see #U2FApplet(byte[], short, byte)
     */
    private static ECPrivateKey attestationPrivateKey;
    
    /**
     * private key for FIDO signing operation
     */
    protected ECPrivateKey localPrivateKey;
    
    /**
     * Saves the state for the signing counter. Set to true if counter exceeds value 0xFFFFFFFF 
     */
    private static boolean counterOverflowed;
    
    /**
     * signature instance for attestation certificate signing
     */
    private static Signature attestationSignature; 
    
    /**
     * signature instance for FIDO signing operation
     */
    private static Signature localSignature;
    
    /**
     * instance of FIDO API crypto implementation, here the pseudo code of FIDO U2F PP gets real ...
     */
    private static FIDOCCImplementation fidoImpl;

    /**
     * fix value to indicate u2f support as defined in FIDO specification "FIDO U2F Raw Message Formats"
     */
    private static final byte VERSION[] = { 'U', '2', 'F', '_', 'V', '2' };

    // Class and Instruction bytes which will be handled in this applet
    private static final byte FIDO_CLA = (byte)0x00; 		// -> FIDO specification "FIDO U2F Raw Message Formats"
    private static final byte FIDO_INS_U2F_REGISTER = (byte)0x01; // -> FIDO specification "FIDO U2F Raw Message Formats"
    private static final byte FIDO_INS_AUTHENTICATE = (byte)0x02;   // -> FIDO specification "FIDO U2F Raw Message Formats"
    private static final byte FIDO_INS_VERSION = (byte)0x03;// -> FIDO specification "FIDO U2F Raw Message Formats"
    private static final byte ISO_INS_GET_RESPONSE = (byte)0xC0;// -> FIDO specification "FIDO U2F Raw Message Formats"
    private static final byte PROPRIETARY_CLA = (byte)0x01; // proprietary class byte used to set attestation certificate
    private static final byte VENDOR_SPECIFIC_SET_ATTESTATION_CERT = (byte)0x09; // proprietary instruction byte used to set attestation certificate
    private static final byte VENDOR_SPECIFIC_RESET = (byte)0x8E; // proprietary instruction byte for resetting the KDF seed and MAC key

    // Offset values to organize "header" of scratch array
    // the first ten bytes are the "header" of the scratch to store information about the data beginning at index 10
    private static final byte SCRATCH_TRANSPORT_STATE = (byte)0; //-> Transport state will be stored at index 0
    private static final byte SCRATCH_CURRENT_OFFSET = (byte)1;  //-> Offset will be stored at index 1
    private static final byte SCRATCH_NONCERT_LENGTH = (byte)3;	 //-> length of data in scratch without length of attestation certificate will be stored at index 3 (and 4)
    private static final byte SCRATCH_INCLUDE_CERT = (byte)5;	 //-> if 0 no attestation certificate will be in response apdu, if 1 certificate will be included in response apdu
    private static final byte SCRATCH_SIGNATURE_LENGTH = (byte)6;//-> Signature length will be stored at index 6 (and 7)
    private static final byte SCRATCH_FULL_LENGTH = (byte)8;	 //-> length of all data in scratch (without header size) + size of attestation certificate will be stored at index 8 (and 9)
    private static final byte SCRATCH_PAD = (byte)10;
    
    // Calculate size of scratch pad
    private static final short ENROLL_FIXED_RESPONSE_SIZE = (short)(1 + 65 + 1);    
    private static final short KEYHANDLE_MAX = (short)64; // Update if you change the KeyHandle encoding implementation
    
    private static final short SIGNATURE_MAX = (short)73; // DER encoding with negative R and S 
    private static final short SCRATCH_PAD_SIZE = (short)(ENROLL_FIXED_RESPONSE_SIZE + KEYHANDLE_MAX + SIGNATURE_MAX); // Should hold 1 (version) + 65 (public key) + 1 (key handle length) + L (key handle) + largest signature
    
    private static final short ENROLL_PUBLIC_KEY_OFFSET = (short)1;
    private static final short ENROLL_KEY_HANDLE_LENGTH_OFFSET = (short)66;
    private static final short ENROLL_KEY_HANDLE_OFFSET = (short)67;
    
    // Offset values to organize scratch array 
    private static final short SCRATCH_PUBLIC_KEY_OFFSET = (short)(SCRATCH_PAD + ENROLL_PUBLIC_KEY_OFFSET);
    private static final short SCRATCH_KEY_HANDLE_LENGTH_OFFSET = (short)(SCRATCH_PAD + ENROLL_KEY_HANDLE_LENGTH_OFFSET);
    private static final short SCRATCH_KEY_HANDLE_OFFSET = (short)(SCRATCH_PAD + ENROLL_KEY_HANDLE_OFFSET);
    private static final short SCRATCH_SIGNATURE_OFFSET = (short)(SCRATCH_PAD + ENROLL_FIXED_RESPONSE_SIZE + KEYHANDLE_MAX);

    // values to save APDU transport state for chaining
    private static final byte TRANSPORT_NONE = (byte)0;
    private static final byte TRANSPORT_EXTENDED = (byte)1;
    private static final byte TRANSPORT_NOT_EXTENDED = (byte)2;
    private static final byte TRANSPORT_NOT_EXTENDED_CERT = (byte)3;
    private static final byte TRANSPORT_NOT_EXTENDED_SIGNATURE = (byte)4;

    // P1 Parameter for FIDO Authentication Request Message - U2F_AUTHENTICATE 
    private static final byte P1_SIGN_CHECK_ONLY = (byte)0x07;
    private static final byte P1_SIGN_ENFORCE_USER_PRESENCE_AND_SIGN = (byte)0x03;
    private static final byte P1_SIGN_DONT_ENFORCE_USER_PRESENCE_AND_SIGN = (byte)0x08;

    /**
     * fix value defined in FIDO specification "FIDO U2F Raw Message Formats"
     */
    private static final byte ENROLL_LEGACY_VERSION = (byte)0x05;
    
    /**
     * fix value defined in FIDO specification "FIDO U2F Raw Message Formats"
     */
    private static final byte RFU_ENROLL_SIGNED_VERSION[] = { (byte)0x00 };

    // Offset of challenge parameter in APDU input buffer for commands U2F_REGISTER and U2F_AUTHENTICATE  
    private static final short APDU_CHALLENGE_OFFSET = (short)0;
    
    // Offset of application parameter in APDU input buffer for commands U2F_REGISTER and U2F_AUTHENTICATE
    private static final short APDU_APPLICATION_PARAMETER_OFFSET = (short)32;

    private static final byte FLAG_USER_PRESENCE_VERIFIED = (byte)0x01;
    private static final byte INSTALL_FLAG_DISABLE_USER_PRESENCE = (byte)0x01;

    //Map some ISO7816 status words to FIDO speech
    private static final short FIDO_SW_TEST_OF_PRESENCE_REQUIRED = ISO7816.SW_CONDITIONS_NOT_SATISFIED;
    private static final short FIDO_SW_INVALID_KEY_HANDLE = ISO7816.SW_WRONG_DATA;

    


    
    /**
     * Applet constructor will be instantiate at the installation on card. Following steps will be performed during instantiation:
     * <ul>
  	 *		<li> 
  	 *		initialize signature counter as byte array with length 4. Each FIFO-Signing command will increase counter by 1. 
     * 	  	If counter reaches value 0xFFFFFFFF (4.294.967.295 dec) the FIDO signing command will stop working and applet will return SW 0x6A84
     * 		</li>
     * 		<li>
     * 		initialize user presence status byte: save status of user presence: Only one signing command will be execute, 
     * 	  	after that the card must be reset (remove card from reader and reinsert card) before next signing command will be accepted.
     * 		</li>
     * 		<li>
	 *		initialize transient byte array as buffer for different operations
	 *		</li>
	 *		<li>
	 *		create and initialize Signature instance with ALG_ECDSA_SHA_256 for attestation certificate signing
	 *		</li>
	 *		<li>
	 *		create Signature instance with ALG_ECDSA_SHA_256 for FIDO authentication process (signing AppID | challenge)
	 *		</li>
	 *		<li>
	 *		store flag parameter (from given parameters)
	 *		</li>
	 *		<li>
	 *		create store (with length defined in parameters) for attestation certificate 
	 *		</li>
	 *		<li>
	 *		create ECPrivateKey store and save given (in parameters) private attestation key (for attestation certificate)
	 *		</li>
	 *		<li>
	 *		create FIDO crypto instance
	 *		</li>
	 * </ul>
     * 
     * @param parameters (also described in User Guidance (AGD)): 
     * 		<ul>
     * 			<li> 1 byte: flag to enable (byte set to 0x00) or disable(byte set to 0x01) user presence check</li>
     * 			<li> 2 bytes: the length in bytes of attestation certificate which will be upload to card in personalization step.</li>
     * 			<li> 32 bytes: private key of attestation certificate (ec key for curve Secp256r1)</li>
     * 		</ul>
     * @param parametersOffset starting offset in parameters 
     * @param parametersLength length of parameters. MUST be be 35. All other length will throw ISOException "Wrong Data", SW 0x6A80
     */
    public U2FApplet(byte[] parameters, short parametersOffset, byte parametersLength) {
        if (parametersLength != 35) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        fidoSigningCounter = new byte[4]; //persistent signing counter for signing operations, keeps value along lifetime of the card. 
        scratchPersistent = JCSystem.makeTransientByteArray((short)1, JCSystem.CLEAR_ON_RESET); // saves status of user presence until card reset
        scratch = JCSystem.makeTransientByteArray((short)(SCRATCH_PAD + SCRATCH_PAD_SIZE), JCSystem.CLEAR_ON_DESELECT); //working buffer 

        localPrivateKey = (ECPrivateKey)KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, KeyBuilder.LENGTH_EC_FP_256, false);
        
        attestationSignature = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
        localSignature = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
        flags = parameters[parametersOffset];
        attestationCertificate = new byte[Util.getShort(parameters, (short)(parametersOffset + 1))];
        attestationPrivateKey = (ECPrivateKey)KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, KeyBuilder.LENGTH_EC_FP_256, false);
        Secp256r1.setCommonCurveParameters(attestationPrivateKey);
        attestationPrivateKey.setS(parameters, (short)(parametersOffset + 3), (short)32);
        attestationSignature.init(attestationPrivateKey, Signature.MODE_SIGN);
        fidoImpl = new FIDOCCImplementation();
        securityState = States.UNINITIALIZED;
    }

    
    /**
     * Incoming attestation certificate data will be proceeded and stored in reserved array. The array size was set up as parameter at the instantiation of the applet.
     * see parameter list in {@link #U2FApplet(byte[], short, byte)}
     * This method will switch the applet to state {@link States#READY_FOR_USE} after the array is complete filled. Certificate bytes can be send in chunks of arbitrary size. 
     * Since array is not completed filled applet will stay in personalization mode. This method will <b>not</b> verify if stored private key matches to the attestation certificates public key.
     * 
     * @param apdu Incoming APDU which should contain attestation certificate bytes
     * @throws ISOException Will throw SW Wrong Data 0x6A80 if the length of the data in APDU will exceed the reserved array length for the attestation certificate.
     */
    private void handleSetAttestationCert(APDU apdu) throws ISOException {
        byte[] buffer = apdu.getBuffer();
        short len = apdu.setIncomingAndReceive();
        short dataOffset = apdu.getOffsetCdata();
        short copyOffset = Util.makeShort(buffer[ISO7816.OFFSET_P1], buffer[ISO7816.OFFSET_P2]);
        
        if ((short)(copyOffset + len) > (short)attestationCertificate.length) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        
        Util.arrayCopy(buffer, dataOffset, attestationCertificate, copyOffset, len);
        
        // Check if attestationCertificate is filled. If so the applet is now operational 
        if ((short)(copyOffset + len) == (short)attestationCertificate.length) {
            securityState = States.DELIVERY_STATE;
            securityState = fidoImpl.initializeKeys(securityState);
        }
    }

    /** 
     * Process FIDO Registration Request Message - U2F_REGISTER
     * This function will check if user presence check is need and enforce it if needed. The internal FIDO signing counter will be checked before function "getPubKeyAndKeyHandle" will be called.
     * Builds key handle, user public key and return it together with the attestation certificate and a signature as specified in 
     * FIDO specification "FIDO U2F Raw Message Formats". Calls method {@link FIDOCCImplementation#getPubKeyAndKeyHandle(byte[] applicationParameter, short applicationParameterOffset, byte[] publicKey, short publicKeyOffset, byte[] keyHandle, short keyHandleOffset)}
     * and if needed {@link #handleGetResponse(APDU)}.
     * Fails if data field doesn't contain exactly 64 bytes, if user presence cannot be validated or if signing counter is full. 
     * 
     * @see FIDOCCImplementation#getPubKeyAndKeyHandle(byte[] applicationParameter, short applicationParameterOffset, byte[] publicKey, short publicKeyOffset, byte[] keyHandle, short keyHandleOffset)
     * @see U2FApplet#handleGetResponse(APDU)
     * @param apdu Expects APDU with 64 Byte data. First 32 bytes shall contain the challenge parameter, 
     * 		  followed by 32 bytes application parameter
     * @throws ISOException Returns the following SW if an exception occurs:
     * 	<ul>
     * 		<li> SW 0x6700 if data field doesn't contain exactly 64 bytes</li>
     * 		<li> SW 0x6985 if user presence is required</li>
     * 		<li> SW 0x6a84 if signing counter exceed its limit</li>
     * 	</ul> 
     */
    private void handleRegister(APDU apdu) throws ISOException {
        byte[] buffer = apdu.getBuffer();
        
        /* added getCurrentState to catch I/O errors (which returns SW 0x6F00) based on wrong length 
         * and return correct SW 0x6700 (Wrong Length) instead.
         */
        byte currentState = apdu.getCurrentState();
        if (currentState==APDU.STATE_ERROR_IO)  ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);        
        
        short len = apdu.setIncomingAndReceive();
        short dataOffset = apdu.getOffsetCdata(); 
        boolean extendedLength = (dataOffset != ISO7816.OFFSET_CDATA); // If command data start at index 7 (getOffsetCdata() returns 5 or 7) extended length APDUs are supported
        short outOffset;
        if (len != 64) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        // Deny if user presence cannot be validated
        if ((flags & INSTALL_FLAG_DISABLE_USER_PRESENCE) == 0) {
            if (scratchPersistent[0] != 0) {
                ISOException.throwIt(FIDO_SW_TEST_OF_PRESENCE_REQUIRED);
            }
        }
        // Check if the counter overflowed
        if (counterOverflowed) {
            ISOException.throwIt(ISO7816.SW_FILE_FULL);
        }
        // Set user presence
        scratchPersistent[0] = (byte)1;
                
        // Call crypto function which returns the key handle and the user public key
        short keyHandleLength = fidoImpl.getPubKeyAndKeyHandle(buffer, (short)(dataOffset + APDU_APPLICATION_PARAMETER_OFFSET), scratch, SCRATCH_PUBLIC_KEY_OFFSET, scratch, SCRATCH_KEY_HANDLE_OFFSET);
        
        scratch[SCRATCH_PAD] = ENROLL_LEGACY_VERSION;
        scratch[SCRATCH_KEY_HANDLE_LENGTH_OFFSET] = (byte)keyHandleLength;
        
        // Prepare the attestation
        attestationSignature.update(RFU_ENROLL_SIGNED_VERSION, (short)0, (short)1);
        attestationSignature.update(buffer, (short)(dataOffset + APDU_APPLICATION_PARAMETER_OFFSET), (short)32);
        attestationSignature.update(buffer, (short)(dataOffset + APDU_CHALLENGE_OFFSET), (short)32);
        attestationSignature.update(scratch, SCRATCH_KEY_HANDLE_OFFSET, keyHandleLength);
        attestationSignature.update(scratch, SCRATCH_PUBLIC_KEY_OFFSET, (short)65);
        outOffset = (short)(ENROLL_PUBLIC_KEY_OFFSET + 65 + 1 + keyHandleLength);
        
        // If using extended length, the message can be completed and sent immediately
        if (extendedLength) {
            //save transport state in scratch array
            scratch[SCRATCH_TRANSPORT_STATE] = TRANSPORT_EXTENDED;
            outOffset = Util.arrayCopyNonAtomic(scratch, SCRATCH_PAD, buffer, (short)0, outOffset);
            outOffset = Util.arrayCopyNonAtomic(attestationCertificate, (short)0, buffer, outOffset, (short)attestationCertificate.length);
            short signatureSize = attestationSignature.sign(buffer, (short)0, (short)0, buffer, outOffset);
            outOffset += signatureSize;
            apdu.setOutgoingAndSend((short)0, outOffset);
        }
        // Otherwise, keep the signature and proceed to send the first chunk
        else {
            short signatureSize = attestationSignature.sign(buffer, (short)0, (short)0, scratch, SCRATCH_SIGNATURE_OFFSET);
            //save transport state in scratch array
            scratch[SCRATCH_TRANSPORT_STATE] = TRANSPORT_NOT_EXTENDED;
            Util.setShort(scratch, SCRATCH_CURRENT_OFFSET, (short)0);
            Util.setShort(scratch, SCRATCH_SIGNATURE_LENGTH, signatureSize);
            Util.setShort(scratch, SCRATCH_NONCERT_LENGTH, outOffset);
            Util.setShort(scratch, SCRATCH_FULL_LENGTH, (short)(outOffset + attestationCertificate.length + signatureSize));
            scratch[SCRATCH_INCLUDE_CERT] = (byte)1;
            handleGetResponse(apdu);
        }
    }

    /**
     * Process FIDO Authentication Request Message - U2F_AUTHENTICATE
     * This function will check if user presence check is need and enforce it if needed. The internal FIDO signing counter will be checked before method {@link FIDOCCImplementation#getSigningKey(byte[], short, short, byte[], short, ECPrivateKey)}  will be called.
     * getSigningKey will return the FIDO EC private if APDU parameter P1 contains value {@link #P1_SIGN_ENFORCE_USER_PRESENCE_AND_SIGN}. Otherwise it will only be checked if a valid registration exists. 
     * See FIDO specification "FIDO U2F Raw Message Formats" for details on this parameter. If FIDO EC private is returned from function getSigningKey it will be used to sign the input data as 
     * described in FIDO specification. For signing it uses the platforms signing function provided by the JavaCard Signature object. This complies FCS_COP.1.
     * After getting the signature or at any error that may occur the FIDO EC private will be securely deleted by using the platforms method {@link ECPrivateKey#clearKey()}. This complies FCS_CKM.4. The signature will be processed 
     * and packed into valid FIDO messages and returned either in one Response APDU (if extended length is supported) or as multiple data blocks (which needs to process multiple GET_RESPONSE APDUs {@link #handleGetResponse(APDU)}).
     * @param apdu Expects APDU with at least 65 Byte data. See FIDO specification "FIDO U2F Raw Message Formats" for detailed input data description.
     * 		  	   Parameter P1 controls the operation mode. 0x07 "check-only", 0x03 "enforce-user-presence-and-sign" or 0x08 "dont-enforce-user-presence-and-sign"
     * 			   are valid values for P1. All other values will result in an ISOException
     * @see U2FApplet#handleGetResponse(APDU)
     * @see FIDOCCImplementation#getSigningKey(byte[] keyHandle, short keyHandleOffset, short keyHandleLength, byte[] applicationParameter, short applicationParameterOffset, ECPrivateKey regeneratedPrivateKey)
     * @throws ISOException Returns the following SW if an exception occurs:
     * 	<ul>
     * 		<li> SW 0x6700 if data field contains less than 65 bytes</li>
     * 		<li> SW 0x6a86 if P1 contains invalid data</li>
     * 		<li> SW 0x6a84 if signing counter exceed its limit</li>
     * 		<li> SW 0x6a80 if key handle verification failed</li>
     * 		<li> SW 0x6985 if user presence is required, could also signal success conditions for "check only" operation if P1 was set to 0x07</li>
     * 	</ul> 
     */
    private void handleAuthenticate(APDU apdu) throws ISOException {
        byte[] buffer = apdu.getBuffer();       
        
        /* added getCurrentState to catch I/O errors (which returns SW 0x6F00) based on wrong length 
         * and return correct SW 0x6700 (Wrong Length) instead.
         */
        byte currentState = apdu.getCurrentState();
        if (currentState==APDU.STATE_ERROR_IO)  ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        
        short len = apdu.setIncomingAndReceive();   
        short dataOffset = apdu.getOffsetCdata();

        byte p1 = buffer[ISO7816.OFFSET_P1];
        boolean sign = false;
        short keyHandleLength;
        // check if extended length command was send, if so use extended length in response otherwise use chaining as described in "FIDO NFC Protocol Specification"
        boolean extendedLength = (dataOffset != ISO7816.OFFSET_CDATA);
        short outOffset = SCRATCH_PAD;
        if (len < 65) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        switch(p1) {
        case P1_SIGN_DONT_ENFORCE_USER_PRESENCE_AND_SIGN: //we always do the user presence check. so it doesn't matter if P1 was 0x08 or 0x03
        case P1_SIGN_ENFORCE_USER_PRESENCE_AND_SIGN:
            sign = true;
            break;
        case P1_SIGN_CHECK_ONLY:
            break;
        default:
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        // Check if the counter overflowed
        if (counterOverflowed) {
            ISOException.throwIt(ISO7816.SW_FILE_FULL);
        }

        keyHandleLength = (short)(buffer[(short)(dataOffset + 64)] & 0xff);
        if (fidoImpl.getSigningKey(buffer, (short)(dataOffset + 65), keyHandleLength, buffer, (short)(dataOffset + APDU_APPLICATION_PARAMETER_OFFSET), (sign ? localPrivateKey : null))==Bool.FALSE) {   
        	ISOException.throwIt(FIDO_SW_INVALID_KEY_HANDLE);
        }
        // If not signing, return with the "correct" exception
        if (!sign) {
            ISOException.throwIt(FIDO_SW_TEST_OF_PRESENCE_REQUIRED);
        }
        // If signing, only proceed if user presence can be validated
        if ((flags & INSTALL_FLAG_DISABLE_USER_PRESENCE) == 0) {
            if (scratchPersistent[0] != 0) {
            	localPrivateKey.clearKey();
                ISOException.throwIt(FIDO_SW_TEST_OF_PRESENCE_REQUIRED);
            }
        }
        // set flag for user presence, only one signing operation is allowed before card has to be removed and reconnect
        scratchPersistent[0] = (byte)1;
        
        // Increase the counter
        boolean carry = false;
        
        // atomic transaction for increasing the counter
        JCSystem.beginTransaction(); 
        for (byte i=0; i<4; i++) {
            short addValue = (i == 0 ? (short)1 : (short)0);
            short val = (short)((short)(fidoSigningCounter[(short)(4 - 1 - i)] & 0xff) + addValue);
            if (carry) {
                val++;
            }
            carry = (val > 255);
            fidoSigningCounter[(short)(4 - 1 - i)] = (byte)val;
        }
        JCSystem.commitTransaction();
        
        // counter is full -> no more signing operations allowed
        if (carry) {
            // Game over
        	localPrivateKey.clearKey();
            counterOverflowed = true;
            ISOException.throwIt(ISO7816.SW_FILE_FULL);
        }
        
        
        // Prepare reply
        scratch[outOffset++] = FLAG_USER_PRESENCE_VERIFIED; //we always do the user presence check. so it doesn't matter if P1 was 0x08 or 0x03 
        outOffset = Util.arrayCopyNonAtomic(fidoSigningCounter, (short)0, scratch, outOffset, (short)4);

        localSignature.init(localPrivateKey, Signature.MODE_SIGN);        
        localSignature.update(buffer, (short)(dataOffset + APDU_APPLICATION_PARAMETER_OFFSET), (short)32);
        localSignature.update(scratch, SCRATCH_PAD, (short)5);
        outOffset += localSignature.sign(buffer, (short)(dataOffset + APDU_CHALLENGE_OFFSET), (short)32, scratch, outOffset);
        localPrivateKey.clearKey();
  
        if (extendedLength) {
            // If using extended length, the message can be completed and sent immediately
            scratch[SCRATCH_TRANSPORT_STATE] = TRANSPORT_EXTENDED;
            Util.arrayCopyNonAtomic(scratch, SCRATCH_PAD, buffer, (short)0, outOffset);
            apdu.setOutgoingAndSend((short)0, (short)(outOffset - SCRATCH_PAD));
        }
        else {
            // Otherwise send the first chunk
            scratch[SCRATCH_TRANSPORT_STATE] = TRANSPORT_NOT_EXTENDED;
            Util.setShort(scratch, SCRATCH_CURRENT_OFFSET, (short)0);
            Util.setShort(scratch, SCRATCH_SIGNATURE_LENGTH, (short)0);
            Util.setShort(scratch, SCRATCH_NONCERT_LENGTH, (short)(outOffset - SCRATCH_PAD));
            Util.setShort(scratch, SCRATCH_FULL_LENGTH, (short)(outOffset - SCRATCH_PAD));
            scratch[SCRATCH_INCLUDE_CERT] = (byte)0;
            handleGetResponse(apdu);
        }
    }

    /**
     * Handle FIDO command U2F_VERSION and return version string 'U2F_V2'
     * @see #VERSION
     * @param apdu APDU object to use for response
     */
    private void handleVersion(APDU apdu) throws ISOException {
        byte[] buffer = apdu.getBuffer();
        Util.arrayCopyNonAtomic(VERSION, (short)0, buffer, (short)0, (short)VERSION.length);
        apdu.setOutgoingAndSend((short)0, (short)VERSION.length);
    }

    /**
     * Handle APDU chaining (see ISO 7816-4 Section A.4) if extended length APDUs can't be used. Also defined in FIDO NFC Protocol Specification.
     * If responses in method handleAuthenticate(APDU apdu) or handleRegister(APDU apdu) couldn't be transceived in one response APDU, the client can call get the response data in multiple
     * smaller data blocks. This function will indicate how much data is still available to get in the SW (see ISO 7816 or FIDO U2F specification). 
     * 
     * @param apdu only parameter "Le" field of incoming APDU which will be processes. If "Le" field contains only bytes set to '00' then all the available data bytes will be returned within the limit of 256
     */
    private void handleGetResponse(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short currentOffset = Util.getShort(scratch, SCRATCH_CURRENT_OFFSET);
        short fullLength = Util.getShort(scratch, SCRATCH_FULL_LENGTH);
        
        //check if scratch array stores a valid transport state 
        switch(scratch[SCRATCH_TRANSPORT_STATE]) {
            case TRANSPORT_NOT_EXTENDED:
            case TRANSPORT_NOT_EXTENDED_CERT:
            case TRANSPORT_NOT_EXTENDED_SIGNATURE:
                break;
            default:
                ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        short requestedSize = apdu.setOutgoing();
        short outOffset = (short)0;
        if (scratch[SCRATCH_TRANSPORT_STATE] == TRANSPORT_NOT_EXTENDED) {
            short dataSize = Util.getShort(scratch, SCRATCH_NONCERT_LENGTH);
            short blockSize = ((short)(dataSize - currentOffset) > requestedSize ? requestedSize : (short)(dataSize - currentOffset));
            Util.arrayCopyNonAtomic(scratch, (short)(SCRATCH_PAD + currentOffset), buffer, outOffset, blockSize);
            outOffset += blockSize;
            currentOffset += blockSize;
            fullLength -= blockSize;
            if (currentOffset == dataSize) {
                if (scratch[SCRATCH_INCLUDE_CERT] == (byte)1) {
                    scratch[SCRATCH_TRANSPORT_STATE] = TRANSPORT_NOT_EXTENDED_CERT;
                    currentOffset = (short)0;
                    requestedSize -= blockSize;                    
                }
                else {
                    scratch[SCRATCH_TRANSPORT_STATE] = TRANSPORT_NONE;
                }
            }
        }
        if ((scratch[SCRATCH_TRANSPORT_STATE] == TRANSPORT_NOT_EXTENDED_CERT) && (requestedSize != (short)0)) {
            short blockSize = ((short)(attestationCertificate.length - currentOffset) > requestedSize ? requestedSize : (short)(attestationCertificate.length - currentOffset));
            Util.arrayCopyNonAtomic(attestationCertificate, currentOffset, buffer, outOffset, blockSize);
            outOffset += blockSize;
            currentOffset += blockSize;
            fullLength -= blockSize;
            if (currentOffset == (short)attestationCertificate.length) {
                if (Util.getShort(scratch, SCRATCH_SIGNATURE_LENGTH) != (short)0) {
                    scratch[SCRATCH_TRANSPORT_STATE] = TRANSPORT_NOT_EXTENDED_SIGNATURE;
                    currentOffset = (short)0;
                    requestedSize -= blockSize;                
                }
                else {
                    scratch[SCRATCH_TRANSPORT_STATE] = TRANSPORT_NONE;   
                }
            }
        }
        if ((scratch[SCRATCH_TRANSPORT_STATE] == TRANSPORT_NOT_EXTENDED_SIGNATURE) && (requestedSize != (short)0)) {
            short signatureSize = Util.getShort(scratch, SCRATCH_SIGNATURE_LENGTH);
            short blockSize = ((short)(signatureSize - currentOffset) > requestedSize ? requestedSize : (short)(signatureSize - currentOffset));
            Util.arrayCopyNonAtomic(scratch, (short)(SCRATCH_SIGNATURE_OFFSET + currentOffset), buffer, outOffset, blockSize);
            outOffset += blockSize;
            currentOffset += blockSize;
            fullLength -= blockSize;
        }                
        apdu.setOutgoingLength(outOffset);
        apdu.sendBytes((short)0, outOffset);        
        Util.setShort(scratch, SCRATCH_CURRENT_OFFSET, currentOffset);
        Util.setShort(scratch, SCRATCH_FULL_LENGTH, fullLength);
        
        // signal that client can request next chunk of data with le=0x00 (Get Response for 256 bytes)
        if (fullLength > 256) {
            ISOException.throwIt(ISO7816.SW_BYTES_REMAINING_00);
        }
        // signal client how many bytes are left to get with next command
        else 
        if (fullLength != 0) {
            ISOException.throwIt((short)(ISO7816.SW_BYTES_REMAINING_00 + fullLength));   
        }
    }
    
    /**
     * Resets the card specific keys for KDF and MAC and set FIDO signing counter to zero
     * This function will check if user presence check is need and enforce it if needed. Calls method {@link FIDOCCImplementation#eraseKeys(short actualState)} with actual internal applet state.
     * After successful clearing the keys the new status is States.DELIVERY_STATE. Then the FIDO signing counter will be reset to zero and the initialization of new seed and MACKey will be
     * triggered by calling method {@link FIDOCCImplementation#initializeKeys(short actualState)}. New state will be return from this method and set as internal applet state.
     * 
     * @param apdu received APDU which contains the instruction for clearing the keys
     */
    private void handleReset(APDU apdu) {
    	byte[] buffer = apdu.getBuffer();
    	byte p1 = buffer[ISO7816.OFFSET_P1];
    	byte p2 = buffer[ISO7816.OFFSET_P2];
    	
    	if (p1!=(byte)0x5E || p2!=(byte)0x70) {
    		ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
    	}
    	
    	if ((flags & INSTALL_FLAG_DISABLE_USER_PRESENCE) == 0) {
            if (scratchPersistent[0] != 0) {
                ISOException.throwIt(FIDO_SW_TEST_OF_PRESENCE_REQUIRED);
            }
        }
    	
    	// set flag for user presence, reset is only allowed if card has been removed and reconnected
        scratchPersistent[0] = (byte)1;
        
        securityState = fidoImpl.eraseKeys(securityState);
        
        if (securityState != States.DELIVERY_STATE) {
        	ISOException.throwIt(ISO7816.SW_WARNING_STATE_UNCHANGED);
        }
        
        //Reset FIDO counter
        Util.arrayFillNonAtomic(fidoSigningCounter, (short)0, (short)4, (byte) 0);
        
        securityState = fidoImpl.initializeKeys(securityState); 
    }

    /** Process incoming APDUs. Handle all FIDO defined commands and vendor specific commands needed for personalization and operation:
     * 	<ul>
     * 		<li>U2F_REGISTER</li>
	 *		<li>U2F_AUTHENTICATE</li>
	 *		<li>U2F_VERSION</li>
	 *		<li>GET RESPONSE</li>
	 *		<li>SET ATTESTATION CERT</li>
	 *		<li>RESET</li>
	 *	</ul>
	 * After receiving the incoming APDU it will be check if the internal state of this applet allows the processing of the command. 
	 * It will be also checked if the APDU contain the correct CLA-Byte for the command which was requested. If the incoming APDU contains a known instruction byte 
	 * the command will be dispatched to the function that handles the APDU. Response APDU will be generated and send out by the command handler functions (handleXYZ).
	 * @param apdu The APDU object which comes from the underlying JavaCard platform. It contains the APDU which this applet is going to process.
     * @see javacard.framework.Applet#process(javacard.framework.APDU)
     */
    public void process(APDU apdu) throws ISOException {

        byte[] buffer = apdu.getBuffer();
        
        //return version string when applet was selected
        if (selectingApplet()) {
            if (securityState == States.READY_FOR_USE) { 
                Util.arrayCopyNonAtomic(VERSION, (short)0, buffer, (short)0, (short)VERSION.length);
                apdu.setOutgoingAndSend((short)0, (short)VERSION.length);
            }
            return;
        }
        
        //if attestation certificate wasn't set yet, we allow to set the certification data, otherwise throw SW 0x6982 (Security conditions not fullfilled)
        if (buffer[ISO7816.OFFSET_CLA] == PROPRIETARY_CLA) {
            if (securityState != States.UNINITIALIZED) {
                ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
            }
            switch(buffer[ISO7816.OFFSET_INS]) {
            case VENDOR_SPECIFIC_SET_ATTESTATION_CERT:
                handleSetAttestationCert(apdu);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
            }
        }
        
        //handle all APDU in operational FIDO mode
        else if (buffer[ISO7816.OFFSET_CLA] == FIDO_CLA) {
            if (securityState != States.READY_FOR_USE) {
                ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
            }
            switch(buffer[ISO7816.OFFSET_INS]) {
            case FIDO_INS_U2F_REGISTER:
                handleRegister(apdu);
                break;
            case FIDO_INS_AUTHENTICATE:
                handleAuthenticate(apdu);
                break;
            case FIDO_INS_VERSION:
                handleVersion(apdu);
                break;
            case ISO_INS_GET_RESPONSE:
                handleGetResponse(apdu);
                break;
            case VENDOR_SPECIFIC_RESET:
            	handleReset(apdu);
            	break;
                
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
            }
        }
        else {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }
    }
    

    /**
     * To create an instance of the U2FApplet, the Java Card runtime environment will call this static method first.
     * Installation parameters are supplied in the bArray parameter. Here we extract the parameters which we need to call the U2FApplet constructor.
     * @see javacard.framework.Applet#install(byte[], short, byte)
     * @param bArray the array containing installation parameters
     * @param bOffset the starting offset in bArray
     * @param bLength the length in bytes of the parameter data in bArray The maximum value of bLength is 127.
     * @throws ISOException if the install method failed
     */
    public static void install (byte bArray[], short bOffset, byte bLength) throws ISOException {
        short offset = bOffset;
        offset += (short)(bArray[offset] + 1); // instance
        offset += (short)(bArray[offset] + 1); // privileges
        new U2FApplet(bArray, (short)(offset + 1), bArray[offset]).register(bArray, (short)(bOffset + 1), bArray[bOffset]);
    }
}
