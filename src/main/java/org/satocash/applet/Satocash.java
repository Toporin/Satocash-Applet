/*
 * SatoChip Satocash - Store your eCash on javacard
 * (c) 2025 by Toporin
 * Sources available on https://github.com/Toporin
 *      
 * BEGIN LICENSE BLOCK
 * Copyright (C) 2025 Toporin
 * All rights reserved.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 * END LICENSE_BLOCK  
 */

package org.satocash.applet;

import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.OwnerPIN;
import javacard.framework.SystemException;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.CryptoException;
import javacard.security.KeyAgreement;
import javacard.security.KeyBuilder;
import javacard.security.Signature;
import javacard.security.MessageDigest;
import javacard.security.RandomData;
import javacardx.crypto.Cipher;

public class Satocash extends javacard.framework.Applet {

    /* constants declaration */

    /** 
     * VERSION HISTORY
     * PROTOCOL VERSION: changes that impact compatibility with the client side
     * APPLET VERSION:   changes with no impact on compatibility of the client
     *
     * 0.1-0.1: (WIP) initial version
     */
    private final static byte PROTOCOL_MAJOR_VERSION = (byte) 0; 
    private final static byte PROTOCOL_MINOR_VERSION = (byte) 1;
    private final static byte APPLET_MAJOR_VERSION = (byte) 0;
    private final static byte APPLET_MINOR_VERSION = (byte) 1;   

    // Maximum size for the extended APDU buffer 
    private final static short EXT_APDU_BUFFER_SIZE = (short) 320;
    private final static short TMP_BUFFER_SIZE = (short) 256;
    private final static short TMP_BUFFER2_SIZE = (short) 32;
    
    // Minimum PIN size
    private final static byte PIN_MIN_SIZE = (byte) 4;
    // Maximum PIN size
    private final static byte PIN_MAX_SIZE = (byte) 16;// TODO: increase size?
    // PIN[0] initial value...
    private final static byte[] PIN_INIT_VALUE={(byte)'M',(byte)'u',(byte)'s',(byte)'c',(byte)'l',(byte)'e',(byte)'0',(byte)'0'};

    // code of CLA byte in the command APDU header
    private final static byte CardEdge_CLA = (byte) 0xB0;

    /****************************************
     *            Instruction codes         *
     ****************************************/

    // Applet initialization
    private final static byte INS_SETUP = (byte) 0x2A;

    // External authentication
    //private final static byte INS_CREATE_PIN = (byte) 0x40; // deprecated
    private final static byte INS_VERIFY_PIN = (byte) 0x42;
    private final static byte INS_CHANGE_PIN = (byte) 0x44;
    private final static byte INS_UNBLOCK_PIN = (byte) 0x46;
    private final static byte INS_LOGOUT_ALL = (byte) 0x60;

    // Status information
    //private final static byte INS_LIST_PINS = (byte) 0x48; // deprecated
    private final static byte INS_GET_STATUS = (byte) 0x3C;
    private final static byte INS_CARD_LABEL= (byte)0x3D;
    private final static byte INS_SET_NFC_POLICY = (byte) 0x3E;
    private final static byte INS_SET_NDEF= (byte)0x3F;


    private final static byte INS_BIP32_GET_AUTHENTIKEY= (byte) 0x73;
    // private final static byte INS_CRYPT_TRANSACTION_2FA = (byte) 0x76;
    // private final static byte INS_SET_2FA_KEY = (byte) 0x79;    
    // private final static byte INS_RESET_2FA_KEY = (byte) 0x78;

    // secure channel
    private final static byte INS_INIT_SECURE_CHANNEL = (byte) 0x81;
    private final static byte INS_PROCESS_SECURE_CHANNEL = (byte) 0x82;

    // Satocash
    private final static byte INS_SATOCASH_GET_STATUS = (byte)0xB0;
    private final static byte INS_SATOCASH_IMPORT_MINT= (byte)0xB1;
    private final static byte INS_SATOCASH_EXPORT_MINT= (byte)0xB2;
    private final static byte INS_SATOCASH_REMOVE_MINT= (byte)0xB3;

    private final static byte INS_SATOCASH_IMPORT_KEYSET= (byte)0xB4;
    private final static byte INS_SATOCASH_EXPORT_KEYSET= (byte)0xB5;
    private final static byte INS_SATOCASH_REMOVE_KEYSET= (byte)0xB6;

    private final static byte INS_SATOCASH_IMPORT_TOKEN= (byte)0xB7;
    private final static byte INS_SATOCASH_EXPORT_TOKENS = (byte)0xB8;
    private final static byte INS_SATOCASH_GET_TOKEN_INFO= (byte)0xB9;

    // TODO
    // 2FA support

    private final static byte INS_PRINT_LOGS= (byte)0xA9;
    private final static byte INS_EXPORT_AUTHENTIKEY= (byte) 0xAD;
    
    // Personalization PKI support
    private final static byte INS_IMPORT_PKI_CERTIFICATE = (byte) 0x92;
    private final static byte INS_EXPORT_PKI_CERTIFICATE = (byte) 0x93;
    private final static byte INS_SIGN_PKI_CSR = (byte) 0x94;
    private final static byte INS_EXPORT_PKI_PUBKEY = (byte) 0x98;
    private final static byte INS_LOCK_PKI = (byte) 0x99;
    private final static byte INS_CHALLENGE_RESPONSE_PKI= (byte) 0x9A;
    
    // reset to factory settings
    private final static byte INS_RESET_TO_FACTORY = (byte) 0xFF;
    
    /****************************************
     *          Error codes                 *
     ****************************************/

    /** Entered PIN is not correct */
    private final static short SW_PIN_FAILED = (short)0x63C0;// includes number of tries remaining
    ///** DEPRECATED - Entered PIN is not correct */
    //private final static short SW_AUTH_FAILED = (short) 0x9C02;
    /** Required operation is not allowed in actual circumstances */
    private final static short SW_OPERATION_NOT_ALLOWED = (short) 0x9C03;
    /** Required setup is not not done */
    private final static short SW_SETUP_NOT_DONE = (short) 0x9C04;
    /** Required setup is already done */
    private final static short SW_SETUP_ALREADY_DONE = (short) 0x9C07;
    /** Required feature is not (yet) supported */
    final static short SW_UNSUPPORTED_FEATURE = (short) 0x9C05;
    /** Required operation was not authorized because of a lack of privileges */
    private final static short SW_UNAUTHORIZED = (short) 0x9C06;
    ///** Algorithm specified is not correct */
    //private final static short SW_INCORRECT_ALG = (short) 0x9C09;
    /** Logger error */
    //public final static short SW_LOGGER_ERROR = (short) 0x9C0A;

    /** There have been memory problems on the card */
    private final static short SW_NO_MEMORY_LEFT = ObjectManager.SW_NO_MEMORY_LEFT; // 0x9C01
    /** DEPRECATED - Required object is missing */
    private final static short SW_OBJECT_NOT_FOUND= (short) 0x9C08;

    /** Incorrect P1 parameter */
    private final static short SW_INCORRECT_P1 = (short) 0x9C10;
    /** Incorrect P2 parameter */
    private final static short SW_INCORRECT_P2 = (short) 0x9C11;
    /** No more data available */
    private final static short SW_SEQUENCE_END = (short) 0x9C12;
    /** Invalid input parameter to command */
    private final static short SW_INVALID_PARAMETER = (short) 0x9C0F;

    // /** Eckeys initialized */
    // private final static short SW_ECKEYS_INITIALIZED_KEY = (short) 0x9C1A;

    /** Verify operation detected an invalid signature */
    private final static short SW_SIGNATURE_INVALID = (short) 0x9C0B;
    /** Operation has been blocked for security reason */
    private final static short SW_IDENTITY_BLOCKED = (short) 0x9C0C;
    /** For debugging purposes */
    private final static short SW_INTERNAL_ERROR = (short) 0x9CFF;
    /** Incorrect initialization of method */
    private final static short SW_INCORRECT_INITIALIZATION = (short) 0x9C13;

    // /** 2FA already initialized*/
    // private final static short SW_2FA_INITIALIZED_KEY = (short) 0x9C18;
    // /** 2FA uninitialized*/
    // private final static short SW_2FA_UNINITIALIZED_KEY = (short) 0x9C19;
    
    /** Lock error**/
    private final static short SW_LOCK_ERROR= (short) 0x9C30;

    /** HMAC errors */
    static final short SW_HMAC_UNSUPPORTED_KEYSIZE = (short) 0x9c1E;
    static final short SW_HMAC_UNSUPPORTED_MSGSIZE = (short) 0x9c1F;

    /** Secure channel */
    private final static short SW_SECURE_CHANNEL_REQUIRED = (short) 0x9C20;
    private final static short SW_SECURE_CHANNEL_UNINITIALIZED = (short) 0x9C21;
    private final static short SW_SECURE_CHANNEL_WRONG_IV= (short) 0x9C22;
    private final static short SW_SECURE_CHANNEL_WRONG_MAC= (short) 0x9C23;
    
    /** PKI error */
    private final static short SW_PKI_ALREADY_LOCKED = (short) 0x9C40;

    /** NFC interface disabled **/
    static final short SW_NFC_DISABLED = (short) 0x9C48;
    static final short SW_NFC_BLOCKED = (short) 0x9C49;
    
    /** For instructions that have been deprecated*/
    private final static short SW_INS_DEPRECATED = (short) 0x9C26;
    /** CARD HAS BEEN RESET TO FACTORY */
    private final static short SW_RESET_TO_FACTORY = (short) 0xFF00;
    /** For debugging purposes 2 */
    private final static short SW_DEBUG_FLAG = (short) 0x9FFF;

    /** Satocash errors */
    private final static short SW_OBJECT_ALREADY_PRESENT = (short) 0x9C60;


    // KeyBlob Encoding in Key Blobs
    //private final static byte BLOB_ENC_PLAIN = (byte) 0x00;

    // For operations running on multiple APDUs
    private final static byte OP_INIT = (byte) 0x01;
    private final static byte OP_PROCESS = (byte) 0x02;
    private final static byte OP_FINALIZE = (byte) 0x03;

    // JC API 2.2.2 does not define these constants:
    private static final byte TYPE_AES_TRANSIENT_DESELECT = 14;
    private static final byte TYPE_AES_TRANSIENT_RESET = 13;
    private static final byte TYPE_EC_FP_PRIVATE_TRANSIENT_DESELECT = 31;
    private static final byte TYPE_EC_FP_PRIVATE_TRANSIENT_RESET = 30;
    private final static byte ALG_ECDSA_SHA_256= (byte) 33;
    private final static byte ALG_EC_SVDP_DH_PLAIN= (byte) 3; //https://javacard.kenai.com/javadocs/connected/javacard/security/KeyAgreement.html#ALG_EC_SVDP_DH_PLAIN
    private final static byte ALG_EC_SVDP_DH_PLAIN_XY= (byte) 6; //https://docs.oracle.com/javacard/3.0.5/api/javacard/security/KeyAgreement.html#ALG_EC_SVDP_DH_PLAIN_XY
    private final static short LENGTH_EC_FP_256= (short) 256;

    /****************************************
     *     Instance variables declaration   *
     ****************************************/

    // PIN and PUK objects, allocated during setup
    //private OwnerPIN[] pins, ublk_pins;
    private OwnerPIN pin, ublk_pin;
    
    //logger logs critical operations performed by the applet such as key export
    private Logger logger;
    private final static short LOGGER_NBRECORDS= (short) 64;
    
    private final static byte MAX_CARD_LABEL_SIZE = (byte) 64;
    private byte card_label_size= (byte)0x00;
    private byte[] card_label;
    
    // seeds data array
    // settings: can be exported in clear,
    // TODO: can probably remove ObjectManager
    private static short OM_SIZE= (short) 0xFFF; // can be overwritten during applet installation using parameters
    private ObjectManager om_secrets;
    private AESKey om_encryptkey; // used to encrypt sensitive data in object
    private Cipher om_aes128_ecb; // 
    private short om_nextid;
    private final static short OM_TYPE= 0x00; // todo: refactor and remove (unused)


    private final static byte AES_BLOCKSIZE= (byte)16;
    private final static byte SIZE_2FA= (byte)20;

    private final static short CHUNK_SIZE= (short)128; // MUST be a multiple of 16; cut secret in chunks for exportSecret()

    // Buffer for storing extended APDUs
    private byte[] recvBuffer; // used as temporary buffer
    private byte[] tmpBuffer; //used for hmac computation
    private byte[] tmpBuffer2; //used in securechannel

    /* For the setup function - should only be called once */
    private boolean setupDone = false;

    // lock mechanism for multiple call to
    // todo: remove?
    private boolean lock_enabled = false;
    private byte lock_ins=(byte)0;
    private byte lock_lastop=(byte)0;
    private byte lock_transport_mode= (byte)0;
    private short lock_id=-1;
    private short lock_id_pubkey=-1;

    // shared cryptographic objects
    private RandomData randomData;
    private KeyAgreement keyAgreement;
    private Signature sigECDSA;
    //private Cipher aes128;
    private MessageDigest sha256;
    private MessageDigest sha512;
    
    /*********************************************
     *  BIP32 Hierarchical Deterministic Wallet  *
     *********************************************/

    private static final short BIP32_KEY_SIZE= 32; // size of extended key and chain code is 256 bits


    /*****************************************
     *               Satocash                *
     *****************************************/

    // Mints table
    private byte[] mints;
    private static final byte MAX_NB_MINTS = 16; // todo: configurable in constructor, should fit in 1 byte!
    private static final byte MAX_MINT_URL_SIZE = 32; // todo: configurable in constructor
    private static final byte MINT_BITMAP_SIZE = (MAX_NB_MINTS+7) >> 3; // number of bytes required to store a bitmap of used keysets
    private static final byte MINT_OBJECT_SIZE = 33;
    private static final byte MINT_OFFSET_URLSIZE = 0; // 1 byte
    private static final byte MINT_OFFSET_URL = 1; // max 32 bytes

    // Keysets table
    private byte[] keysets;
    private static final byte MAX_NB_KEYSETS = 32; // todo: configurable in constructor, should fit in 1 byte!
    private static final byte KEYSET_BITMAP_SIZE = (MAX_NB_KEYSETS+7) >> 3; // number of bytes required to store a bitmap of used keysets
    private static final byte KEYSET_OBJECT_SIZE = 10;
    private static final byte KEYSET_OFFSET_ID = 0; // 8 bytes
    private static final byte KEYSET_OFFSET_MINT_INDEX = 8; // 1 byte
    private static final byte KEYSET_OFFSET_UNIT = 9; // 1 byte

    // Tokens table
    private byte[] tokens;
    private static final short MAX_NB_TOKENS = 128; // todo: configurable in constructor
    private static final short TOKEN_BITMAP_SIZE = (MAX_NB_TOKENS+7) >> 3; // number of bytes required to store a bitmap of used tokens
    private static final byte TOKEN_OBJECT_SIZE = 67;
    private static final byte TOKEN_OFFSET_STATE = 0; // 1 byte
    private static final byte TOKEN_OFFSET_KEYSET_INDEX = 1; // 1 byte
    private static final byte TOKEN_OFFSET_AMOUNT = 2; // 1 byte
    private static final byte TOKEN_OFFSET_SECRET = 3; // 32 bytes
    private static final byte TOKEN_OFFSET_UNBLINDED_KEY = 35; // 32 bytes

    // Tokens export index list
    private short[] token_export_list;
    private short token_export_index;
    private short token_export_size;
    private boolean token_export_flag = false; // set to true when export is ongoing
    private static final short MAX_TOKEN_EXPORT_LIST_SIZE = 64;


    // Status info
    private byte NB_MINTS = 0;
    private byte NB_KEYSETS = 0;
    private byte NB_TOKENS_UNSPENT = 0;
    private byte NB_TOKENS_SPENT = 0;

    // size constants
    private static final byte SIZE_KEYSETID = 8;
    private static final byte SIZE_BALANCE = 4;
    private static final byte SIZE_SECRET = 32;
    private static final byte SIZE_UNBLINDED_KEY = 33;

    // State constants
    private static final byte STATE_EMPTY=0;
    private static final byte STATE_UNSPENT=1;
    private static final byte STATE_SPENT=2;

    // Unit constants
    private static final byte UNIT_NONE = 0; // empty slot flag
    private static final byte UNIT_SAT = 1;
    private static final byte UNIT_MSAT = 2;
    private static final byte UNIT_USD = 3;
    private static final byte UNIT_EUR = 4;
    private static final byte AMOUNT_NULL = (byte) 0xff;

    // metadata_type constants
    private static final byte METADATA_STATE = 0;
    private static final byte METADATA_KEYSET_INDEX = 1;
    private static final byte METADATA_AMOUNTS = 2;
    private static final byte METADATA_MINT_INDEX = 3;
    private static final byte METADATA_UNIT = 4;

    /*********************************************
     *        Other data instances               *
     *********************************************/

    // secure channel
    private static final byte[] CST_SC = {'s','c','_','k','e','y', 's','c','_','m','a','c'};
    private boolean needs_secure_channel= true;
    private boolean initialized_secure_channel= false;
    private ECPrivateKey sc_ephemeralkey; 
    private AESKey sc_sessionkey;
    private Cipher sc_aes128_cbc;
    private byte[] sc_buffer;
    private static final byte OFFSET_SC_IV=0;
    private static final byte OFFSET_SC_IV_RANDOM=OFFSET_SC_IV;
    private static final byte OFFSET_SC_IV_COUNTER=12;
    private static final byte OFFSET_SC_MACKEY=16;
    private static final byte SIZE_SC_MACKEY=20;
    private static final byte SIZE_SC_IV= 16;
    private static final byte SIZE_SC_IV_RANDOM=12;
    private static final byte SIZE_SC_IV_COUNTER=SIZE_SC_IV-SIZE_SC_IV_RANDOM;
    private static final byte SIZE_SC_BUFFER=SIZE_SC_MACKEY+SIZE_SC_IV; // 36

    //private ECPrivateKey bip32_authentikey; // key used to authenticate data
    
    // additional options
    private short option_flags;
    private boolean needs2FA = false; // todo: add 2FA support
    private boolean needsPIN = true; // todo: make PIN optional

    // PIN policy
    private static final byte PIN_DISABLED=0; // never ask pin
    private static final byte PIN_ENABLED=1; // always ask pin (except for satocash status)
    private static final byte PIN_ENABLED_FOR_STATE_CHANGE=3; //ask pin for operations that modify card state, including imports
    private static final byte PIN_ENABLED_FOR_PAYMENT=4; // ask pin for payment
    private static final byte PIN_ENABLED_FOR_AMOUNT=5; // todo: set max amount without pin
    private byte pin_policy;

    // NFC 
    private static final byte NFC_ENABLED=0;
    private static final byte NFC_DISABLED=1; // can be re-enabled at any time
    private static final byte NFC_BLOCKED=2; // warning: cannot be re-enabled except with reset factory!
    private byte nfc_policy;

    /*********************************************
     *               PKI objects                 *
     *********************************************/
    private static final byte[] PKI_CHALLENGE_MSG = {'C','h','a','l','l','e','n','g','e',':'};
    private boolean personalizationDone=false;
    private ECPrivateKey authentikey_private;
    private ECPublicKey authentikey_public;
    private short authentikey_certificate_size=0;
    private byte[] authentikey_certificate;
    
    /****************************************
     *                Methods               *
     ****************************************/

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        // extract install parameters if any
        byte aidLength = bArray[bOffset];
        short controlLength = (short)(bArray[(short)(bOffset+1+aidLength)]&(short)0x00FF);
        short dataLength = (short)(bArray[(short)(bOffset+1+aidLength+1+controlLength)]&(short)0x00FF);

        new Satocash(bArray, (short) (bOffset+1+aidLength+1+controlLength+1), dataLength);
    }

    private Satocash(byte[] bArray, short bOffset, short bLength) {

        // recover OM_SIZE from install params
        // For example, using Global Platform Pro:
        // .\gp.exe -f -install .\Satocash.cap -params 0FFF
        if (bLength>=2){
            OM_SIZE= Util.getShort(bArray, bOffset);
        }

        pin = null;

        // NFC is enabled by default, can be modified with INS_SET_NFC_POLICY
        nfc_policy = NFC_ENABLED;

        // PIN is enabled by default
        pin_policy = PIN_ENABLED;
        
        // Temporary working arrays
        try {
            tmpBuffer = JCSystem.makeTransientByteArray(TMP_BUFFER_SIZE, JCSystem.CLEAR_ON_DESELECT);
        } catch (SystemException e) {
            tmpBuffer = new byte[TMP_BUFFER_SIZE];
        }
        try {
            tmpBuffer2 = JCSystem.makeTransientByteArray(TMP_BUFFER2_SIZE, JCSystem.CLEAR_ON_DESELECT);
        } catch (SystemException e) {
            tmpBuffer2 = new byte[TMP_BUFFER2_SIZE];
        }
        // Initialize the extended APDU buffer
        try {
            // Try to allocate the extended APDU buffer on RAM memory
            recvBuffer = JCSystem.makeTransientByteArray(EXT_APDU_BUFFER_SIZE, JCSystem.CLEAR_ON_DESELECT);
        } catch (SystemException e) {
            // Allocate the extended APDU buffer on EEPROM memory
            // This is the fallback method, but its usage is really not
            // recommended as after ~ 100000 writes it will kill the EEPROM cells...
            recvBuffer = new byte[EXT_APDU_BUFFER_SIZE];
        }

        // shared cryptographic objects
        randomData = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        sha256= MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
        sha512 = MessageDigest.getInstance(MessageDigest.ALG_SHA_512, false);    
        sigECDSA= Signature.getInstance(ALG_ECDSA_SHA_256, false); 
        HmacSha160.init(tmpBuffer);
        HmacSha512.init(tmpBuffer, sha512);
        try {
            keyAgreement = KeyAgreement.getInstance(ALG_EC_SVDP_DH_PLAIN_XY, false); 
        } catch (CryptoException e) {
            // TODO: remove if possible
            ISOException.throwIt(SW_UNSUPPORTED_FEATURE);// unsupported feature => use a more recent card!
        }

        //secure channel objects
        try {
            sc_buffer = JCSystem.makeTransientByteArray((short) SIZE_SC_BUFFER, JCSystem.CLEAR_ON_DESELECT);
        } catch (SystemException e) {
            sc_buffer = new byte[SIZE_SC_BUFFER];
        }
        try {
            // Put the AES key in RAM if we can.
            sc_sessionkey = (AESKey)KeyBuilder.buildKey(TYPE_AES_TRANSIENT_DESELECT, KeyBuilder.LENGTH_AES_128, false);
        } catch (CryptoException e) {
            try {
                // This uses a bit more RAM, but at least it isn't using flash.
                sc_sessionkey = (AESKey)KeyBuilder.buildKey(TYPE_AES_TRANSIENT_RESET, KeyBuilder.LENGTH_AES_128, false);
            } catch (CryptoException x) {
                // Last option as it will wear out the flash eventually
                sc_sessionkey = (AESKey)KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
            }
        }

        try {
            // Put the EC key in RAM if we can.
            sc_ephemeralkey= (ECPrivateKey) KeyBuilder.buildKey(TYPE_EC_FP_PRIVATE_TRANSIENT_DESELECT, LENGTH_EC_FP_256, false);
        } catch (CryptoException e) {
            try {
                // This uses a bit more RAM, but at least it isn't using flash.
                sc_ephemeralkey= (ECPrivateKey) KeyBuilder.buildKey(TYPE_EC_FP_PRIVATE_TRANSIENT_RESET, LENGTH_EC_FP_256, false);
            } catch (CryptoException x) {
                // Last option as it will wear out the flash eventually
                sc_ephemeralkey= (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, LENGTH_EC_FP_256, false);
            }
        }
        sc_aes128_cbc= Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
        
        // Secret objects manager
        om_secrets= new ObjectManager(OM_SIZE);
        randomData.generateData(recvBuffer, (short)0, (short)AES_BLOCKSIZE);
        om_encryptkey= (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
        om_encryptkey.setKey(recvBuffer, (short)0); // data must be exactly 16 bytes long
        om_aes128_ecb= Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_ECB_NOPAD, false);
       
        // logger
        logger= new Logger(LOGGER_NBRECORDS); 

        // card label
        card_label= new byte[MAX_CARD_LABEL_SIZE];

        // Satocash data
        mints = new byte[(short)(MAX_NB_MINTS*MINT_OBJECT_SIZE)];
        keysets = new byte[(short)(MAX_NB_KEYSETS*KEYSET_OBJECT_SIZE)];
        tokens = new byte[(short)(MAX_NB_TOKENS*TOKEN_OBJECT_SIZE)];
        token_export_list = new short[MAX_TOKEN_EXPORT_LIST_SIZE];

        // perso PKI: generate public/private keypair
        authentikey_private= (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, LENGTH_EC_FP_256, false);
        Secp256k1.setCommonCurveParameters(authentikey_private);
        authentikey_public= (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, LENGTH_EC_FP_256, false); 
        Secp256k1.setCommonCurveParameters(authentikey_public);
        randomData.generateData(recvBuffer, (short)0, BIP32_KEY_SIZE);
        authentikey_private.setS(recvBuffer, (short)0, BIP32_KEY_SIZE); //random value first
        keyAgreement.init(authentikey_private);   
        keyAgreement.generateSecret(Secp256k1.SECP256K1, Secp256k1.OFFSET_SECP256K1_G, (short) 65, recvBuffer, (short)0); //pubkey in uncompressed form => silently fail after cap loaded
        authentikey_public.setW(recvBuffer, (short)0, (short)65);
        
        // finally, register applet
        register();
    } // end of constructor

    public boolean select() {
        /*
         * Application has been selected: Do session cleanup operation
         */
        LogOutAll();

        //todo: clear secure channel values?
        initialized_secure_channel=false;

        // check nfc policy
        if (nfc_policy == NFC_DISABLED || nfc_policy == NFC_BLOCKED){
            // check that the contact interface is used
            byte protocol = (byte) (APDU.getProtocol() & APDU.PROTOCOL_MEDIA_MASK);
            if (protocol != APDU.PROTOCOL_MEDIA_USB && protocol != APDU.PROTOCOL_MEDIA_DEFAULT) {
                ISOException.throwIt(SW_NFC_DISABLED);
            }
        }

        return true;
    }

    public void deselect() {
        LogOutAll();
    }

    public void process(APDU apdu) {
        // APDU object carries a byte array (buffer) to
        // transfer incoming and outgoing APDU header
        // and data bytes between card and CAD

        // At this point, only the first header bytes
        // [CLA, INS, P1, P2, P3] are available in
        // the APDU buffer.
        // The interface javacard.framework.ISO7816
        // declares constants to denote the offset of
        // these bytes in the APDU buffer

        short sizeout=(short)0;
        byte[] buffer = apdu.getBuffer();
        if (selectingApplet()){
            // returns card status
            //sizeout= GetStatus(apdu, buffer);
            sizeout= satocashGetStatus(apdu, buffer);
            apdu.setOutgoingAndSend((short) 0, sizeout);
            return;
        }

        // check SELECT APDU command
        if ((buffer[ISO7816.OFFSET_CLA] == 0) && (buffer[ISO7816.OFFSET_INS] == (byte) 0xA4))
            ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND); // spurious select (see https://github.com/Toporin/SatochipApplet/issues/11)

        // verify the rest of commands have the
        // correct CLA byte, which specifies the
        // command structure
        if (buffer[ISO7816.OFFSET_CLA] != CardEdge_CLA)
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);

        byte ins = buffer[ISO7816.OFFSET_INS];
        
        // prepare APDU buffer
        if (ins != INS_GET_STATUS){
            short bytesLeft = Util.makeShort((byte) 0x00, buffer[ISO7816.OFFSET_LC]);
            if (bytesLeft != apdu.setIncomingAndReceive())
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        // only 4 commands are allowed, the others must be wrapped in a secure channel command
        // the 4 commands are: get_status, satocash_get_status, initialize_secure_channel & process_secure_channel
        if (ins == INS_GET_STATUS){
            sizeout= GetStatus(apdu, buffer);
            apdu.setOutgoingAndSend((short) 0, sizeout);
            return;
        } if (ins == INS_SATOCASH_GET_STATUS){
            sizeout= satocashGetStatus(apdu, buffer);
            apdu.setOutgoingAndSend((short) 0, sizeout);
            return;
        }
        else if (ins == INS_INIT_SECURE_CHANNEL){
            sizeout= InitiateSecureChannel(apdu, buffer);
            apdu.setOutgoingAndSend((short) 0, sizeout);
            return;
        }
        else if (ins == INS_PROCESS_SECURE_CHANNEL){
            sizeout= ProcessSecureChannel(apdu, buffer);
            //todo: check if sizeout and buffer[ISO7816.OFFSET_LC] matches...
            //if sizeout>4, buffer[ISO7816.OFFSET_LC] should be equal to (sizeout-5)
            //todo: remove padding ? (it is actually not used)          
        }
        else if (needs_secure_channel){
            ISOException.throwIt(SW_SECURE_CHANNEL_REQUIRED);
        }

        // at this point, the encrypted content has been deciphered in the buffer
        ins = buffer[ISO7816.OFFSET_INS];
        if (!setupDone && (ins != INS_SETUP)){
            if (personalizationDone ||
                    ((ins != INS_VERIFY_PIN) 
                    && (ins != INS_EXPORT_PKI_PUBKEY)
                    && (ins != INS_IMPORT_PKI_CERTIFICATE)
                    && (ins != INS_SIGN_PKI_CSR)
                    && (ins != INS_LOCK_PKI)) ){
                ISOException.throwIt(SW_SETUP_NOT_DONE);
            } 
        }
        if (setupDone && (ins == INS_SETUP))
            ISOException.throwIt(SW_SETUP_ALREADY_DONE);

        switch (ins) {
            case INS_SETUP:
                sizeout= setup(apdu, buffer);
                break;
            // PIN mgmt
            case INS_VERIFY_PIN:
                sizeout= VerifyPIN(apdu, buffer);
                break;
            case INS_CHANGE_PIN:
                sizeout= ChangePIN(apdu, buffer);
                break;
            case INS_UNBLOCK_PIN:
                sizeout= UnblockPIN(apdu, buffer);
                break;
            case INS_LOGOUT_ALL:
                sizeout= LogOutAll();
                break;
            // Generic functions
            case INS_GET_STATUS:
                // For backward compatibility
                // Use INS_SATOCASH_GET_STATUS instead for satocash specific info
                sizeout= GetStatus(apdu, buffer);
                break;
            case INS_CARD_LABEL:
                sizeout= cardLabel(apdu, buffer);
                break;
            case INS_SET_NDEF:
                sizeout= cardNdef(apdu, buffer);
                break;
            case INS_SET_NFC_POLICY:
                sizeout= setNfcPolicy(apdu, buffer);
                break;
            case INS_BIP32_GET_AUTHENTIKEY:
                sizeout= getBIP32AuthentiKey(apdu, buffer);
                break;
            case INS_PRINT_LOGS:
                sizeout= printLogs(apdu, buffer);
                break;
            case INS_EXPORT_AUTHENTIKEY:
                sizeout= getAuthentikey(apdu, buffer);
                break;    

            // Satocash
            case INS_SATOCASH_GET_STATUS:
                sizeout= satocashGetStatus(apdu, buffer);
                break;
            case INS_SATOCASH_IMPORT_MINT:
                sizeout= satocashImportMint(apdu, buffer);
                break;
            case INS_SATOCASH_EXPORT_MINT:
                sizeout= satocashExportMint(apdu, buffer);
                break;
            case INS_SATOCASH_REMOVE_MINT:
                sizeout= satocashRemoveMint(apdu, buffer);
                break;

            case INS_SATOCASH_IMPORT_KEYSET:
                sizeout= satocashImportKeyset(apdu, buffer);
                break;
            case INS_SATOCASH_EXPORT_KEYSET:
                sizeout= satocashExportKeysets(apdu, buffer);
                break;
            case INS_SATOCASH_REMOVE_KEYSET:
                sizeout= satocashRemoveKeyset(apdu, buffer);
                break;

            case INS_SATOCASH_IMPORT_TOKEN:
                sizeout= satocashImportToken(apdu, buffer);
                break;
            case INS_SATOCASH_EXPORT_TOKENS:
                sizeout= satocashExportTokens(apdu, buffer);
                break;
            case INS_SATOCASH_GET_TOKEN_INFO:
                sizeout= satocashGetTokenInfo(apdu, buffer);
                break;

            // PKI
            case INS_EXPORT_PKI_PUBKEY:
                sizeout= export_PKI_pubkey(apdu, buffer);
                break;
            case INS_IMPORT_PKI_CERTIFICATE:
                sizeout= import_PKI_certificate(apdu, buffer);
                break;
            case INS_EXPORT_PKI_CERTIFICATE:
                sizeout= export_PKI_certificate(apdu, buffer);
                break;
            case INS_SIGN_PKI_CSR:
                sizeout= sign_PKI_CSR(apdu, buffer);
                break;
            case INS_LOCK_PKI:
                sizeout= lock_PKI(apdu, buffer);
                break;
            case INS_CHALLENGE_RESPONSE_PKI:
                sizeout= challenge_response_pki(apdu, buffer);
                break;
            // default
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }//end of switch

        // Prepare buffer for return
        if (sizeout==0){
            return;
        }
        else if ((ins == INS_GET_STATUS) || (ins == INS_INIT_SECURE_CHANNEL)) {
            apdu.setOutgoingAndSend((short) 0, sizeout);
        }
        else if (needs_secure_channel) { // encrypt response
            // buffer contains the data (sizeout)
            // for encryption, data is padded with PKCS#7
            //short blocksize=(short)16;
            short padsize= (short) (AES_BLOCKSIZE - sizeout%AES_BLOCKSIZE);

            Util.arrayCopy(buffer, (short)0, tmpBuffer, (short)0, sizeout);
            Util.arrayFillNonAtomic(tmpBuffer, sizeout, padsize, (byte)padsize);//padding
            Util.arrayCopy(sc_buffer, OFFSET_SC_IV, buffer, (short)0, SIZE_SC_IV);
            sc_aes128_cbc.init(sc_sessionkey, Cipher.MODE_ENCRYPT, sc_buffer, OFFSET_SC_IV, SIZE_SC_IV);
            short sizeoutCrypt=sc_aes128_cbc.doFinal(tmpBuffer, (short)0, (short)(sizeout+padsize), buffer, (short) (SIZE_SC_IV+2));
            Util.setShort(buffer, (short)SIZE_SC_IV, sizeoutCrypt);
            sizeout= (short)(SIZE_SC_IV+2+sizeoutCrypt);
            //send back
            apdu.setOutgoingAndSend((short) 0, sizeout);
        }
        else {
            apdu.setOutgoingAndSend((short) 0, sizeout);
        }

    } // end of process method

    /** 
     * Setup APDU - initialize the applet and reserve memory
     * This is done only once during the lifetime of the applet
     * 
     * ins: INS_SETUP (0x2A) 
     * p1: 0x00
     * p2: 0x00
     * data: [default_pin_length(1b) | default_pin | 
     *        pin_tries0(1b) | ublk_tries0(1b) | pin0_length(1b) | pin0 | ublk0_length(1b) | ublk0 | 
     *        pin_tries1(1b) | ublk_tries1(1b) | pin1_length(1b) | pin1 | ublk1_length(1b) | ublk1 | 
     *        RFU(2b) | RFU(2b) | RFU(3b) |
     *        option_flags(2b - RFU) | 
     *        ]
     * where: 
     *      default_pin: {0x4D, 0x75, 0x73, 0x63, 0x6C, 0x65, 0x30, 0x30};
     *      pin_tries: max number of PIN try allowed before the corresponding PIN is blocked
     *      ublk_tries:  max number of UBLK(unblock) try allowed before the PUK is blocked
     *      option_flags: flags to define up to 16 additional options       
     * return: none
     */
    private short setup(APDU apdu, byte[] buffer) {
        personalizationDone=true;// perso PKI should not be modifiable once setup is done
        
        short bytesLeft = Util.makeShort((byte) 0x00, buffer[ISO7816.OFFSET_LC]);
        short base = (short) (ISO7816.OFFSET_CDATA);
        byte numBytes = buffer[base++];
        bytesLeft--;

        // Default PIN, ignore

        //OwnerPIN pin = pins[0];

        // if (!CheckPINPolicy(buffer, base, numBytes))
        //     ISOException.throwIt(SW_INVALID_PARAMETER);

        // byte triesRemaining = pin.getTriesRemaining();
        // if (triesRemaining == (byte) 0x00)
        //     ISOException.throwIt(SW_IDENTITY_BLOCKED);
        // if (!pin.check(buffer, base, numBytes))
        //     ISOException.throwIt((short)(SW_PIN_FAILED + triesRemaining - 1));

        base += numBytes;
        bytesLeft-=numBytes;

        byte pin_tries = buffer[base++];
        byte ublk_tries = buffer[base++];
        numBytes = buffer[base++];
        bytesLeft-=3;

        // PIN0
        if (!CheckPINPolicy(buffer, base, numBytes))
            ISOException.throwIt(SW_INVALID_PARAMETER); 

        if (pin == null)
            pin = new OwnerPIN(pin_tries, PIN_MAX_SIZE);
        pin.update(buffer, base, numBytes);

//        pins[0] = new OwnerPIN(pin_tries, PIN_MAX_SIZE);//TODO: new pin or update pin?
//        pins[0].update(buffer, base, numBytes);

        base += numBytes;
        bytesLeft-=numBytes;
        numBytes = buffer[base++];
        bytesLeft--;

        // PUK0
        if (!CheckPINPolicy(buffer, base, numBytes))
            ISOException.throwIt(SW_INVALID_PARAMETER);

        if (ublk_pin == null)
            ublk_pin = new OwnerPIN(ublk_tries, PIN_MAX_SIZE);
        ublk_pin.update(buffer, base, numBytes);

        base += numBytes;
        bytesLeft-=numBytes;

        pin_tries = buffer[base++];
        ublk_tries = buffer[base++];
        numBytes = buffer[base++];
        bytesLeft-=3;

        // PIN1 is deprecated, ignore

        // if (!CheckPINPolicy(buffer, base, numBytes))
        //     ISOException.throwIt(SW_INVALID_PARAMETER);

        // if (pins[1]==null)
        //     pins[1] = new OwnerPIN(pin_tries, PIN_MAX_SIZE);
        // pins[1].update(buffer, base, numBytes);

        base += numBytes;
        bytesLeft-=numBytes;
        numBytes = buffer[base++];
        bytesLeft--;

        // PUK1 is deprecated, ignore

        // if (!CheckPINPolicy(buffer, base, numBytes))
        //     ISOException.throwIt(SW_INVALID_PARAMETER);

        // if (ublk_pins[1]==null)
        //     ublk_pins[1] = new OwnerPIN(ublk_tries, PIN_MAX_SIZE);
        // ublk_pins[1].update(buffer, base, numBytes);
        
        base += numBytes;
        bytesLeft-=numBytes;

        short RFU= Util.getShort(buffer, base); // secmem_size deprecated => RFU
        base += (short) 2;
        RFU = Util.getShort(buffer, base); //mem_size deprecated => RFU
        base += (short) 2;
        bytesLeft-=4;

        RFU = buffer[base++]; //create_object_ACL deprecated => RFU
        RFU = buffer[base++]; //create_key_ACL deprecated => RFU
        RFU = buffer[base++]; //create_pin_ACL deprecated => RFU
        bytesLeft-=3;
        
        // parse options
        option_flags=0;
        if (bytesLeft>=2){
            option_flags = Util.getShort(buffer, base);
            base+=(short)2;
            bytesLeft-=(short)2;
        }
        
        // bip32
//        Secp256k1.setCommonCurveParameters(bip32_extendedkey);

        om_nextid= (short)0;
        setupDone = true;
        return (short)0;//nothing to return
    }

    /****************************************
     *           Utility functions          *
     ****************************************/
    

    /** Checks if PIN policies are satisfied for a PIN code */
    private boolean CheckPINPolicy(byte[] pin_buffer, short pin_offset, byte pin_size) {
        if ((pin_size < PIN_MIN_SIZE) || (pin_size > PIN_MAX_SIZE))
            return false;
        return true;
    }
    
    /** Erase all user data */
    private boolean resetToFactory(){
        
        //TODO        
        // logs
        // currently, we do NOT erase logs, but we add an entry for the reset
        logger.createLog(INS_RESET_TO_FACTORY, (short)-1, (short)-1, (short)0x0000 );
        
        // reset all secrets in store
        om_secrets.resetObjectManager(true);
        
        // reset NFC policy to enabled
        nfc_policy = NFC_ENABLED;

        // reset card label
        card_label_size=0;
        Util.arrayFillNonAtomic(card_label, (short)0, (short)card_label.length, (byte)0);
        
        // setup
        pin.update(PIN_INIT_VALUE, (short) 0, (byte) PIN_INIT_VALUE.length);
        setupDone=false;
        
        // update log
        logger.updateLog(INS_RESET_TO_FACTORY, (short)-1, (short)-1, (short)0x9000 );
        
        return true;
    }
    
    /****************************************
     *           Satocash Methods           *
     ****************************************/

    /**
     * This function retrieves general information about the Applet running on the smart
     * card, and useful information about the status of current session such as:
     *      - applet version (4b)
     *
     *  ins: 0x3C
     *  p1: 0x00
     *  p2: 0x00
     *  data: none
     *  return: [versions(4b) | PIN0-PUK0-PIN1-PUK1 tries (4b) |
     *            needs2FA (1b) | needsPIN(1b) | setupDone(1b) | needs_secure_channel(1b) | nfc_policy(1b)
     *            MAX_NB_MINT (1b) | NB_USED_MINT(1b) | bitmap_size(1b) | mint_bitmap |
     *            MAX_NB_KEYSET(1b) | NB_USED_KEYSET(1b) | | bitmap_size(1b) | keyset_bitmap |
     *            MAX_NB_TOKEN(1b) | NB_UNSPENT_TOKEN(1b)
     *          ]
     *
     *  Exceptions: (none)
     */
    private short satocashGetStatus(APDU apdu, byte[] buffer) {

        // applet version
        short pos = (short) 0;
        buffer[pos++] = PROTOCOL_MAJOR_VERSION; // Major Card Edge Protocol version n.
        buffer[pos++] = PROTOCOL_MINOR_VERSION; // Minor Card Edge Protocol version n.
        buffer[pos++] = APPLET_MAJOR_VERSION; // Major Applet version n.
        buffer[pos++] = APPLET_MINOR_VERSION; // Minor Applet version n.
        // PIN/PUK remaining tries available
        if (setupDone){
            buffer[pos++] = pin.getTriesRemaining();
            buffer[pos++] = ublk_pin.getTriesRemaining();
            buffer[pos++] = (byte) 0; //pins[1].getTriesRemaining();
            buffer[pos++] = (byte) 0; //ublk_pins[1].getTriesRemaining();
        } else {
            buffer[pos++] = (byte) 0;
            buffer[pos++] = (byte) 0;
            buffer[pos++] = (byte) 0;
            buffer[pos++] = (byte) 0;
        }
        // 2FA status
        if (needs2FA) // todo
            buffer[pos++] = (byte)0x01;
        else
            buffer[pos++] = (byte)0x00;
        // RFU
        buffer[pos++] = (byte)0x00;
        // setup status
        if (setupDone)
            buffer[pos++] = (byte)0x01;
        else
            buffer[pos++] = (byte)0x00;
        // secure channel support
        if (needs_secure_channel)
            buffer[pos++] = (byte)0x01;
        else
            buffer[pos++] = (byte)0x00;
        // NFC policy
        buffer[pos++] = nfc_policy;
        // PIN Policy (todo)
        buffer[pos++] = pin_policy;
        // RFU Policy
        buffer[pos++] = 0x00;
        // satocash config
        buffer[pos++] = MAX_NB_MINTS;
        buffer[pos++] = NB_MINTS;
        buffer[pos++] = MAX_NB_KEYSETS;
        buffer[pos++] = NB_KEYSETS;
        Util.setShort(buffer, pos, MAX_NB_TOKENS);
        pos+=2;
        Util.setShort(buffer, pos, NB_TOKENS_UNSPENT);
        pos+=2;
        Util.setShort(buffer, pos, NB_TOKENS_SPENT);
        pos+=2;

        return pos;
    }

    /**
     * This function imports a mint URL in the card
     *
     *  ins: 0xB1
     *  p1: RFU
     *  p2: RFU
     *  data: [mint_url_size(1b) | mint_url]
     *  return: [MINT_INDEX(1b)]
     *
     *  Exceptions: 9C06 SW_UNAUTHORIZED , 9C01 SW_NO_MEMORY_LEFT, 6700 SW_WRONG_LENGTH, 9C0F SW_INVALID_PARAMETER
     */
    private short satocashImportMint(APDU apdu, byte[] buffer) {
        // check that PIN has been entered previously
        if (!pin.isValidated())
            ISOException.throwIt(SW_UNAUTHORIZED);

        // check that there are still mint slot available
        if (NB_MINTS >= MAX_NB_MINTS)
            ISOException.throwIt(SW_NO_MEMORY_LEFT); // todo: use more specific error?

        // check input size
        short bytesLeft = Util.makeShort((byte) 0x00, buffer[ISO7816.OFFSET_LC]);
        if (bytesLeft < (short)(1))
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

        short buffer_offset=ISO7816.OFFSET_CDATA;
        byte url_size= buffer[buffer_offset++];
        bytesLeft--;

        // check url size fits
        if (url_size<=0 || url_size> MAX_MINT_URL_SIZE)
            ISOException.throwIt(SW_INVALID_PARAMETER);

        if (bytesLeft < (short)(url_size))
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

        // check that mint is not already present
        byte index;
        boolean already_present = false;
        for (index=(byte)0; index<MAX_NB_MINTS; index++) {
            byte mint_url_size = mints[(short)(index*MINT_OBJECT_SIZE + MINT_OFFSET_URLSIZE)];
            if (mint_url_size != url_size)
                continue;

            short mint_offset_url = (short)(index*MINT_OBJECT_SIZE + MINT_OFFSET_URL);
            if (Util.arrayCompare(buffer, buffer_offset, mints, mint_offset_url, (short)url_size) == 0){
                //ISOException.throwIt(SW_OBJECT_ALREADY_PRESENT);
                already_present = true;
                break;
            }
        }

        // find available slot
        if (!already_present) {
            for (index = (byte) 0; index < MAX_NB_MINTS; index++) {
                if ((mints[(short) (index * MINT_OBJECT_SIZE + MINT_OFFSET_URLSIZE)]) == 0x00) {
                    // slot is empty, copy URL
                    Util.arrayCopy(buffer, buffer_offset, mints, (short) (index * MINT_OBJECT_SIZE + MINT_OFFSET_URL), url_size);
                    mints[(short) (index * MINT_OBJECT_SIZE + MINT_OFFSET_URLSIZE)] = url_size;
                    NB_MINTS++;
                    break;
                }
            }
        }

        // return index
        buffer[0]=index;
        return (short)1;
    }

    /**
     * This function exports a mint URL from the card
     *
     *  ins: 0xB2
     *  p1: index
     *  p2: RFU
     *  data: none
     *  return: [URL_size (1b) | URL ]
     *
     *  Exceptions: 9C06 SW_UNAUTHORIZED , 9C10 SW_INCORRECT_P1
     */
    private short satocashExportMint(APDU apdu, byte[] buffer) {
        // check that PIN has been entered previously
        if (!pin.isValidated())
            ISOException.throwIt(SW_UNAUTHORIZED);

        // check p1 value
        byte index = buffer[ISO7816.OFFSET_P1];
        if ((index < 0) || (index >= MAX_NB_MINTS) )
            ISOException.throwIt(SW_INCORRECT_P1);

        // copy URL+size
        byte url_size = mints[(short)(index*MINT_OBJECT_SIZE + MINT_OFFSET_URLSIZE)];
        buffer[0] = url_size;
        Util.arrayCopy(mints, (short) (index*MINT_OBJECT_SIZE + MINT_OFFSET_URL), buffer, (short) 1, url_size);

        return (short)(url_size+1);
    }

    /**
     * This function removes a mint URL from the card.
     * The mint should have no unspent token associated with it.
     *
     *  ins: 0xB3
     *  p1: index
     *  p2: RFU
     *  data: none
     *  return: []
     *
     *  Exceptions: 9C06 SW_UNAUTHORIZED , 9C10 SW_INCORRECT_P1, 9C03 SW_OPERATION_NOT_ALLOWED
     */
    private short satocashRemoveMint(APDU apdu, byte[] buffer) {
        // check that PIN has been entered previously
        if (!pin.isValidated())
            ISOException.throwIt(SW_UNAUTHORIZED);

        // check p1 value
        byte index = buffer[ISO7816.OFFSET_P1];
        if ((index < 0) || (index >= MAX_NB_MINTS) )
            ISOException.throwIt(SW_INCORRECT_P1);

        // check that no keyset refers to this mint
        for (byte keyset_index=(byte)0; keyset_index<MAX_NB_KEYSETS; keyset_index++){
            if ((keysets[(short)(keyset_index*KEYSET_OBJECT_SIZE + KEYSET_OFFSET_MINT_INDEX)]) == index) {
                // the mint is still referenced by a keyset!
                ISOException.throwIt(SW_OPERATION_NOT_ALLOWED); // todo: use more specific code?
            }
        }

        // reset slot
        mints[(short)(index*MINT_OBJECT_SIZE + MINT_OFFSET_URLSIZE)] = (byte) 0x00;

        Util.arrayFillNonAtomic(mints, (short)(index*MINT_OBJECT_SIZE + MINT_OFFSET_URL), MINT_OBJECT_SIZE, (byte)0x00);
        NB_MINTS--;

        return (short)0;
    }

    /**
     * This function imports a keyset URL in the card.
     * The keyset should not be already present in the card
     *
     *  ins: 0xB4
     *  p1: RFU
     *  p2: RFU
     *  data: [keyset_id(8b) | mint_index(1b) | unit(1b) ]
     *  return: [KEYSET_INDEX(1b)]
     *
     *  Exceptions: 9C06 SW_UNAUTHORIZED , 9C01 SW_NO_MEMORY_LEFT , 6700 SW_WRONG_LENGTH , 9C0F SW_INVALID_PARAMETER
     *
     */
    private short satocashImportKeyset(APDU apdu, byte[] buffer) {
        // check that PIN has been entered previously
        if (!pin.isValidated())
            ISOException.throwIt(SW_UNAUTHORIZED);

        // check that there are still keyset slot available
        if (NB_KEYSETS >= MAX_NB_KEYSETS)
            ISOException.throwIt(SW_NO_MEMORY_LEFT); // todo: use more specific error?

        // check input size
        short bytesLeft = Util.makeShort((byte) 0x00, buffer[ISO7816.OFFSET_LC]);
        if (bytesLeft < (short)(10))
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

        short buffer_offset=ISO7816.OFFSET_CDATA;

        // check that keyset is not already present
        byte index;
        boolean already_present = false;
        for (index=(byte)0; index<MAX_NB_KEYSETS; index++) {
            short keyset_id_offset = (short)(index*KEYSET_OBJECT_SIZE + KEYSET_OFFSET_ID);
            if (Util.arrayCompare(buffer, buffer_offset, keysets, keyset_id_offset, (short)8) == 0){
                //ISOException.throwIt(SW_OBJECT_ALREADY_PRESENT);
                already_present = true;
                break;
            }
        }

        // check that mint is defined
        byte mint_index = buffer[(short)(buffer_offset + KEYSET_OFFSET_MINT_INDEX)];
        if (mint_index<0 || mint_index>=MAX_NB_MINTS)
            ISOException.throwIt(SW_INVALID_PARAMETER);
        if (mints[(short)(mint_index*MINT_OBJECT_SIZE + MINT_OFFSET_URLSIZE)] == 0x00)
            ISOException.throwIt(SW_INVALID_PARAMETER);

        // check unit is in valid range
        byte unit = buffer[(short)(buffer_offset + KEYSET_OFFSET_UNIT)];
        if ((unit < UNIT_SAT))
            ISOException.throwIt(SW_INVALID_PARAMETER);

        // find available slot
        if (!already_present){
            for (index=(byte)0; index<MAX_NB_KEYSETS; index++) {
                if ((keysets[(short)(index*KEYSET_OBJECT_SIZE + KEYSET_OFFSET_UNIT)]) == UNIT_NONE) {
                    // slot is empty, copy data
                    Util.arrayCopy(buffer, buffer_offset, keysets, (short)(index*KEYSET_OBJECT_SIZE + KEYSET_OFFSET_ID), (short)10);
                    NB_KEYSETS++;
                    break;
                }
            }
        }

        // return index
        buffer[0]=index;
        return (short)1;
    }

    /**
     * This function exports keysets info from the card.
     *
     *  ins: 0xB5
     *  p1: RFU
     *  p2: RFU
     *  data: [index_list_size(1b) | index_list]
     *  return: [keyset_index(1b) | keyset(10b)] for each keyset index in the list
     *
     *  Exceptions: 9C06 SW_UNAUTHORIZED, 6700 SW_WRONG_LENGTH, 9C0F SW_INVALID_PARAMETER
     */
    private short satocashExportKeysets(APDU apdu, byte[] buffer) {
        // check that PIN has been entered previously
        // todo: remove pin requirement for this function?
        if (!pin.isValidated())
            ISOException.throwIt(SW_UNAUTHORIZED);

        // check input size
        short bytesLeft = Util.makeShort((byte) 0x00, buffer[ISO7816.OFFSET_LC]);
        if (bytesLeft < (short)(1))
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

        // get list size
        short buffer_offset = ISO7816.OFFSET_CDATA;
        short keyset_index_list_size = Util.makeShort((byte)0x00, buffer[buffer_offset++]);
        bytesLeft--;
        if (keyset_index_list_size<=0 || keyset_index_list_size>16)
            ISOException.throwIt(SW_INVALID_PARAMETER);

        //check data size again
        if (bytesLeft < keyset_index_list_size)
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

        // copy array list in tmp buffer
        Util.arrayCopy(buffer, buffer_offset, recvBuffer, (short)0, keyset_index_list_size);

        // copy keysets
        buffer_offset=0;
        for (byte i = 0; i<keyset_index_list_size; i++){
            // check index bound
            byte index = recvBuffer[i];
            if (index<0 || index>= MAX_NB_KEYSETS)
                ISOException.throwIt(SW_INVALID_PARAMETER);
            // copy keyset index
            buffer[buffer_offset++]= index;
            // copy keyset data
            short keyset_offset = (short)(index*KEYSET_OBJECT_SIZE);
            Util.arrayCopy(keysets, keyset_offset, buffer, buffer_offset, KEYSET_OBJECT_SIZE);
            buffer_offset+=KEYSET_OBJECT_SIZE;
        }

        return buffer_offset;
    }

    /**
     * This function removes a keyset info from the card.
     * The keyset should have no unspent token associated with it.
     *
     *  ins: 0xB6
     *  p1: index
     *  p2: RFU
     *  data: none
     *  return: []
     *
     *  Exceptions: 9C06 SW_UNAUTHORIZED , 9C10 SW_INCORRECT_P1, 9C03 SW_OPERATION_NOT_ALLOWED
     */
    private short satocashRemoveKeyset(APDU apdu, byte[] buffer) {
        // check that PIN has been entered previously
        if (!pin.isValidated())
            ISOException.throwIt(SW_UNAUTHORIZED);

        // check p1 value
        byte index = buffer[ISO7816.OFFSET_P1];
        if ((index < 0) || (index >= MAX_NB_KEYSETS) )
            ISOException.throwIt(SW_INCORRECT_P1);

        // check that no tokens refers to this keyset
        for (byte token_index=(byte)0; token_index<MAX_NB_TOKENS; token_index++){
            if ((tokens[(short)(token_index*TOKEN_OBJECT_SIZE + TOKEN_OFFSET_KEYSET_INDEX)]) == index) {
                // check if the keyset is still referenced by an unspent token
                // spent token are basically only kept as backup
                if ((tokens[(short)(token_index*TOKEN_OBJECT_SIZE + TOKEN_OFFSET_STATE)]) == STATE_UNSPENT)
                    ISOException.throwIt(SW_OPERATION_NOT_ALLOWED); // todo: use more specific code?
            }
        }

        // reset slot
        Util.arrayFillNonAtomic(keysets, (short)(index*KEYSET_OBJECT_SIZE + KEYSET_OFFSET_ID), KEYSET_OBJECT_SIZE, (byte)0x00);
        NB_KEYSETS--;
        return (short)0;
    }

    /**
     * This function imports a token in the card.
     *
     *  ins: 0xB7
     *  p1: RFU
     *  p2: RFU
     *  data: [keyset_index(1b) | amount(1b) | secret(32b) | unblinded_key(32b)]
     *  return: [index(2b)]
     *
     *  Exceptions: 9C06 SW_UNAUTHORIZED, 9C01 SW_NO_MEMORY_LEFT, 6700 SW_WRONG_LENGTH, 9C0F SW_INVALID_PARAMETER
     */
    private short satocashImportToken(APDU apdu, byte[] buffer) {
        // check that PIN has been entered previously
        if (!pin.isValidated())
            ISOException.throwIt(SW_UNAUTHORIZED);

        // check that there are still token slot available
        if (NB_TOKENS_SPENT+NB_TOKENS_UNSPENT >= MAX_NB_TOKENS)
            ISOException.throwIt(SW_NO_MEMORY_LEFT); // todo: use more specific error?

        // check input size
        short bytesLeft = Util.makeShort((byte) 0x00, buffer[ISO7816.OFFSET_LC]);
        if (bytesLeft < (short)(TOKEN_OBJECT_SIZE-1))
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

        short buffer_offset=ISO7816.OFFSET_CDATA;

        // check that keyset is defined
        byte keyset_index = buffer[buffer_offset++];
        if (keyset_index<0 || keyset_index>=MAX_NB_KEYSETS)
            ISOException.throwIt(SW_INVALID_PARAMETER);
        if (keysets[(short)(keyset_index*KEYSET_OBJECT_SIZE + KEYSET_OFFSET_UNIT)] == UNIT_NONE)
            ISOException.throwIt(SW_INVALID_PARAMETER);

        // check amount
        byte amount = buffer[buffer_offset++];
        if (amount<0)
            ISOException.throwIt(SW_INVALID_PARAMETER); // todo: amount can be <0 (would represent a negative power of 2)?

        // todo: check if token already present?

        // find empty slot
        byte found_slot_state = STATE_UNSPENT;
        short index;
        for (index=(byte)0; index<MAX_NB_TOKENS; index++) {
            if ((tokens[(short)(index*TOKEN_OBJECT_SIZE + TOKEN_OFFSET_STATE)]) == STATE_EMPTY) {
                // slot is empty
                found_slot_state = STATE_EMPTY;
                break;
            }
        }

        if (found_slot_state == STATE_UNSPENT){
            // if no empty slot available, look for a spent_slot to overwrite
            for (index=(byte)0; index<MAX_NB_TOKENS; index++) {
                if ((tokens[(short)(index*TOKEN_OBJECT_SIZE + TOKEN_OFFSET_STATE)]) == STATE_SPENT) {
                    // slot is spent
                    found_slot_state = STATE_SPENT;
                    break;
                }
            }
        }

        if (found_slot_state == STATE_UNSPENT)
            ISOException.throwIt(SW_NO_MEMORY_LEFT); // todo: use more specific error

        // copy token in available slot
        tokens[(short)(index*TOKEN_OBJECT_SIZE + TOKEN_OFFSET_KEYSET_INDEX)] = keyset_index;
        tokens[(short)(index*TOKEN_OBJECT_SIZE + TOKEN_OFFSET_AMOUNT)] = amount;
        // copy secret & unblinded key
        Util.arrayCopy(buffer, buffer_offset, tokens, (short)(index*TOKEN_OBJECT_SIZE + TOKEN_OFFSET_SECRET), (short) 64);
        buffer_offset+=(short)64;

        // update state
        tokens[(short)(index*TOKEN_OBJECT_SIZE + TOKEN_OFFSET_STATE)] = STATE_UNSPENT;
        NB_TOKENS_UNSPENT++;
        if (found_slot_state == STATE_SPENT)
            NB_TOKENS_SPENT--;

        // return index
        Util.setShort(buffer, (short)0, index);
        return (short)2;
    }

    /**
     * This function exports multiple tokens from the card.
     *
     *  ins: 0xB8
     *  p1: RFU
     *  p2: OP_INIT | OP_PROCESS
     *  data (OP_INIT): [ token_index_list_size(1b) | token_index(2b) ... | 2FA_size(1b) | 2FA ] else
     *  data (OP_PROCESS): []
     *
     *  return: [token_index(2b) | token_state(1b) | keyset_index(1b) | amount(1b) | secret(32b) | unblinded_key(32b)]
     *
     *  exceptions (OP_INIT): 9C06 SW_UNAUTHORIZED, 9C11 SW_INCORRECT_P2, 6700 SW_WRONG_LENGTH, 9C0F SW_INVALID_PARAMETER,
     *  exceptions (OP_PROCESS): 9C06 SW_UNAUTHORIZED, 9C11 SW_INCORRECT_P2, 9C13 SW_INCORRECT_INITIALIZATION,
     */
    private short  satocashExportTokens(APDU apdu, byte[] buffer) {
        // check that PIN has been entered previously
        if (!pin.isValidated())
            ISOException.throwIt(SW_UNAUTHORIZED);

        byte p2= buffer[ISO7816.OFFSET_P2];
        if (p2 < OP_INIT || p2 > OP_PROCESS)
            ISOException.throwIt(SW_INCORRECT_P2);

        switch (p2){
            case OP_INIT:

                // check input size
                short bytesLeft = Util.makeShort((byte) 0x00, buffer[ISO7816.OFFSET_LC]);
                if (bytesLeft < (short)(1))
                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

                // get list size
                short buffer_offset = ISO7816.OFFSET_CDATA;
                short token_index_list_size = Util.makeShort((byte)0x00, buffer[buffer_offset++]);
                bytesLeft--;
                if (token_index_list_size<=0 || token_index_list_size>96)
                    ISOException.throwIt(SW_INVALID_PARAMETER);

                //check data size again
                if (bytesLeft < (short)(2*token_index_list_size))
                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

                // TODO: check 2FA if enabled
                // idea: compute hash of available token data (index, keyset_id, amount) and uses this as challenge

                // copy list in array and save in state for next APDU calls
                short index_out=0;
                for (short index_in= 0; index_in<token_index_list_size; index_in++) {
                    short index_token = Util.getShort(buffer, (short)(buffer_offset+2*index_in));
                    // check index_token
                    if (index_token<0 || index_token>=MAX_NB_TOKENS)
                        ISOException.throwIt(SW_INVALID_PARAMETER);
                    // save index_token in state
                    token_export_list[index_out++] = index_token;
                }
                token_export_size = token_index_list_size;
                token_export_index = 0;
                token_export_flag = true;

                // note: intentional fallthrough
                // without the 'break' instruction, we fall through the OP_PROCESS phase directly, thus saving one APDU call...
                //break;

            case OP_PROCESS:

                // check flag
                if (!token_export_flag)
                    ISOException.throwIt(SW_INCORRECT_INITIALIZATION);

                // prepare output buffer
                buffer_offset = 0;

                // process up to 3 token per OP_PROCESS apdu call
                short nb_token_to_process = (short)(token_export_size-token_export_index);
                if (nb_token_to_process>3)
                    nb_token_to_process = 3;

                // start from last token_export_index position and export each token
                for (byte i= 0; i<nb_token_to_process; i++){
                    // get index_token from state
                    short index_token = token_export_list[token_export_index++];

                    // check token state
                    short token_offset_state = (short)(index_token*TOKEN_OBJECT_SIZE + TOKEN_OFFSET_STATE);
                    if (tokens[token_offset_state] == STATE_EMPTY){
                        // if token is empty, fill with 0x00
                        Util.setShort(buffer, buffer_offset, index_token);
                        buffer_offset+=2;
                        Util.arrayFillNonAtomic(buffer, buffer_offset, TOKEN_OBJECT_SIZE, (byte)0x00);
                        //buffer[buffer_offset] = STATE_EMPTY; // update state, not needed as STATE_EMPTY == 0x00
                        buffer_offset+=TOKEN_OBJECT_SIZE;

                    } else {
                        // export token data
                        Util.setShort(buffer, buffer_offset, index_token);
                        buffer_offset+=2;
                        Util.arrayCopy(tokens, token_offset_state, buffer, buffer_offset, TOKEN_OBJECT_SIZE);
                        buffer_offset+=TOKEN_OBJECT_SIZE;
                        // if token was unspent, change its state to spent
                        if (tokens[token_offset_state] == STATE_UNSPENT) {
                            tokens[token_offset_state] = STATE_SPENT;
                            NB_TOKENS_SPENT++;
                            NB_TOKENS_UNSPENT--;
                        }
                    }
                } // end for

                // if all tokens have been exported, set export flag to false
                if (token_export_index >= token_export_size)
                    token_export_flag = false;

                return buffer_offset;

            default:
                ISOException.throwIt(SW_INCORRECT_P2);
        }

        return (short) 0;
    }


    /**
     * This function returns some token info from the card.
     * The sensitive token data (secret, unblinded_key) is not returned.
     * Only valid (unspent) token are considered.
     *
     *  ins: 0xB9
     *  p1: unit
     *  p2: into_type (amounts, mints_index, keyset_index, state)
     *  data: [index_start(2b) | index_size(2b)]
     *  return: [info(1b) for each token in range]
     *
     *  Exceptions: 9C06 SW_UNAUTHORIZED, 9C0F SW_INVALID_PARAMETER, 6700 SW_WRONG_LENGTH,
     */
    private short satocashGetTokenInfo(APDU apdu, byte[] buffer) {
        // check that PIN has been entered previously
        if (!pin.isValidated())
            ISOException.throwIt(SW_UNAUTHORIZED);

        // check input size
        short index_start = 0;
        short index_size = 0;
        short bytesLeft = Util.makeShort((byte) 0x00, buffer[ISO7816.OFFSET_LC]);
        short buffer_offset = ISO7816.OFFSET_CDATA;
        if (bytesLeft == 0){
            // use defaults if no index provided
            index_start = 0;
            if (MAX_NB_TOKENS < 192)
                index_size = MAX_NB_TOKENS;
            else
                index_size = CHUNK_SIZE;

        } if (bytesLeft >= 4){
            // get & check index
            index_start = Util.getShort(buffer, buffer_offset);
            if (index_start<0 || index_start>=MAX_NB_TOKENS)
                ISOException.throwIt(SW_INVALID_PARAMETER);

            buffer_offset+=2;
            index_size = Util.getShort(buffer, buffer_offset);
            if (index_size<0)
                ISOException.throwIt(SW_INVALID_PARAMETER);
            if ((short)(index_start+index_size) > MAX_NB_TOKENS)
                index_size = (short)(MAX_NB_TOKENS - index_start);

        } else {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        // check p1 value
        byte unit = buffer[ISO7816.OFFSET_P1];
        if ((unit < UNIT_SAT))
            ISOException.throwIt(SW_INVALID_PARAMETER);

        // check p2 value
        byte info_type = buffer[ISO7816.OFFSET_P2];
        byte metadata_offset= TOKEN_OFFSET_STATE;
        switch (info_type){
            case METADATA_STATE:
                metadata_offset = TOKEN_OFFSET_STATE;
                break;
            case METADATA_KEYSET_INDEX:
                metadata_offset = TOKEN_OFFSET_KEYSET_INDEX;
                break;
            case METADATA_AMOUNTS:
                // for amount info, we must check token unit from the keysets
                // Then we must check that token state is UNSPENT
                metadata_offset = TOKEN_OFFSET_KEYSET_INDEX;
                break;
            case METADATA_MINT_INDEX:
                // mint info must be recovered from the keysets table using the token keyset_index
                metadata_offset = TOKEN_OFFSET_KEYSET_INDEX;
                break;
            case METADATA_UNIT:
                // unit info must be recovered from the keysets table using the token keyset_index
                metadata_offset = TOKEN_OFFSET_KEYSET_INDEX;
                break;
            default:
                ISOException.throwIt(SW_INVALID_PARAMETER);
        }

        // export metadata
        buffer_offset = 0;
        for (short index=index_start; index<index_size; index++) {
            short token_offset = (short)(index*TOKEN_OBJECT_SIZE + metadata_offset);
            byte metadata = tokens[token_offset];

            // mint info must be recovered from keysets table
            if (info_type == METADATA_MINT_INDEX){
                // current metadata is the token keyset_index, get token mint from keysets
                metadata = keysets[(short)(metadata*KEYSET_OBJECT_SIZE + KEYSET_OFFSET_MINT_INDEX)];

            } else if (info_type == METADATA_UNIT){
                // current metadata is the token keyset_index, get token unit from keysets
                metadata = keysets[(short)(metadata*KEYSET_OBJECT_SIZE + KEYSET_OFFSET_UNIT)];

            } else if (info_type == METADATA_AMOUNTS){

                // for amount_metadata, we must check token unit first, then state
                // current metadata is the token keyset_index, get token unit from keysets
                metadata = keysets[(short)(metadata*KEYSET_OBJECT_SIZE + KEYSET_OFFSET_UNIT)];
                if (metadata == unit){
                    // get token state
                    metadata = tokens[(short)(index*TOKEN_OBJECT_SIZE + TOKEN_OFFSET_STATE)];
                    if (metadata == STATE_UNSPENT){
                        // get token amount
                        metadata = tokens[(short)(index*TOKEN_OBJECT_SIZE + TOKEN_OFFSET_AMOUNT)];
                    } else if (metadata == STATE_SPENT) {
                        // if STATE_SPENT, add flag at msb
                        metadata = (byte) (tokens[(short)(index*TOKEN_OBJECT_SIZE + TOKEN_OFFSET_AMOUNT)] | 0x80);
                    } else {
                        // if STATE_EMPTY, amount is null
                        metadata = AMOUNT_NULL;
                    }

                } else {
                    // amount is considered null
                    metadata = AMOUNT_NULL;
                }

            }

            // update buffer with requested info for each token in range
            buffer[buffer_offset++] = metadata;
        }// end for

        return buffer_offset;
    }

    /****************************************
     *               PIN Methods            *
     ****************************************/

    /** 
     * This function verifies a PIN number sent by the DATA portion. The length of
     * this PIN is specified by the value contained in P3.
     * Multiple consecutive unsuccessful PIN verifications will block the PIN. If a PIN
     * blocks, then an UnblockPIN command can be issued.
     * 
     * ins: 0x42
     * p1: 0x00 (PIN number)
     * p2: 0x00
     * data: [PIN] 
     * return: none (throws an exception in case of wrong PIN)
     */
    private short VerifyPIN(APDU apdu, byte[] buffer) {
        byte pin_nb = buffer[ISO7816.OFFSET_P1];
        // if ((pin_nb < 0) || (pin_nb >= MAX_NUM_PINS))
        //     ISOException.throwIt(SW_INCORRECT_P1);
        if (pin_nb != 0)
            ISOException.throwIt(SW_INCORRECT_P1);
        if (buffer[ISO7816.OFFSET_P2] != 0x00)
            ISOException.throwIt(SW_INCORRECT_P2);

        //OwnerPIN pin = pins[pin_nb];
        if (pin == null)
            return (short)0; //verifyPIN does not fail if no PIN (i.e. before setup)
            //ISOException.throwIt(SW_INCORRECT_P1);

        short bytesLeft = Util.makeShort((byte) 0x00, buffer[ISO7816.OFFSET_LC]);
        /*
         * Here I suppose the PIN code is small enough to enter in the buffer
         * TODO: Verify the assumption and eventually adjust code to support
         * reading PIN in multiple read()s
         */
        if (!CheckPINPolicy(buffer, ISO7816.OFFSET_CDATA, (byte) bytesLeft))
            ISOException.throwIt(SW_INVALID_PARAMETER);
        byte triesRemaining = pin.getTriesRemaining();
        if (triesRemaining == (byte) 0x00)
            ISOException.throwIt(SW_IDENTITY_BLOCKED);
        if (!pin.check(buffer, (short) ISO7816.OFFSET_CDATA, (byte) bytesLeft)) {
            logger.createLog(INS_VERIFY_PIN, (short)-1, (short)-1, (short)(SW_PIN_FAILED + triesRemaining - 1) );
            ISOException.throwIt((short)(SW_PIN_FAILED + triesRemaining - 1));
        }

        return (short)0;
    }

    /** 
     * This function changes a PIN code. The DATA portion contains both the old and
     * the new PIN codes. 
     * 
     * ins: 0x44
     * p1: 0x00 (PIN number)
     * p2: 0x00
     * data: [PIN_size(1b) | old_PIN | PIN_size(1b) | new_PIN ] 
     * return: none (throws an exception in case of wrong PIN)
     */
    private short ChangePIN(APDU apdu, byte[] buffer) {
        /*
         * Here I suppose the PIN code is small enough that 2 of them enter in
         * the buffer TODO: Verify the assumption and eventually adjust code to
         * support reading PINs in multiple read()s
         */
        byte pin_nb = buffer[ISO7816.OFFSET_P1];
        // if ((pin_nb < 0) || (pin_nb >= MAX_NUM_PINS))
        //     ISOException.throwIt(SW_INCORRECT_P1);
        if (pin_nb != 0)
            ISOException.throwIt(SW_INCORRECT_P1);
        if (buffer[ISO7816.OFFSET_P2] != (byte) 0x00)
            ISOException.throwIt(SW_INCORRECT_P2);
        if (pin == null)
            ISOException.throwIt(SW_INCORRECT_P1);
        
        short bytesLeft = Util.makeShort((byte) 0x00, buffer[ISO7816.OFFSET_LC]);
        // At least 1 character for each PIN code
        if (bytesLeft < 4)
            ISOException.throwIt(SW_INVALID_PARAMETER);
        byte pin_size = buffer[ISO7816.OFFSET_CDATA];
        if (bytesLeft < (short) (1 + pin_size + 1))
            ISOException.throwIt(SW_INVALID_PARAMETER);
        if (!CheckPINPolicy(buffer, (short) (ISO7816.OFFSET_CDATA + 1), pin_size))
            ISOException.throwIt(SW_INVALID_PARAMETER);
        byte new_pin_size = buffer[(short) (ISO7816.OFFSET_CDATA + 1 + pin_size)];
        if (bytesLeft < (short) (1 + pin_size + 1 + new_pin_size))
            ISOException.throwIt(SW_INVALID_PARAMETER);
        if (!CheckPINPolicy(buffer, (short) (ISO7816.OFFSET_CDATA + 1 + pin_size + 1), new_pin_size))
            ISOException.throwIt(SW_INVALID_PARAMETER);

        byte triesRemaining = pin.getTriesRemaining();
        if (triesRemaining == (byte) 0x00)
            ISOException.throwIt(SW_IDENTITY_BLOCKED);
        if (!pin.check(buffer, (short) (ISO7816.OFFSET_CDATA + 1), pin_size)) {
            logger.createLog(INS_CHANGE_PIN, (short)-1, (short)-1, (short)(SW_PIN_FAILED + triesRemaining - 1) );
            ISOException.throwIt((short)(SW_PIN_FAILED + triesRemaining - 1));
        }

        pin.update(buffer, (short) (ISO7816.OFFSET_CDATA + 1 + pin_size + 1), new_pin_size);

        return (short)0;
    }

    /**
     * This function unblocks a PIN number using the unblock code specified in the
     * DATA portion. The P3 byte specifies the unblock code length. 
     * If the PIN is blocked and the PUK is blocked, proceed to reset to factory.
     * 
     * ins: 0x46
     * p1: 0x00 (PUK number)
     * p2: 0x00
     * data: [PUK] 
     * return: none (throws an exception in case of wrong PUK)
     */
    private short UnblockPIN(APDU apdu, byte[] buffer) {
        byte pin_nb = buffer[ISO7816.OFFSET_P1];
        if (pin_nb  != 0)
            ISOException.throwIt(SW_INCORRECT_P1);
        if (buffer[ISO7816.OFFSET_P2] != 0x00)
            ISOException.throwIt(SW_INCORRECT_P2);
        
        // OwnerPIN pin = pins[pin_nb];
        // OwnerPIN ublk_pin = ublk_pins[pin_nb];
        if (pin == null)
            ISOException.throwIt(SW_INCORRECT_P1);
        if (ublk_pin == null)
            ISOException.throwIt(SW_INTERNAL_ERROR);
        // If the PIN is not blocked, the call is inconsistent
        if (pin.getTriesRemaining() != 0)
            ISOException.throwIt(SW_OPERATION_NOT_ALLOWED);
        short bytesLeft = Util.makeShort((byte) 0x00, buffer[ISO7816.OFFSET_LC]);
        /*
         * Here I suppose the PIN code is small enough to fit into the buffer
         * TODO: Verify the assumption and eventually adjust code to support
         * reading PIN in multiple read()s
         */
        if (!CheckPINPolicy(buffer, ISO7816.OFFSET_CDATA, (byte) bytesLeft))
            ISOException.throwIt(SW_INVALID_PARAMETER);
        byte triesRemaining = ublk_pin.getTriesRemaining();
        if (triesRemaining == (byte) 0x00)
            ISOException.throwIt(SW_IDENTITY_BLOCKED);
        if (!ublk_pin.check(buffer, ISO7816.OFFSET_CDATA, (byte) bytesLeft)){
            logger.createLog(INS_UNBLOCK_PIN, (short)-1, (short)-1, (short)(SW_PIN_FAILED + triesRemaining - 1) );
            // if PUK is blocked, proceed to factory reset
            if (ublk_pin.getTriesRemaining() == (byte) 0x00){
                resetToFactory();
                ISOException.throwIt(SW_RESET_TO_FACTORY);
            }
            ISOException.throwIt((short)(SW_PIN_FAILED + triesRemaining - 1));
        }

        pin.resetAndUnblock();

        return (short)0;
    }

    private short LogOutAll() {
        if (pin != null)
            pin.reset();
        return (short)0;
    }

    /****************************************
     *            Generic Methods           *
     ****************************************/

    /**
     * This function retrieves general information about the Applet running on the smart
     * card, and useful information about the status of current session such as:
     *      - applet version (4b)
     *  
     *  ins: 0x3C
     *  p1: 0x00 
     *  p2: 0x00 
     *  data: none
     *  return: [versions(4b) | PIN0-PUK0-PIN1-PUK1 tries (4b) | needs2FA (1b) | is_seeded(1b) | setupDone(1b) | needs_secure_channel(1b) | nfc_policy(1b)]
     */
    private short GetStatus(APDU apdu, byte[] buffer) {

        // applet version
        short pos = (short) 0;
        buffer[pos++] = PROTOCOL_MAJOR_VERSION; // Major Card Edge Protocol version n.
        buffer[pos++] = PROTOCOL_MINOR_VERSION; // Minor Card Edge Protocol version n.
        buffer[pos++] = APPLET_MAJOR_VERSION; // Major Applet version n.
        buffer[pos++] = APPLET_MINOR_VERSION; // Minor Applet version n.
        // PIN/PUK remaining tries available
        if (setupDone){
            buffer[pos++] = pin.getTriesRemaining();
            buffer[pos++] = ublk_pin.getTriesRemaining();
            buffer[pos++] = (byte) 0; //pins[1].getTriesRemaining();
            buffer[pos++] = (byte) 0; //ublk_pins[1].getTriesRemaining();
        } else {
            buffer[pos++] = (byte) 0;
            buffer[pos++] = (byte) 0;
            buffer[pos++] = (byte) 0;
            buffer[pos++] = (byte) 0;
        }
        // 2FA status
        if (needs2FA)
            buffer[pos++] = (byte)0x01;
        else
            buffer[pos++] = (byte)0x00;
        // RFU
        buffer[pos++] = (byte)0x00;
        // setup status
        if (setupDone)
            buffer[pos++] = (byte)0x01;
        else
            buffer[pos++] = (byte)0x00;
        // secure channel support
        if (needs_secure_channel)
            buffer[pos++] = (byte)0x01;
        else
            buffer[pos++] = (byte)0x00;
        // NFC policy
        buffer[pos++] = nfc_policy;

        return pos;
    }

    /**
     * This function returns the logs stored in the card
     *
     * This function must be initially called with the INIT option.
     * The function only returns one object information at a time and must be
     * called in repetition until SW_SUCCESS is returned with no further data.
     * Log are returned starting with the most recent log first.
     *
     * ins: 0xA9
     * p1: 0x00
     * p2: OP_INIT (reset and get first entry) or OP_PROCESS (next entry)
     * data: (none)
     * return:
     *      OP_INIT: [nbtotal_logs(2b) | nbavail_logs(2b)]
     *      OP_PROCESS: [logs(7b)]
     */
    private short printLogs(APDU apdu, byte[] buffer){
        // check that PIN[0] has been entered previously
        if (!pin.isValidated())
            ISOException.throwIt(SW_UNAUTHORIZED);

        short buffer_offset=(short)0;
        if (buffer[ISO7816.OFFSET_P2] == OP_INIT){
            boolean is_log= logger.getFirstRecord(buffer, buffer_offset);
            if (is_log)
                return (short)(4+Logger.LOG_SIZE);
            else
                return (short)4;
        }
        else if (buffer[ISO7816.OFFSET_P2] == OP_PROCESS){
            while(logger.getNextRecord(buffer, buffer_offset)){
                buffer_offset+=Logger.LOG_SIZE;
                if (buffer_offset>=128)
                    break;
            }
            return buffer_offset;
        }
        else{
            ISOException.throwIt(SW_INCORRECT_P2);
        }
        return buffer_offset;
    }

    /**
     * This function allows to define or recover a short description of the card.
     * 
     *  ins: 0x3D
     *  p1: 0x00 
     *  p2: operation (0x00 to set label, 0x01 to get label)
     *  data: [label_size(1b) | label ] if p2==0x00 else (none)
     *  return: [label_size(1b) | label ] if p2==0x01 else (none)
     */
    private short cardLabel(APDU apdu, byte[] buffer){
        // check that PIN[0] has been entered previously
        if (!pin.isValidated())
            ISOException.throwIt(SW_UNAUTHORIZED);
        
        byte op = buffer[ISO7816.OFFSET_P2];
        switch (op) {
            case 0x00: // set label
                short bytes_left = Util.makeShort((byte) 0x00, buffer[ISO7816.OFFSET_LC]);
                short buffer_offset = ISO7816.OFFSET_CDATA;
                if (bytes_left>0){
                    short label_size= Util.makeShort((byte) 0x00, buffer[buffer_offset]);
                    if (label_size>bytes_left)
                        ISOException.throwIt(SW_INVALID_PARAMETER);
                    if (label_size>MAX_CARD_LABEL_SIZE)
                        ISOException.throwIt(SW_INVALID_PARAMETER);
                    card_label_size= buffer[buffer_offset];
                    bytes_left--;
                    buffer_offset++;
                    Util.arrayCopyNonAtomic(buffer, buffer_offset, card_label, (short)0, label_size);
                }
                else if (bytes_left==0){//reset label
                    card_label_size= (byte)0x00;
                }
                return (short)0;
                
            case 0x01: // get label
                buffer[(short)0]=card_label_size;
                Util.arrayCopyNonAtomic(card_label, (short)0, buffer, (short)1, card_label_size);
                return (short)(card_label_size+1);
                
            default:
                ISOException.throwIt(SW_INCORRECT_P2);
                
        }//end switch()
        
        return (short)0;
    }

    /**
     * This function allows to define or recover a the NDEF data bytes.
     * The first byte of the ndef byte array is the size of the remaining bytes.
     * 
     *  ins: 0x3F
     *  p1: 0x00 
     *  p2: operation (0x00 to set NDEF, 0x01 to get NDEF)
     *  data: [ndef_size (1b) | ndef] if p2==0x00 else (none)
     *  return: [ndef_size(1b) | ndef] if p2==0x01 else (none)
     */
    private short cardNdef(APDU apdu, byte[] buffer){
        // check that PIN[0] has been entered previously
        if (!pin.isValidated())
            ISOException.throwIt(SW_UNAUTHORIZED);
        
        byte op = buffer[ISO7816.OFFSET_P2];
        switch (op) {
            case 0x00: // set ndef from buffer
                short bytes_left = Util.makeShort((byte) 0x00, buffer[ISO7816.OFFSET_LC]);
                short buffer_offset = ISO7816.OFFSET_CDATA;
                if (bytes_left>0){
                    short ndef_size = Util.makeShort((byte) 0x00, buffer[buffer_offset]);
                    if (ndef_size != (short)(bytes_left - 1)) {
                        ISOException.throwIt(SW_INVALID_PARAMETER);
                    }
                    if (bytes_left>SharedMemory.ndefDataFile.length)
                        ISOException.throwIt(SW_INVALID_PARAMETER);
                    Util.arrayCopyNonAtomic(buffer, buffer_offset, SharedMemory.ndefDataFile, (short)0, bytes_left);
                }
                else if (bytes_left==0){//reset ndef
                    SharedMemory.ndefDataFile[0] = (byte)0x00;
                }
                return (short)0;
                
            case 0x01: // get ndef
                short ndef_size = Util.makeShort((byte) 0x00, SharedMemory.ndefDataFile[0]);
                ndef_size++;
                Util.arrayCopyNonAtomic(SharedMemory.ndefDataFile, (short)0, buffer, (short)0, ndef_size);
                return ndef_size;
                
            default:
                ISOException.throwIt(SW_INCORRECT_P2);
                
        }//end switch()
        
        return (short)0;
    }

    /**
     * This function enables of disables the NFC interface.
     * By default, NFC interface is enabled. 
     * NFC access can only be changed through the contact interface.
     * PIN must be validated to use this function.
     * NFC access policy is defined with 1 byte:
     *  - NFC_ENABLED: NFC enabled
     *  - NFC_DISABLED: NFC disabled but can be reenabled
     *  - NFC_BLOCKED: NFC disabled and can only be reenable by factory reset!
     * 
     * 
     *  ins: 0x3E
     *  p1: NFC access policy
     *  p2: RFU (set specific permission policies for NFC interface)
     *  data: (none)
     *  return: (none)
     */
    private short setNfcPolicy(APDU apdu, byte[] buffer){
        // check that PIN has been entered previously
        if (!pin.isValidated())
            ISOException.throwIt(SW_UNAUTHORIZED);


        // check that the contact interface is used
        byte protocol = (byte) (APDU.getProtocol() & APDU.PROTOCOL_MEDIA_MASK);
        if (protocol != APDU.PROTOCOL_MEDIA_USB && protocol != APDU.PROTOCOL_MEDIA_DEFAULT) {
            ISOException.throwIt(SW_NFC_DISABLED);
        }

        // check if status change is allowed
        // if NFC is blocked, it is not allowed to unblock it, except via factory reset!
        if (nfc_policy == NFC_BLOCKED)
            ISOException.throwIt(SW_NFC_BLOCKED);

        // get new NFC status from P1
        byte nfc_policy_new = buffer[ISO7816.OFFSET_P1];
        if (nfc_policy_new<0 || nfc_policy_new>2)
            ISOException.throwIt(SW_INCORRECT_P1);

        // update NFC access policy
        nfc_policy = nfc_policy_new;

        return (short)0;
    }

    /**
     * DEPRECATED - use exportAuthentikey() instead.
     * This function is kept for backward compatibility with legacy satochip cards (where authentikey was derived from the seed).
     * 
     * This function returns the authentikey public key.
     * The function returns the x-coordinate of the authentikey, self-signed.
     * The authentikey full public key can be recovered from the signature.
     * 
     *  ins: 0x73
     *  p1: 0x00 
     *  p2: 0x00 
     *  data: none
     *  return: [coordx_size(2b) | coordx | sig_size(2b) | sig]
     */
    private short getBIP32AuthentiKey(APDU apdu, byte[] buffer){
        return getAuthentikey(apdu, buffer);
    }
    
    /**
     * This function returns the authentikey public key.
     * The function returns the x-coordinate of the authentikey, self-signed.
     * The authentikey full public key can be recovered from the signature.
     * 
     * Compared to getBIP32AuthentiKey(), this method returns the Authentikey even if the card is not seeded (for legacy satochip cards).
     * For SeedKeeper encrypted seed import, we use the authentikey as a Trusted Pubkey for the ECDH key exchange, 
     * thus the authentikey must be available before the Satochip is seeded. 
     * Before a seed is available, the authentiey is generated oncard randomly in the constructor
     * 
     *  ins: 0xAD
     *  p1: 0x00 
     *  p2: 0x00 
     *  data: none
     *  return: [coordx_size(2b) | coordx | sig_size(2b) | sig]
     */
    private short getAuthentikey(APDU apdu, byte[] buffer){
        // We don't require PIN for this functionality, since authentikey can be recovered 
        // from the authentikey signature in initiateSecureChannel()
        
        // get the partial authentikey public key...
        authentikey_public.getW(buffer, (short)1);
        Util.setShort(buffer, (short)0, BIP32_KEY_SIZE);
        // self signed public key
        sigECDSA.init(authentikey_private, Signature.MODE_SIGN);
        short sign_size= sigECDSA.sign(buffer, (short)0, (short)(BIP32_KEY_SIZE+2), buffer, (short)(BIP32_KEY_SIZE+4));
        Util.setShort(buffer, (short)(BIP32_KEY_SIZE+2), sign_size);
        
        // return x-coordinate of public key+signature
        // the client can recover full public-key from the signature or
        // by guessing the compression value () and verifying the signature... 
        // buffer= [coordx_size(2) | coordx | sigsize(2) | sig]
        return (short)(BIP32_KEY_SIZE+sign_size+4);
    }

    /******************************
     *       Secure Channel       *
     ******************************/

    /**
     * This function allows to initiate a Secure Channel
     *  
     *  ins: 0x81
     *  p1: 0x00
     *  p2: 0x00
     *  data: [client-pubkey(65b)]
     *  return: [coordx_size(2b) | ephemeralkey_coordx | sig_size(2b) | self_sig | sig2_size | authentikey_sig | coordx_size(2b) | authentikey_coordx]
     */
    private short InitiateSecureChannel(APDU apdu, byte[] buffer){

        // get client pubkey
        short bytesLeft = Util.makeShort((byte) 0x00, buffer[ISO7816.OFFSET_LC]);
        if (bytesLeft < (short)65)
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        if (buffer[ISO7816.OFFSET_CDATA] != (byte)0x04)
            ISOException.throwIt(SW_INVALID_PARAMETER);

        // generate a new ephemeral key
        sc_ephemeralkey.clearKey(); //todo: simply generate new random S param instead?
        Secp256k1.setCommonCurveParameters(sc_ephemeralkey);// keep public params!
        randomData.generateData(recvBuffer, (short)0, BIP32_KEY_SIZE);
        sc_ephemeralkey.setS(recvBuffer, (short)0, BIP32_KEY_SIZE); //random value first

        // compute the shared secret...
        keyAgreement.init(sc_ephemeralkey);        
        keyAgreement.generateSecret(buffer, ISO7816.OFFSET_CDATA, (short) 65, recvBuffer, (short)0); //pubkey in uncompressed form
        // derive sc_sessionkey & sc_mackey
        HmacSha160.computeHmacSha160(recvBuffer, (short)1, (short)32, CST_SC, (short)6, (short)6, recvBuffer, (short)33);
        Util.arrayCopyNonAtomic(recvBuffer, (short)33, sc_buffer, OFFSET_SC_MACKEY, SIZE_SC_MACKEY);
        HmacSha160.computeHmacSha160(recvBuffer, (short)1, (short)32, CST_SC, (short)0, (short)6, recvBuffer, (short)33);
        sc_sessionkey.setKey(recvBuffer,(short)33); // AES-128: 16-bytes key!!       

        //reset IV counter
        Util.arrayFillNonAtomic(sc_buffer, OFFSET_SC_IV, SIZE_SC_IV, (byte) 0);

        // self signed ephemeral pubkey
        keyAgreement.generateSecret(Secp256k1.SECP256K1, Secp256k1.OFFSET_SECP256K1_G, (short) 65, buffer, (short)1); //pubkey in uncompressed form
        Util.setShort(buffer, (short)0, BIP32_KEY_SIZE);
        sigECDSA.init(sc_ephemeralkey, Signature.MODE_SIGN);
        short sign_size= sigECDSA.sign(buffer, (short)0, (short)(BIP32_KEY_SIZE+2), buffer, (short)(BIP32_KEY_SIZE+4));
        Util.setShort(buffer, (short)(BIP32_KEY_SIZE+2), sign_size);

        // hash signed by authentikey
        short offset= (short)(2+BIP32_KEY_SIZE+2+sign_size);
        sigECDSA.init(authentikey_private, Signature.MODE_SIGN);
        short sign2_size= sigECDSA.sign(buffer, (short)0, offset, buffer, (short)(offset+2));
        Util.setShort(buffer, offset, sign2_size);
        offset+=(short)(2+sign2_size);

        // add coordx for authentikey (allows for non-ambiguous recovery of pubkey using signature)
        authentikey_public.getW(buffer, (short)(offset+1));
        Util.setShort(buffer, offset, BIP32_KEY_SIZE);
        offset+=(short)(2+BIP32_KEY_SIZE);

        initialized_secure_channel= true;

        // return x-coordinate of public key+signature
        // the client can recover full public-key from the signature or
        // by guessing the compression value () and verifying the signature... 
        // buffer= [coordx_size(2) | coordx | sigsize(2) | sig | sig2_size(optional) | sig2(optional)]
        return offset;
    }

    /**
     * This function allows to decrypt a secure channel message
     *  
     *  ins: 0x82
     *  
     *  p1: 0x00 (RFU)
     *  p2: 0x00 (RFU)
     *  data: [IV(16b) | data_size(2b) | encrypted_command | mac_size(2b) | mac]
     *  
     *  return: [decrypted command]
     *   
     */
    private short ProcessSecureChannel(APDU apdu, byte[] buffer){

        short bytesLeft = Util.makeShort((byte) 0x00, buffer[ISO7816.OFFSET_LC]);
        short offset = ISO7816.OFFSET_CDATA;

        if (!initialized_secure_channel){
            ISOException.throwIt(SW_SECURE_CHANNEL_UNINITIALIZED);
        }

        // check hmac
        if (bytesLeft<18)
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        short sizein = Util.getShort(buffer, (short) (offset+SIZE_SC_IV));
        if (bytesLeft<(short)(SIZE_SC_IV+2+sizein+2))
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        short sizemac= Util.getShort(buffer, (short) (offset+SIZE_SC_IV+2+sizein));
        if (sizemac != (short)20)
            ISOException.throwIt(SW_SECURE_CHANNEL_WRONG_MAC);
        if (bytesLeft<(short)(SIZE_SC_IV+2+sizein+2+sizemac))
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        HmacSha160.computeHmacSha160(sc_buffer, OFFSET_SC_MACKEY, SIZE_SC_MACKEY, buffer, offset, (short)(SIZE_SC_IV+2+sizein), tmpBuffer2, (short)0);
        if ( Util.arrayCompare(tmpBuffer2, (short)0, buffer, (short)(offset+SIZE_SC_IV+2+sizein+2), (short)20) != (byte)0 )
            ISOException.throwIt(SW_SECURE_CHANNEL_WRONG_MAC);

        // process IV
        // IV received from client should be odd and strictly greater than locally saved IV
        // IV should be random (the 12 first bytes), never reused (the last 4 bytes counter) and different for send and receive
        if ((buffer[(short)(offset+SIZE_SC_IV-(short)1)] & (byte)0x01)==0x00)// should be odd
            ISOException.throwIt(SW_SECURE_CHANNEL_WRONG_IV);
        if ( !Biginteger.lessThan(sc_buffer, OFFSET_SC_IV_COUNTER, buffer, (short)(offset+SIZE_SC_IV_RANDOM), SIZE_SC_IV_COUNTER ) ) //and greater than local IV
            ISOException.throwIt(SW_SECURE_CHANNEL_WRONG_IV);
        // update local IV
        Util.arrayCopy(buffer, (short)(offset+SIZE_SC_IV_RANDOM), sc_buffer, OFFSET_SC_IV_COUNTER, SIZE_SC_IV_COUNTER);
        Biginteger.add1_carry(sc_buffer, OFFSET_SC_IV_COUNTER, SIZE_SC_IV_COUNTER);
        randomData.generateData(sc_buffer, OFFSET_SC_IV_RANDOM, SIZE_SC_IV_RANDOM);
        sc_aes128_cbc.init(sc_sessionkey, Cipher.MODE_DECRYPT, buffer, offset, SIZE_SC_IV);
        offset+=SIZE_SC_IV;
        bytesLeft-=SIZE_SC_IV;

        //decrypt command
        offset+=2;
        bytesLeft-=2;
        if (bytesLeft<sizein)
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        short sizeout=sc_aes128_cbc.doFinal(buffer, offset, sizein, buffer, (short) (0));
        return sizeout;
    }
    
    
    /*********************************************
     *      Methods for PKI personalization      *
     *********************************************/
    
    /**
     * This function is used to self-sign the CSR of the device
     *  
     *  ins: 0x94
     *  p1: 0x00  
     *  p2: 0x00 
     *  data: [hash(32b)]
     *  return: [signature]
     */
    private short sign_PKI_CSR(APDU apdu, byte[] buffer) {
        if (personalizationDone)
            ISOException.throwIt(SW_PKI_ALREADY_LOCKED);
        
        // check that PIN[0] has been entered previously
        if (pin != null && !pin.isValidated())
            ISOException.throwIt(SW_UNAUTHORIZED);        
        
        short bytesLeft = Util.makeShort((byte) 0x00, buffer[ISO7816.OFFSET_LC]);
        if (bytesLeft < (short)32)
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        
        sigECDSA.init(authentikey_private, Signature.MODE_SIGN);
        short sign_size= sigECDSA.signPreComputedHash(buffer, ISO7816.OFFSET_CDATA, MessageDigest.LENGTH_SHA_256, buffer, (short)0);
        return sign_size;
    }
    
    /**
     * This function export the ECDSA secp256k1 public key that corresponds to the private key
     *  
     *  ins: 
     *  p1: 0x00
     *  p2: 0x00 
     *  data: [none]
     *  return: [ pubkey (65b) ]
     */
    private short export_PKI_pubkey(APDU apdu, byte[] buffer) {
        // We don't require PIN for this functionality, since authentikey can be recovered 
        // from the authentikey signature in initiateSecureChannel()
        
        authentikey_public.getW(buffer, (short)0); 
        return (short)65;
    }
    
    /**
     * This function imports the device certificate
     *  
     *  ins: 
     *  p1: 0x00
     *  p2: Init-Update 
     *  data(init): [ full_size(2b) ]
     *  data(update): [chunk_offset(2b) | chunk_size(2b) | chunk_data ]
     *  return: [none]
     */
    private short import_PKI_certificate(APDU apdu, byte[] buffer) {
        if (personalizationDone)
            ISOException.throwIt(SW_PKI_ALREADY_LOCKED);
        
        // check that PIN[0] has been entered previously
        if (pin != null && !pin.isValidated())
            ISOException.throwIt(SW_UNAUTHORIZED);
        
        short bytesLeft = Util.makeShort((byte) 0x00, buffer[ISO7816.OFFSET_LC]);
        short buffer_offset = (short) (ISO7816.OFFSET_CDATA);
        
        byte op = buffer[ISO7816.OFFSET_P2];
        switch(op){
            case OP_INIT:
                if (bytesLeft < (short)2)
                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                
                short new_certificate_size=Util.getShort(buffer, buffer_offset);
                if (new_certificate_size < 0)
                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                if (authentikey_certificate==null){
                    // create array
                    authentikey_certificate= new byte[new_certificate_size];
                    authentikey_certificate_size=new_certificate_size;
                }else{
                    if (new_certificate_size>authentikey_certificate.length)
                        ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                    authentikey_certificate_size=new_certificate_size;
                }
                break;
                
            case OP_PROCESS: 
                if (bytesLeft < (short)4)
                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                short chunk_offset= Util.getShort(buffer, buffer_offset);
                buffer_offset+=2;
                short chunk_size= Util.getShort(buffer, buffer_offset);
                buffer_offset+=2;
                bytesLeft-=4;
                if (bytesLeft < chunk_size)
                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                if ((chunk_offset<0) || (chunk_offset>=authentikey_certificate_size))
                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                if (((short)(chunk_offset+chunk_size))>authentikey_certificate_size)
                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                
                Util.arrayCopyNonAtomic(buffer, buffer_offset, authentikey_certificate, chunk_offset, chunk_size);
                break;
                
            default:
                ISOException.throwIt(SW_INCORRECT_P2);
        }
        return (short)0;
    }
    
    /**
     * This function exports the device certificate
     *  
     *  ins: 
     *  p1: 0x00  
     *  p2: Init-Update 
     *  data(init): [ none ]
     *  return(init): [ full_size(2b) ]
     *  data(update): [ chunk_offset(2b) | chunk_size(2b) ]
     *  return(update): [ chunk_data ] 
     */
    private short export_PKI_certificate(APDU apdu, byte[] buffer) {
        // check that PIN[0] has been entered previously
        if (pin != null && !pin.isValidated())
            ISOException.throwIt(SW_UNAUTHORIZED);
        
        byte op = buffer[ISO7816.OFFSET_P2];
        switch(op){
            case OP_INIT:
                Util.setShort(buffer, (short)0, authentikey_certificate_size);
                return (short)2; 
                
            case OP_PROCESS: 
                short bytesLeft = Util.makeShort((byte) 0x00, buffer[ISO7816.OFFSET_LC]);
                if (bytesLeft < (short)4)
                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                
                short buffer_offset = (short) (ISO7816.OFFSET_CDATA);
                short chunk_offset= Util.getShort(buffer, buffer_offset);
                buffer_offset+=2;
                short chunk_size= Util.getShort(buffer, buffer_offset);
                
                if ((chunk_offset<0) || (chunk_offset>=authentikey_certificate_size))
                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                if (((short)(chunk_offset+chunk_size))>authentikey_certificate_size)
                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                Util.arrayCopyNonAtomic(authentikey_certificate, chunk_offset, buffer, (short)0, chunk_size);
                return chunk_size; 
                
            default:
                ISOException.throwIt(SW_INCORRECT_P2);
                return (short)0; 
        }
    }
    
    /**
     * This function locks the PKI config.
     * Once it is locked, it is not possible to modify private key, certificate or allowed_card_AID.
     *  
     *  ins: 
     *  p1: 0x00 
     *  p2: 0x00 
     *  data: [none]
     *  return: [none]
     */
    private short lock_PKI(APDU apdu, byte[] buffer) {
        if (pin != null  && !pin.isValidated())
            ISOException.throwIt(SW_UNAUTHORIZED);
        personalizationDone=true;
        return (short)0;
    }
    
    /**
     * This function performs a challenge-response to verify the authenticity of the device.
     * The challenge is made of three parts: 
     *          - a constant header
     *          - a 32-byte challenge provided by the requester
     *          - a 32-byte random nonce generated by the device
     * The response is the signature over this challenge. 
     * This signature can be verified with the certificate stored in the device.
     * 
     *  ins: 
     *  p1: 0x00 
     *  p2: 0x00 
     *  data: [challenge1(32b)]
     *  return: [challenge2(32b) | sig_size(2b) | sig]
     */
    private short challenge_response_pki(APDU apdu, byte[] buffer) {
        // todo: require PIN?
        if (!pin.isValidated())
            ISOException.throwIt(SW_UNAUTHORIZED);
        
        short bytesLeft = Util.makeShort((byte) 0x00, buffer[ISO7816.OFFSET_LC]);
        if (bytesLeft < (short)32)
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        
        //copy all data into array
        short offset=(short)0;
        Util.arrayCopyNonAtomic(PKI_CHALLENGE_MSG, (short)0, recvBuffer, offset, (short)PKI_CHALLENGE_MSG.length);
        offset+=PKI_CHALLENGE_MSG.length;
        randomData.generateData(recvBuffer, offset, (short)32);
        offset+=(short)32;
        Util.arrayCopyNonAtomic(buffer, ISO7816.OFFSET_CDATA, recvBuffer, offset, (short)32);
        offset+=(short)32;
         
        //sign challenge
        sigECDSA.init(authentikey_private, Signature.MODE_SIGN);
        short sign_size= sigECDSA.sign(recvBuffer, (short)0, offset, buffer, (short)34);
        Util.setShort(buffer, (short)32, sign_size);
        Util.arrayCopyNonAtomic(recvBuffer, (short)PKI_CHALLENGE_MSG.length, buffer, (short)0, (short)32);
        
        // verify response
        sigECDSA.init(authentikey_public, Signature.MODE_VERIFY);
        boolean is_valid= sigECDSA.verify(recvBuffer, (short)0, offset, buffer, (short)(34), sign_size);
        if (!is_valid)
            ISOException.throwIt(SW_SIGNATURE_INVALID);
        
        return (short)(32+2+sign_size);
    }

} // end of class JAVA_APPLET

