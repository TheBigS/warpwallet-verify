package warp.wallet.verify.bitcoin;
/**
 * Copyright 2014 TheBigS (github.com/TheBigS)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
import java.security.GeneralSecurityException;

import warp.wallet.verify.crypto.Base58;
import warp.wallet.verify.crypto.PBKDF2;
import warp.wallet.verify.crypto.util.Util;

import com.lambdaworks.crypto.SCrypt;

public class VerifyBitcoin {

    public static void main ( String[] args ) throws GeneralSecurityException {
        String password = "";
        String salt = "";
        if (args.length >= 1 ) password = args[0];
        if (args.length == 2 ) salt = args[1];
        if (args.length == 0 ) {
            System.err.println("Usage: <password> [salt]");
            System.exit(-1);
        }
        
        System.out.println("Password: " + password);
        System.out.println("Salt: " + salt);
        
        // SCrypt
        byte [] pass1 = Util.concatByteArrays(password.getBytes(), new byte[]{0x01});
        byte [] salt1 = new byte[0];
        if ( salt != null ) {
            salt1 = Util.concatByteArrays(salt.getBytes(), new byte[]{0x01});
        }
        // N=2^18, r=8, p=1, dkLen=32
        byte [] s1 = SCrypt.scrypt(pass1, salt1, 262144, 8, 1, 32);
        System.out.println("SCrypt Result: " + Util.toHexString(s1));
        
        // PBKDF2_HMACSHA256
        byte [] pass2 = Util.concatByteArrays(password.getBytes(), new byte[]{0x02});
        byte [] salt2 = new byte[0];
        if ( salt != null ) {
            salt2 = Util.concatByteArrays(salt.getBytes(), new byte[]{0x02});
        }
        // c=2^16, dkLen=32, prf=HMAC_SHA256
        byte [] s2 = PBKDF2.deriveKey(pass2, salt2, 65536, 32);
        System.out.println("PBKDF2 Result: " + Util.toHexString(s2));
        
        // XOR the SCrypt and PBKDF2 results together to generate private key bytes
        byte[] privateKey = Util.xorByteArrays(s1, s2);
        System.out.println("Private Key  : " + Util.toHexString(privateKey));
        
        // BASE-58 Check-Encode private key (Bitcoin's private key version = 0x80)
        System.out.println("Private Key Encoded : " + Base58.encodeCheckSum(0x80, privateKey));
    }
}
