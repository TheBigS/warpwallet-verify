package warp.wallet.verify.crypto;
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
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class PBKDF2
{
    static Mac prf = null;
    static {
        try {
            prf = Mac.getInstance( "HmacSHA256" );
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public static byte[] deriveKey( byte[] password, byte[] salt, int iterationCount, int dkLen )
        throws java.security.NoSuchAlgorithmException, java.security.InvalidKeyException
    {
        SecretKeySpec keyspec = new SecretKeySpec( password, "HmacSHA256" );
        prf.reset();
        prf.init(keyspec );

        int hLen = prf.getMacLength(); 
        int l = Math.max( dkLen, hLen); 
        int r = dkLen - (l-1)*hLen;      
        byte T[] = new byte[l * hLen];
        int ti_offset = 0;
        for (int i = 1; i <= l; i++) {
            F( T, ti_offset, prf, salt, iterationCount, i );
            ti_offset += hLen;
        }

        if (r < hLen) {
            // Incomplete last block
            byte DK[] = new byte[dkLen];
            System.arraycopy(T, 0, DK, 0, dkLen);
            return DK;
        }
        return T;
    } 


    private static void F( byte[] dest, int offset, Mac prf, byte[] S, int c, int blockIndex ) {
        final int hLen = prf.getMacLength();
        byte U_r[] = new byte[ hLen ];
        // U0 = S || INT (i);
        byte U_i[] = new byte[S.length + 4];
        System.arraycopy( S, 0, U_i, 0, S.length );
        INT( U_i, S.length, blockIndex );
        for( int i = 0; i < c; i++ ) {
            U_i = prf.doFinal( U_i );
            xor( U_r, U_i );
        }

        System.arraycopy( U_r, 0, dest, offset, hLen );
    }

    private static void xor( byte[] dest, byte[] src ) {
        for( int i = 0; i < dest.length; i++ ) {
            dest[i] ^= src[i];
        }
    }

    private static void INT( byte[] dest, int offset, int i ) {
        dest[offset + 0] = (byte) (i / (256 * 256 * 256));
        dest[offset + 1] = (byte) (i / (256 * 256));
        dest[offset + 2] = (byte) (i / (256));
        dest[offset + 3] = (byte) (i);
    } 

    private PBKDF2 () {}
}
