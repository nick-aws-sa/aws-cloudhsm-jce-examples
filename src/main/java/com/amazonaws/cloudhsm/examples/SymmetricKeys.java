/*
 * Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this
 * software and associated documentation files (the "Software"), to deal in the Software
 * without restriction, including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
 * INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
 * PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
package com.amazonaws.cloudhsm.examples;

import com.cavium.key.parameter.CaviumAESKeyGenParameterSpec;
import com.cavium.key.parameter.CaviumDESKeyGenParameterSpec;

import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import java.lang.String;
import java.util.*;
import java.lang.System;

/**
 * Symmetric key generation examples.
 */
public class SymmetricKeys {
    /**
     * Generate an AES key.
     * In this example method, the key is never persistent and is never extractable.
     *
     * @param keySizeInBits Size of the key.
     * @param keyLabel      Label to associate with the key.
     * @return Key object
     */
    public static Key generateAESKey(int keySizeInBits, String keyLabel)
            throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {
        boolean isExtractable = false;
        boolean isPersistent = false;

        // long start0 = start_timer("KeyGenerator.getInstance - Cavium");
        KeyGenerator keyGen = KeyGenerator.getInstance("AES", "Cavium");
        // end_timer(start0);
        
        

        // long start1 = start_timer("Crate Cavium AES Spec");
        CaviumAESKeyGenParameterSpec aesSpec = new CaviumAESKeyGenParameterSpec(keySizeInBits, keyLabel, isExtractable, isPersistent);

        keyGen.init(aesSpec);
        // end_timer(start1);
        
        
        // long start3 = start_timer("Generate AES Key ");
        SecretKey aesKey = keyGen.generateKey();
        // end_timer(start3);

        return aesKey;
    }

    /**
     * Generate an extractable AES key.
     * In this example method, the key is extractable and is never persistent.
     *
     * @param keySizeInBits Size of the key.
     * @param keyLabel      Label to associate with the key.
     * @return Key object
     */
    public static Key generateExtractableAESKey(int keySizeInBits, String keyLabel)
            throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {
        boolean isExtractable = true;
        boolean isPersistent = false;

        KeyGenerator keyGen = KeyGenerator.getInstance("AES", "Cavium");

        CaviumAESKeyGenParameterSpec aesSpec = new CaviumAESKeyGenParameterSpec(keySizeInBits, keyLabel, isExtractable, isPersistent);
        keyGen.init(aesSpec);
        SecretKey aesKey = keyGen.generateKey();

        return aesKey;
    }

    /**
     * Generate a DES key.
     * In this example method, the key is never persistent and is never extractable.
     *
     * @param keyLabel
     * @return Key object
     * @throws InvalidAlgorithmParameterException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     */
    public static Key generateDESKey(String keyLabel)
            throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {
        boolean isExtractable = false;
        boolean isPersistent = false;

        KeyGenerator keyGen = KeyGenerator.getInstance("DESede", "Cavium");

        CaviumDESKeyGenParameterSpec desSpec = new CaviumDESKeyGenParameterSpec(192, keyLabel, isExtractable, isPersistent);
        keyGen.init(desSpec);
        SecretKey des3Key = keyGen.generateKey();
        return des3Key;
    }


    // --------------------------------------------------------------------------------------------------------
    // --------------------------------------------------------------------------------------------------------
    // Nick's Output

    private static long start_timer(String operation) {
        System.out.println("---------------- Operation:\t" + operation);
        long start = System.currentTimeMillis();
        System.out.println("-------------------- Start At:\t" + String.valueOf(start) + " ms");
        return start;
    }

    private static void end_timer(long start) {
        long end = System.currentTimeMillis();
        System.out.println("-------------------- End At:\t" + String.valueOf(end) + " ms");
        long totaltime = end - start;
        System.out.println("-------------------- TOTAL TIME:\t" + String.valueOf(totaltime) + " ms\n\n");
    }
}
