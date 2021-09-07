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

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Base64;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.util.*;
import java.lang.System;
import java.lang.String;

import java.util.ArrayList;
import java.util.Collections;
/**
 * Demonstrate basic RSA operations.
 */
public class RSAOperationsRunner {
    /**
     * Encrypt plainText using the passed transformation.
     * Supported transformations are documented here: https://docs.aws.amazon.com/cloudhsm/latest/userguide/java-lib-supported.html
     *
     * @param transformation
     * @param key
     * @param plainText
     * @return
     * @throws InvalidKeyException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     * @throws NoSuchPaddingException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     */
    public static byte[] encrypt(String transformation, Key key, byte[] plainText)
            throws InvalidKeyException,
            NoSuchAlgorithmException,
            NoSuchProviderException,
            NoSuchPaddingException,
            IllegalBlockSizeException,
            BadPaddingException {
        Cipher encCipher = Cipher.getInstance(transformation, "Cavium");
        encCipher.init(Cipher.ENCRYPT_MODE, key);
        return encCipher.doFinal(plainText);
    }

    /**
     * Decrypt cipherText using the passed transformation.
     * Supported transformations are documented here: https://docs.aws.amazon.com/cloudhsm/latest/userguide/java-lib-supported.html
     *
     * @param transformation
     * @param key
     * @param cipherText
     * @return
     * @throws InvalidKeyException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     * @throws NoSuchPaddingException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     */
    public static byte[] decrypt(String transformation, Key key, byte[] cipherText)
            throws InvalidKeyException,
            NoSuchAlgorithmException,
            NoSuchProviderException,
            NoSuchPaddingException,
            IllegalBlockSizeException,
            BadPaddingException {
        Cipher decCipher = Cipher.getInstance(transformation, "Cavium");
        decCipher.init(Cipher.DECRYPT_MODE, key);
        return decCipher.doFinal(cipherText);
    }

    /**
     * Sign a message using the passed signing algorithm.
     * Supported signature types are documented here: https://docs.aws.amazon.com/cloudhsm/latest/userguide/java-lib-supported.html
     *
     * @param message
     * @param key
     * @param signingAlgorithm
     * @return
     * @throws SignatureException
     * @throws InvalidKeyException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     */
    public static byte[] sign(byte[] message, PrivateKey key, String signingAlgorithm)
            throws SignatureException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException {
        Signature sig = Signature.getInstance(signingAlgorithm, "Cavium");
        sig.initSign(key);
        sig.update(message);
        return sig.sign();
    }

    /**
     * Verify the signature of a message.
     * Supported signature types are documented here: https://docs.aws.amazon.com/cloudhsm/latest/userguide/java-lib-supported.html
     *
     * @param message
     * @param signature
     * @param publicKey
     * @param signingAlgorithm
     * @return
     * @throws SignatureException
     * @throws InvalidKeyException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     */
    public static boolean verify(byte[] message, byte[] signature, PublicKey publicKey, String signingAlgorithm)
            throws SignatureException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException {
        Signature sig = Signature.getInstance(signingAlgorithm, "Cavium");
        sig.initVerify(publicKey);
        sig.update(message);
        return sig.verify(signature);
    }

    public static void main(final String[] args) throws Exception {
        ArrayList<Long> arr_cavium_provider = new ArrayList<>();
        ArrayList<Long> arr_gen_rsa_key_pair = new ArrayList<>();
        ArrayList<Long> arr_RSA_Encryption = new ArrayList<>();
        ArrayList<Long> arr_RSA_Decryption = new ArrayList<>();
        ArrayList<Long> arr_sign = new ArrayList<>();
        ArrayList<Long> arr_verify = new ArrayList<>();

        for(int x = 0; x < 1000; ++x) {
            try {
                long start = start_timer("CAVIUM PROVIDER");
                Security.addProvider(new com.cavium.provider.CaviumProvider());
                arr_cavium_provider.add(end_timer(start));
            } catch (IOException ex) {
                System.out.println(ex);
                return;
            }

            String plainText = "This is a sample Plain Text Message!";
            String transformation = "RSA/ECB/OAEPPadding";

            long start1 = start_timer("Gernate RSA Key Pair");
            KeyPair kp = new AsymmetricKeys().generateRSAKeyPair(2048, "rsa test");
            arr_gen_rsa_key_pair.add(end_timer(start1));

            long start2 = start_timer("Performing RSA Encryption Operation");
            byte[] cipherText = null;
            cipherText = encrypt(transformation, kp.getPublic(), plainText.getBytes("UTF-8"));
            arr_RSA_Encryption.add(end_timer(start2));

            // System.out.println("Encrypted plaintext = " + Base64.getEncoder().encodeToString(cipherText));

            long start3 = start_timer("Performing RSA Decryption Operation");
            byte[] decryptedText = decrypt(transformation, kp.getPrivate(), cipherText);
            arr_RSA_Decryption.add(end_timer(start3));
            // System.out.println("Decrypted text = " + new String(decryptedText, "UTF-8"));

            String signingAlgorithm = "SHA512withRSA/PSS";
            long start4 = start_timer("Sign a message using the passed signing algorithm. SHA512withRSA/PSS");
            byte[] signature = sign(plainText.getBytes("UTF-8"), kp.getPrivate(), signingAlgorithm);
            // System.out.println("Plaintext signature = " + Base64.getEncoder().encodeToString(signature));
            arr_sign.add(end_timer(start4));

            long start5 = start_timer("Verify RSA Signature");
            if (verify(plainText.getBytes("UTF-8"), signature, kp.getPublic(), signingAlgorithm)) {
                System.out.println("Signature verified");
            } else {
                System.out.println("Signature is invalid!");
            }
            arr_verify.add(end_timer(start5));
        }
        output_results(arr_cavium_provider, "CAVIUM PROVIDER CREATION");
        output_results(arr_gen_rsa_key_pair, "Gernate RSA Key Pair");
        output_results(arr_RSA_Encryption, "Performing RSA Encryption Operation");
        output_results(arr_RSA_Decryption, "Performing RSA Decryption Operation");
        output_results(arr_sign, "Sign a message using the passed signing algorithm. SHA512withRSA/PSS");
        output_results(arr_verify, "Verify RSA Signature");

    }

    // --------------------------------------------------------------------------------------------------------
    // --------------------------------------------------------------------------------------------------------
    // Nick's Output

    private static long start_timer(String operation) {
        // System.out.println("---------------- Operation:\t" + operation);
        long start = System.currentTimeMillis();
        // System.out.println("-------------------- Start At:\t" + String.valueOf(start) + " ms");
        return start;
    }

    private static long end_timer(long start) {
        long end = System.currentTimeMillis();
        // System.out.println("-------------------- End At:\t" + String.valueOf(end) + " ms");
        long totaltime = end - start;
        // System.out.println("-------------------- TOTAL TIME:\t" + String.valueOf(totaltime) + " ms\n\n");
        return totaltime;
    }

    private static long average_arr(ArrayList<Long> cur) {

        long total = 0;
        for(int x = 0; x < cur.size(); ++x) {
            total = total + cur.get(x);
        }

        long average = total / cur.size();

        return average;
    }

    private static void output_results(ArrayList<Long> cur_arr, String description) {
        System.out.println("---------------- Operation:\t" + description);

        long average = average_arr(cur_arr);
        System.out.println("----------- Average MS:\t" + String.valueOf(average) + " ms");

        Collections.sort(cur_arr);
        long min = cur_arr.get(0);
        System.out.println("----------- Min MS:\t" + String.valueOf(min) + " ms");

        Long max = cur_arr.get(cur_arr.size()-2);
        System.out.println("----------- Max MS:\t" + String.valueOf(max) + " ms");

        
        System.out.println("------ Array Size:\t" + String.valueOf(cur_arr.size()));
    }
}

