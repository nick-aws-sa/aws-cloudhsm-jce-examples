/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import sun.security.util.KeyUtil;

import java.lang.String;
import java.util.*;
import java.lang.System;
import java.util.ArrayList;
import java.util.Collections;

/**
 * Demonstrate how to generate keys
 */
public class ECDHOperationsRunner {

    public static void main(final String[] args) throws Exception {
        ArrayList<Long> arr_cavium_provider = new ArrayList<>();
        ArrayList<Long> keypairinhsm = new ArrayList<>();
        ArrayList<Long> sunecprovider = new ArrayList<>();
        ArrayList<Long> keypairAprivatekeysecgen = new ArrayList<>();
        ArrayList<Long> keypairBprivatekeysecgen = new ArrayList<>();
        ArrayList<Long> arr_gen_secret_keys = new ArrayList<>();
        

        for(int x = 0; x < 1000; ++x) {
            try {
                long start = start_timer("CAVIUM PROVIDER CREATION");
                Security.addProvider(new com.cavium.provider.CaviumProvider());
                arr_cavium_provider.add(end_timer(start));

                //Add another provider. SunEC is used as an example here.
                Security.addProvider(new sun.security.ec.SunEC());
            } catch (IOException ex) {
                System.out.println(ex);
                return;
            }

            final String CURVE_ID = "secp256r1";

            //There is a EC key pair in HSM
            long start0 = start_timer("Generate a EC key pair in HSM");
            KeyPairGenerator keyPairGenA = KeyPairGenerator.getInstance("EC", "Cavium");
            keyPairGenA.initialize(new ECGenParameterSpec(CURVE_ID));
            KeyPair keyPairA = keyPairGenA.generateKeyPair();
            keypairinhsm.add(end_timer(start0));

            //There is a EC key pair externally. Lets say with SunEC provider.
            long start1 = start_timer("Generate a EC key pair from SunEC provider(external to HSM) - with the same Curve");
            KeyPairGenerator keyPairGenB = KeyPairGenerator.getInstance("EC", "SunEC");
            keyPairGenB.initialize(new ECGenParameterSpec(CURVE_ID)); //We need to use the same Curve on both the sides.
            KeyPair keyPairB = keyPairGenB.generateKeyPair();
            sunecprovider.add(end_timer(start1));

            //Each side computes the shared key using its own private key and public key from the other side

            //Use keyPairA's private key and keyPairB's public key to generate a secret. This has to be Cavium provider as keyPairA's private key is in HSM and non-extractable by default.
            long start2 = start_timer("Use HSM private key and SunEC public key to generate a secret.");
            KeyAgreement keyAgreementA = KeyAgreement.getInstance("ECDH", "Cavium");
            keyAgreementA.init(keyPairA.getPrivate());
            keyAgreementA.doPhase(keyPairB.getPublic(), true);
            byte[] secretXBytes = keyAgreementA.generateSecret();
            keypairAprivatekeysecgen.add(end_timer(start2));

            //Use keyPairB's private key and keyPairA's public key to generate a secret.
            long start3 = start_timer("Use SunEC private key and HSM public key to generate a secret");
            KeyAgreement keyAgreementB = KeyAgreement.getInstance("ECDH", "SunEC");
            keyAgreementB.init(keyPairB.getPrivate());
            keyAgreementB.doPhase(keyPairA.getPublic(), true);
            byte[] secretYBytes = keyAgreementB.generateSecret();
            keypairBprivatekeysecgen.add(end_timer(start3));

            //These byte[] should be identical.
            // System.out.println("Secret X: Length = " + secretXBytes.length +", Base64 = " + Base64.getEncoder().encodeToString(secretXBytes));
            // System.out.println("Secret Y: Length = " + secretYBytes.length +", Base64 = " + Base64.getEncoder().encodeToString(secretYBytes));

            //Each side can now convert this into a secret key.
            long start4 = start_timer("After Agreement Secret Generattion, convert bytes to secret key for use");
            SecretKey keyA = new SecretKeySpec(KeyUtil.trimZeroes(secretXBytes), "TlsPremasterSecret");
            SecretKey keyB = new SecretKeySpec(KeyUtil.trimZeroes(secretYBytes), "TlsPremasterSecret");
            arr_gen_secret_keys.add(end_timer(start4));

            // if(Arrays.equals(keyA.getEncoded(), keyB.getEncoded())) {
            //     System.out.println("Secret Keys are same!");
            // } else {
            //     System.out.println("Secret Keys are different!");
            // }
        }
        output_results(arr_cavium_provider, "CAVIUM PROVIDER CREATION");
        output_results(keypairinhsm, "Generate a EC key pair in HSM");
        output_results(sunecprovider, "Generate a EC key pair from SunEC provider(external to HSM) - with the same Curve");
        output_results(keypairAprivatekeysecgen, "Use HSM private key and SunEC public key to generate a secret.");
        output_results(keypairBprivatekeysecgen, "Use SunEC private key and HSM public key to generate a secret");
        output_results(arr_gen_secret_keys, "After Agreement Secret Generattion, convert bytes to secret key for use");
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
