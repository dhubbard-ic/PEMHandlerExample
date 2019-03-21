/* 
 * Copyright (C) 2019 InfraCentric Limited 
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.infracentric.pemhandler;

import java.io.File;
import java.io.IOException;
import java.security.interfaces.RSAPublicKey;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author david
 */
public class PemHandlingTest {

    private String here = System.getProperty("user.dir");
    
    public PemHandlingTest() {
        
    }
    
    @BeforeClass
    public static void setUpClass() {
    }
    
    @AfterClass
    public static void tearDownClass() {
    }
    
    @Before
    public void setUp() {
    }
    
    @After
    public void tearDown() {
    }

    @Test
    public void generateKeyTest() {
         
        String comment = "Test key";
        String filename = here + "/temp.pem";
        
        PemHandler ph = new PemHandler();
         
        try {
            ph.generateKeys(comment);
            
        } catch (PemHandlingException ex) {
            Assert.assertTrue("Exception on Generate ["+ex.getLocalizedMessage()+"]", false);
        }
     
        try {
            ph.storePrivateKey(filename);    // note: default forces stored file to end with .pem
        } catch (PemHandlingException ex) {
            Assert.assertTrue("Exception on Store ["+ex.getLocalizedMessage()+"]", false);
        }
        
        File pkey = new File(filename);
        try {
            RSAPublicKey pubKey = ph.getPublicFromPrivateKey(pkey, null);
                    
        } catch (PemHandlingException ex) {
            Assert.assertTrue("Exception on get Public From Private["+ex.getLocalizedMessage()+"]", false);
        }
        
        try {
            boolean privateKeyEncrypted = ph.isPrivateKeyEncrypted(pkey);            
            Assert.assertFalse("Encryption check on unencrypted key fails", privateKeyEncrypted);
            
        } catch (IOException ex) {
            Assert.assertTrue("Exception on check of encryption ["+ex.getLocalizedMessage()+"]", false);
        }
        
        try {
            String publicKeyForHost = ph.getPublicKeyForHost();
            Assert.assertTrue("Public Key format error", publicKeyForHost.startsWith("ssh-rsa"));
            Assert.assertTrue("Public Key format error - comment", publicKeyForHost.endsWith(comment));
            
            System.out.println("Public Key for Host authorized_keys ["+publicKeyForHost+"]");
            
        } catch (PemHandlingException ex) {
            Assert.assertTrue("Exception on get Host string ["+ex.getLocalizedMessage()+"]", false);
        }
        
    }
    
    @Test
    public void generateEncryptedKeyTest() {
         
        String comment = "Test Encrypted key";
        String password = "myPassw0rd";
        String filename = here + "/temp_encrypted.pem";
        
        PemHandler ph = new PemHandler();
         
        try {
            ph.generateKeys(comment);
            
        } catch (PemHandlingException ex) {
            Assert.assertTrue("Exception on Generate ["+ex.getLocalizedMessage()+"]", false);
        }
     
        try {
            ph.storePrivateKeyEncrypted(filename, password.toCharArray());    // note: default forces stored file to end with .pem
        } catch (PemHandlingException ex) {
            Assert.assertTrue("Exception on Store Encrypted ["+ex.getLocalizedMessage()+"]", false);
        }
        
        File pkey = new File(filename);
        try {
            RSAPublicKey pubKey = ph.getPublicFromPrivateKey(pkey, null);

            Assert.assertTrue("Should throw an Exception when no passphase supplied", false);

        } catch (PemHandlingException ex) {
            // correct response
        }
        
        try {
            RSAPublicKey pubKey = ph.getPublicFromPrivateKey(pkey, password.toCharArray());
                    
        } catch (PemHandlingException ex) {
            Assert.assertTrue("Exception on get Public From Private["+ex.getLocalizedMessage()+"]", false);
        }
        
        try {
            boolean privateKeyEncrypted = ph.isPrivateKeyEncrypted(pkey);            
            Assert.assertTrue("Encryption check on encrypted key fails", privateKeyEncrypted);
            
        } catch (IOException ex) {
            Assert.assertTrue("Exception on check of encryption ["+ex.getLocalizedMessage()+"]", false);
        }
        
        try {
            String publicKeyForHost = ph.getPublicKeyForHost();
            Assert.assertTrue("Public Key format error", publicKeyForHost.startsWith("ssh-rsa"));
            Assert.assertTrue("Public Key format error - comment", publicKeyForHost.endsWith(comment));
            
            System.out.println("Public Key for Host authorized_keys ["+publicKeyForHost+"]");
            
        } catch (PemHandlingException ex) {
            Assert.assertTrue("Exception on get Host string ["+ex.getLocalizedMessage()+"]", false);
        }
        
    }    
}
