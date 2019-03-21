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

import java.io.BufferedWriter;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.OutputStream;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import javax.crypto.Cipher;
import net.schmizz.sshj.userauth.keyprovider.PuTTYKeyFile;
import net.schmizz.sshj.userauth.password.PasswordFinder;
import net.schmizz.sshj.userauth.password.Resource;
 
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMEncryptor;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaMiscPEMGenerator;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPKCS8Generator;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8EncryptorBuilder;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.bouncycastle.openssl.jcajce.JcePEMEncryptorBuilder;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.io.pem.PemGenerationException;
import org.bouncycastle.util.io.pem.PemObjectGenerator;
import org.bouncycastle.util.io.pem.PemWriter;

/**
 *
 * @author David
 */
public class PemHandler {
    
    public static final int KEY_SIZE = 2048;
    
    public static final int FORMAT_PKCS8 = 0;
    public static final int FORMAT_RSA_LEGACY = 1;
    
    private static final int privkeyEncryptedFormat = FORMAT_RSA_LEGACY;
            
    protected RSAPrivateKey priv;
    protected RSAPublicKey pub;    
    protected String comment;

    public PemHandler() {
        Security.addProvider(new BouncyCastleProvider());
    }
    
    public void clear() {
        this.priv = null;
        this.pub = null;            
        this.comment = "";            
    }
    
    public void generateKeys(String comment) throws PemHandlingException  {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "BC");
            generator.initialize(KEY_SIZE);

            KeyPair keyPair = generator.generateKeyPair();
            
            this.priv = (RSAPrivateKey)keyPair.getPrivate();
            this.pub = (RSAPublicKey)keyPair.getPublic();
            
            this.comment = comment;
            
        } catch (NoSuchAlgorithmException | NoSuchProviderException ex) {
            throw new PemHandlingException("Error generating Keys", ex);
        }
        
    }
    public void storePrivateKey(String fileName) throws PemHandlingException {
        storePrivateKey(fileName, true);
    }    
    
    public void storePrivateKey(String fileName, boolean enforceExtension) throws PemHandlingException {
        
        if (priv == null) {
            throw new PemHandlingException("Key must be generated first");
        }
        
        try {
            PemObjectGenerator gen = new JcaMiscPEMGenerator(priv);                 
            storePrivateKeyFromGenerator(fileName, gen, enforceExtension);            
            
        } catch (IOException ex) {
             throw new PemHandlingException("Error storing Private Key", ex);
        }        
    }

    public void storePrivateKeyEncrypted(String fileName, char[] password) throws PemHandlingException {        
        storePrivateKeyEncrypted(fileName, password, true);                
    }

    public void storePrivateKeyEncrypted(String fileName, char[] password, boolean enforceExtension) throws PemHandlingException {        
        storePrivateKeyEncrypted(fileName, password, privkeyEncryptedFormat, enforceExtension);        
    }

    public void storePrivateKeyEncrypted(String fileName, char[] password, int keyFormat) throws PemHandlingException {        
        storePrivateKeyEncrypted(fileName, password, keyFormat, true);        
    }
    
    public void storePrivateKeyEncrypted(String fileName, char[] password, int keyFormat, boolean enforceExtension) throws PemHandlingException {        

        if (priv == null) {
            throw new PemHandlingException("Key must be generated first");
        }

        PemObjectGenerator gen;

        try {
            if (keyFormat == FORMAT_PKCS8) {                    
                String algorithm = JceOpenSSLPKCS8EncryptorBuilder.AES_256_CBC;
                if (!isRunningInHighStrengthJVM()) {
                    algorithm = JceOpenSSLPKCS8EncryptorBuilder.DES3_CBC;
                }                
                JceOpenSSLPKCS8EncryptorBuilder encryptorBuilder = 
                                new JceOpenSSLPKCS8EncryptorBuilder(
                                                new ASN1ObjectIdentifier(algorithm));
                encryptorBuilder.setProvider(BouncyCastleProvider.PROVIDER_NAME);
                encryptorBuilder.setPasssword(password);
                OutputEncryptor oe = encryptorBuilder.build();
                gen = new JcaPKCS8Generator(priv, oe);
            } 
            else {
                JcePEMEncryptorBuilder builder = null;
                builder = new JcePEMEncryptorBuilder("AES-256-CBC");
                if (!isRunningInHighStrengthJVM()) {                
                    builder = new JcePEMEncryptorBuilder("DES-EDE3-CBC");
                }
                builder.setProvider(BouncyCastleProvider.PROVIDER_NAME);
                builder.setSecureRandom(new SecureRandom());
                PEMEncryptor encryptor = builder.build(password);
                gen = new JcaMiscPEMGenerator(priv, encryptor);
            }            
            
            storePrivateKeyFromGenerator(fileName, gen, enforceExtension);
        } 
        catch (OperatorCreationException ex) {
            throw new PemHandlingException("Unable to store encrypted key", ex);
        } 
        catch (PemGenerationException ex) {
            throw new PemHandlingException("Unable to store encrypted key", ex);
        } 
        catch (IOException ex) {
            throw new PemHandlingException("Unable to store encrypted key", ex);
        }

    }
    
    private void storePrivateKeyFromGenerator(String fileName, PemObjectGenerator gen, boolean enforceExtension) throws IOException {
        
        String privFile = fileName;
        
        if (enforceExtension) {
            if (!fileName.endsWith(".pem")) {
                privFile += ".pem";
            }
        }
        File prFile = new File(privFile);
        
        StringWriter stringWriter = new StringWriter();
        PemWriter pemWriter = new PemWriter(stringWriter);
        pemWriter.writeObject(gen);
        pemWriter.close();
        String s = stringWriter.toString();
        
        FileWriter fw = new FileWriter(prFile);
        BufferedWriter bw = new BufferedWriter(fw);
        bw.write(s);
        bw.flush();
        bw.close();
    }
        
    public boolean isPrivateKeyEncrypted(File file) throws FileNotFoundException, IOException {
         
        boolean encrypted = false;
                   
        PEMParser pemParser = new PEMParser(new FileReader(file));
        Object object = pemParser.readObject();
        
        if (object instanceof PEMEncryptedKeyPair || object instanceof PKCS8EncryptedPrivateKeyInfo) {
            encrypted = true;
        }
        else
        if (object instanceof PEMKeyPair) {
            encrypted = false;
        }
        else {            
            // if not PEM and encrypted check for Putty encrypted file
            MyPuttyHandler puttyKeyFileHandler = new MyPuttyHandler();
            puttyKeyFileHandler.init(file);
            try {
                puttyKeyFileHandler.parseKeyPair();
            }
            catch (IOException ex) {
                // ignore for now - may be due to encryption, but required to read headers (work-around)
            }
            if (puttyKeyFileHandler.isEncrypted()) {
                encrypted = true;
            }
        }
        
        return encrypted;
    }
     
    public void loadPrivateKeyFileEncrypted(File file, char[] password) throws FileNotFoundException, IOException, PemHandlingException {
        
        PEMParser pemParser = null;
        BouncyCastleProvider BCProvider = new BouncyCastleProvider();
        
        try {
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider(BCProvider.PROVIDER_NAME);
            KeyPair keyPair;
            
            pemParser = new PEMParser(new FileReader(file));
            Object object = pemParser.readObject();            
            
            if (object instanceof PEMEncryptedKeyPair) {

                // Encrypted OpenSSL format key - we will use provided password
                PEMEncryptedKeyPair ckp = (PEMEncryptedKeyPair) object;
                PEMDecryptorProvider decProv = new JcePEMDecryptorProviderBuilder().build(password);
                PEMKeyPair decryptKeyPair = ckp.decryptKeyPair(decProv);
                
                // Convert Key Pair to RSA to extract Private and Public keys
                keyPair = converter.getKeyPair(decryptKeyPair);
                this.priv = (RSAPrivateKey)keyPair.getPrivate();
                this.pub = (RSAPublicKey)keyPair.getPublic();
            }
            else
            if (object instanceof PKCS8EncryptedPrivateKeyInfo) {

                // Encrypted PKCS#8 Key Pair
                PKCS8EncryptedPrivateKeyInfo pair = (PKCS8EncryptedPrivateKeyInfo)object;
                JceOpenSSLPKCS8DecryptorProviderBuilder jce = new JceOpenSSLPKCS8DecryptorProviderBuilder();
                jce.setProvider(BCProvider.PROVIDER_NAME);
                
                // Decrypt using password
                InputDecryptorProvider decProv = jce.build(password);
                PrivateKeyInfo info = pair.decryptPrivateKeyInfo(decProv);

                // Convert to RSA Private Key
                this.priv = (RSAPrivateKey)converter.getPrivateKey(info);
                
                // and generateKeys Public Key from this
                RSAPrivateCrtKey rsaCrtKey = (RSAPrivateCrtKey) this.priv;             
                RSAPublicKey publicKey = (RSAPublicKey)KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(this.priv.getModulus(), rsaCrtKey.getPublicExponent()));
                this.pub = (RSAPublicKey)publicKey;                            
            }
            else {
                throw new PemHandlingException("Unable to load Private Key ["+(object != null ? object.getClass().getName() : "is null")+"]");
            }
        } catch (OperatorCreationException | PKCSException | NoSuchAlgorithmException | InvalidKeySpecException ex) {
            throw new PemHandlingException("Cannot decrypt private key", ex);
        } finally {
            try {
                pemParser.close();
            } catch (IOException ex) {
                throw new PemHandlingException("Error closing parser", ex);
            }
        }
    }

    public void loadPrivateKeyFile(File file) throws FileNotFoundException, IOException, PemHandlingException {
        
        PEMParser pemParser = null;
        BouncyCastleProvider BCProvider = new BouncyCastleProvider();
        
        try {
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider(BCProvider.PROVIDER_NAME);
            KeyPair keyPair;
            
            pemParser = new PEMParser(new FileReader(file));
            Object object = pemParser.readObject();            
            
            if (object instanceof PEMKeyPair) {
                
                // Convert PEM Key Pair to RSA Pair to extract Private and Public keys
                keyPair = converter.getKeyPair((PEMKeyPair)object);
                this.priv = (RSAPrivateKey)keyPair.getPrivate();
                this.pub = (RSAPublicKey)keyPair.getPublic();   
            }
            else {
                throw new PemHandlingException("Unable to load Private Key ["+(object != null ? object.getClass().getName() :"is null")+"]");
            }
            
        } finally {
            try {
                pemParser.close();
            } catch (IOException ex) {
                throw new PemHandlingException("Error closing parser", ex);
            }
        }
    }
       
    private byte[] encodePublicKey() throws PemHandlingException {
        
        if (pub == null) {
            throw new PemHandlingException("Public Key must be generated or loaded first");
        }

        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            // encode the "ssh-rsa" string
            byte[] sshrsa = new byte[] {0, 0, 0, 7, 's', 's', 'h', '-', 'r', 's', 'a'};
            out.write(sshrsa);
            // Encode the public exponent
            BigInteger e = pub.getPublicExponent();
            byte[] data = e.toByteArray();
            encodeUInt32(data.length, out);
            out.write(data);
            // Encode the modulus
            BigInteger m = pub.getModulus();
            data = m.toByteArray();
            encodeUInt32(data.length, out);
            out.write(data);
            return out.toByteArray();
        } catch (IOException ex) {
            throw new PemHandlingException("Error encoding Public Key", ex);
        }
    }

     private static void encodeUInt32(int value, OutputStream out) throws PemHandlingException {
        try {
            byte[] tmp = new byte[4];
            tmp[0] = (byte) ((value >>> 24) & 0xff);
            tmp[1] = (byte) ((value >>> 16) & 0xff);
            tmp[2] = (byte) ((value >>> 8) & 0xff);
            tmp[3] = (byte) (value & 0xff);
            out.write(tmp);
        } catch (IOException ex) {
              throw new PemHandlingException("Error encoding Public Key", ex);
        }
    }
     
    public String getPublicKeyForHost() throws PemHandlingException {
        return getPublicKeyForHost(comment);
    }
    
    public String getPublicKeyForHost(String comment) throws PemHandlingException {
        try {
            StringBuilder b = new StringBuilder("ssh-rsa ");
            byte[] encode = Base64.encode(encodePublicKey());
            b.append(new String(encode));
            if (comment != null) {
                b.append(" ").append(comment);
            }
            return b.toString();
            
        } catch (Exception e) {
            throw new PemHandlingException("Unable to get Public key", e);
        }
    }
    
    public RSAPublicKey getPublicFromPrivateKey(File privKeyFile, char[] passphrase) throws PemHandlingException  {

        RSAPublicKey rsaPublicKey = null;
        
        try {            
            // check is encrypted 
            if (this.isPrivateKeyEncrypted(privKeyFile)) {
                
                try {            
                    this.loadPrivateKeyFileEncrypted(privKeyFile, passphrase);
                }
                catch (PemHandlingException ex) {
                    
                    // new Putty Handler required (as work-around) to ensure clean run through
                    MyPuttyHandler puttyKeyFileHandler = new MyPuttyHandler();
                
                    // Load a finder to allow Putty Handler to get passphrase
                    puttyKeyFileHandler.init(privKeyFile, new PasswordFinder() {
                        @Override
                        public char[] reqPassword(Resource<?> rsrc) {
                            return passphrase;
                        }

                        @Override
                        public boolean shouldRetry(Resource<?> rsrc) {
                            return false;
                        }
                    });  
                      
                    // getPrivate forces a key parse
                    this.priv = (RSAPrivateKey)puttyKeyFileHandler.getPrivate();
                    this.pub = (RSAPublicKey)puttyKeyFileHandler.getPublic();                    
                }                
            }
            else {
                try {            
                    this.loadPrivateKeyFile(privKeyFile);
                }
                catch (PemHandlingException ex) {
    
                    MyPuttyHandler puttyKeyFileHandler = new MyPuttyHandler();
                
                    puttyKeyFileHandler.init(privKeyFile);
  
                    this.priv = (RSAPrivateKey)puttyKeyFileHandler.getPrivate();
                    this.pub = (RSAPublicKey)puttyKeyFileHandler.getPublic();                    
                }                
                                
            }
            rsaPublicKey = this.pub;
        } 
        catch (IOException ex2) {
            
            throw new PemHandlingException("Unable to load Private Key, tried PEM and Putty formats");
        }

        return rsaPublicKey;
    }

    protected class MyPuttyHandler extends PuTTYKeyFile {

        // This class used to force a parse of Key Pair to load key values and allow correct encryption check
        @Override
        protected void parseKeyPair() throws IOException {
            super.parseKeyPair(); 
        }
        
    }
 
    public static boolean isRunningInHighStrengthJVM() {
        try {
           int maxKeyLen = Cipher.getMaxAllowedKeyLength("AES");
           if (maxKeyLen > 128) {
               return true;
           }
        } catch (Exception e){
            //
        }     
        return false;
    }
}