package com.example.tnnd.messageexchange;

import android.os.Bundle;
import android.support.annotation.NonNull;
import android.support.design.widget.BottomNavigationView;
import android.support.v7.app.AppCompatActivity;
import android.view.MenuItem;
import android.widget.TextView;
import org.ethereum.geth.Geth;
import org.ethereum.geth.KeyStore;
import org.ethereum.geth.Account;
import org.ethereum.geth.Accounts;
import org.ethereum.geth.EthereumClient;
import org.ethereum.geth.Context;
import org.ethereum.geth.Node;
import org.ethereum.geth.NodeConfig;
import org.ethereum.geth.Address;
import org.ethereum.geth.BigInt;
import org.ethereum.geth.Transaction;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.charset.StandardCharsets;
import java.io.File;
import java.net.URLEncoder;

import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.BufferedReader;
import java.io.FileInputStream;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import android.util.Base64;
import java.util.UUID;
import java.security.Signature;
import org.json.JSONObject;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;

public class MainActivity extends AppCompatActivity {

    private TextView mTextMessage;
    private final String defaultPassword = "Creation password";
    private KeyStore ks = null; //  = new KeyStore(getFilesDir() + "/keystore", Geth.LightScryptN, Geth.LightScryptP);
    private Context context = new Context();
    private NodeConfig nodeConfig = new NodeConfig();
    private final String publicAddressStr = "0xce66ae967e95f6f90defa8b58e6ab4a721c3c7fb";
    private Node node = null; // Geth.newNode(getFilesDir() + "/.eth1", nodeConfig);
    private PublicKey publicKey = null;
    private PrivateKey privateKey = null;
    private final String symmetricKeyForAllFriends = "5d8324e83dc14336914152775d1bb757";
    private final String symmetricKey = "e1edb2d92c8f48de9029e111afff4b4b";



    private BottomNavigationView.OnNavigationItemSelectedListener mOnNavigationItemSelectedListener
            = new BottomNavigationView.OnNavigationItemSelectedListener() {

        @Override
        public boolean onNavigationItemSelected(@NonNull MenuItem item) {
            String transactionStr = "transaction";
            Accounts accounts = null;
            Account account = null;

            switch (item.getItemId()) {
                case R.id.navigation_home:
                    // decrypt friend request, and approve request
                    // input:         {
                    // "from_address": "8E8b666F134EDd37D95eD182F5AC33d8a21E359E",
                    //    "name": "GxYUXbZygO1gFCwgZVI32w==\n",
                    //    "request": "Ub6yEsQEIdrNMf6OXsxw43XN5TnUK48oU61Hjg5sVi5j1daiBn1OFnjPuSHcFXLLyh9x8dw/MzUy\nEj6ykofLNl2OldvLEqlWkpXld+QJyZ5uatLP7nf9Z/HYSdz8sGPUOJAbITG5uGhBplZYZ5owEqny\nUftfu8EON83iBJX2O/AMXzw6ZFtHUv3B7JJZ23/NOivHZRq0aRQme/bSQ2SBACEmOmF4feZxZ+z3\nHAQTAkKCs1AMk67iXmq8m1pZu6s3vC5Tf0kkT/KLXyVJHpqOg2kkD4QBybC34x/UPZm3OUlhXuS8\npgBap7YbYU13WSRIpi2iKM3M8QO+W3x0gGT7Kg==\n"
                    // }
                    String requestStr = null;
                    try {
                        // following code is to demo the signing of transaction
                        accounts = ks.getAccounts();
                        account = accounts.get(0);

                        // String inputStr = "{\"from_address\": \"8E8b666F134EDd37D95eD182F5AC33d8a21E359E\", \"name\": \"GxYUXbZygO1gFCwgZVI32w==\n\",\"request\": \"Ub6yEsQEIdrNMf6OXsxw43XN5TnUK48oU61Hjg5sVi5j1daiBn1OFnjPuSHcFXLLyh9x8dw/MzUyEj6ykofLNl2OldvLEqlWkpXld+QJyZ5uatLP7nf9Z/HYSdz8sGPUOJAbITG5uGhBplZYZ5owEqnyUftfu8EON83iBJX2O/AMXzw6ZFtHUv3B7JJZ23/NOivHZRq0aRQme/bSQ2SBACEmOmF4feZxZ+z3HAQTAkKCs1AMk67iXmq8m1pZu6s3vC5Tf0kkT/KLXyVJHpqOg2kkD4QBybC34x/UPZm3OUlhXuS8pgBap7YbYU13WSRIpi2iKM3M8QO+W3x0gGT7Kg==\"}";
                        String inputStr = "{\"from_address\": \"0x8E8b666F134EDd37D95eD182F5AC33d8a21E359E\", \"name\": \"GxYUXbZygO1gFCwgZVI32w==\n\",\"request\": \"Ub6yEsQEIdrNMf6OXsxw43XN5TnUK48oU61Hjg5sVi5j1daiBn1OFnjPuSHcFXLLyh9x8dw/MzUy\\nEj6ykofLNl2OldvLEqlWkpXld+QJyZ5uatLP7nf9Z/HYSdz8sGPUOJAbITG5uGhBplZYZ5owEqny\\nUftfu8EON83iBJX2O/AMXzw6ZFtHUv3B7JJZ23/NOivHZRq0aRQme/bSQ2SBACEmOmF4feZxZ+z3\\nHAQTAkKCs1AMk67iXmq8m1pZu6s3vC5Tf0kkT/KLXyVJHpqOg2kkD4QBybC34x/UPZm3OUlhXuS8\\npgBap7YbYU13WSRIpi2iKM3M8QO+W3x0gGT7Kg==\\n\"}";

                        JSONObject requestNode = new JSONObject(inputStr);
                        String data = requestNode.get("request").toString();
                        String from_address = requestNode.get("from_address").toString();
                        // int dLen = data.length();

                        requestStr = decryptData(privateKey, data);
                        JSONObject keyNode = new JSONObject(requestStr);
                        String requester_all_friends_key = keyNode.get("all_friends_symmetric_key").toString();
                        String received_key = keyNode.get("friend_request_symmetric_key").toString();
                        requestStr = " name: " + decryptDataWithSymmetricKey(requester_all_friends_key, requestNode.get("name").toString());
                        String friend_request_key = keyNode.get("friend_request_symmetric_key").toString();
                        requestStr += "\nfriend_key: " + friend_request_key;

                        // create approve request
                        transactionStr = approveFriendRequest(account, from_address, received_key, symmetricKeyForAllFriends);
                        System.out.println("approval request: " + transactionStr);

                        // validating xko52z9PyQbaP/Jopbrmr0W5ere/pbxWvBkzQ0y2rX3O2mDewMPdw7PHO9sXmt9qSCMEIEA88aIN\nq+sbfUfVT3D0cEPqB4Uo3LO9wzWkoaU=
                        // String validateStr = "xko52z9PyQbaP/Jopbrmr0W5ere/pbxWvBkzQ0y2rX3O2mDewMPdw7PHO9sXmt9qSCMEIEA88aIN\nq+sbfUfVT3D0cEPqB4Uo3LO9wzWkoaU=";
                        // validateStr = decryptDataWithSymmetricKey(received_key, validateStr);
                        // System.out.println("validated str: " + validateStr);
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                    mTextMessage.setText(requestStr);
                    return true;
                case R.id.navigation_dashboard:
                    try {
                        // following code is to demo the signing of transaction
                        accounts = ks.getAccounts();
                        if (accounts.size() <= 1) {
                            createUser();
                            accounts = ks.getAccounts();
                        }
                        account = accounts.get(1);
                        Account account_0 = accounts.get(0);

                        // System.out.println("from_address: " + account.getAddress().getHex());


                        // replace data by public key
                        // String data = "very long data very long data very long data very long data very long data very long data very long data very long data very long data very long data ";
                        // this.publicKey = getPublicKey();
                        getPublicPrivateKeys();

                        UUID idOne = UUID.randomUUID();
                        // symmetricKey = idOne.toString().replace("-", "");
                        // symmetricKey = "e1edb2d92c8f48de9029e111afff4b4b";
                        System.out.println("symmetric key: " + symmetricKey);

                        // UUID id2 = UUID.randomUUID();
                        // symmetricKeyForAllFriends = id2.toString().replace("-", "");
                        System.out.println("symmetric key for all friends: " + symmetricKeyForAllFriends);

                        // friend request is in JSON format:
                        // {
                        //      "friend_request_symmetric_key" : "<symmetricKey>",
                        //      "all_friends_symmetric_key" : "<symmetricKeyForAllFriends>"
                        // }
                        JSONObject requestNode = new JSONObject();
                        requestNode.put("friend_request_symmetric_key", symmetricKey);
                        requestNode.put("all_friends_symmetric_key", symmetricKeyForAllFriends);
                        // System.out.println("length to encrypt: " + requestNode.toString().length());

                        String data = encryptData(publicKey, requestNode.toString());
                        // System.out.println("length of data: " + data.length() + " data: " + data);

                        // String decryptedData = decryptData(privateKey, data);
                        // System.out.println("decrypted data: " + decryptedData);
                        transactionStr = getFriendRequest(account, account_0, data);
                        System.out.println("friend request transaction: " + "length: " + transactionStr.length() + " string: " + transactionStr);

                        if (accounts.size() <= 2) {
                            createUser();
                            accounts = ks.getAccounts();
                        }
                        account = accounts.get(2);
                        transactionStr = getFriendRequest(account, account_0, data);
                        System.out.println("friend request transaction: " + "length: " + transactionStr.length() + " string: " + transactionStr);

                    } catch (Exception e) {
                        transactionStr = e.getMessage();
                        e.printStackTrace();

                    }
                    mTextMessage.setText(transactionStr);
                    return true;
                case R.id.navigation_notifications:
                    try {
                        // following code is to demo the signing of transaction
                        accounts = ks.getAccounts();
                        if (accounts.size() <= 0) {
                            createUser();
                            accounts = ks.getAccounts();
                        }
                        account = accounts.get(0);

                        System.out.println("from_address: " + account.getAddress().getHex());


                        // replace data by public key
                        // String data = "very long data very long data very long data very long data very long data very long data very long data very long data very long data very long data ";
                        // this.publicKey = getPublicKey();
                        getPublicPrivateKeys();
                        // byte[] data = "012345678901234567890123456789012345678901234567890123456789".getBytes();
                        long unixTime = System.currentTimeMillis() / 1000L;
                        String timeString = Long.toString(unixTime);
                        System.out.println("time: " + timeString);
                        byte[] data = timeString.getBytes();

                        Signature sig = Signature.getInstance("SHA256withRSA");
                        sig.initSign(privateKey);
                        sig.update(data);
                        byte[] signatureBytes = sig.sign();
                        transactionStr = new String(Base64.encode(signatureBytes, Base64.DEFAULT));
                        transactionStr = URLEncoder.encode(transactionStr,"UTF-8");
                        System.out.println("Signature:" + transactionStr);
                        transactionStr = "/?from_address=" + account.getAddress().getHex() + "&time_stamp="+timeString+"&b64encoded_signature="+transactionStr;

                        System.out.println("request data: " + transactionStr);



                    } catch (Exception e) {
                        transactionStr = e.getMessage();
                        e.printStackTrace();

                    }
                    mTextMessage.setText(transactionStr);

                    // mTextMessage.setText(R.string.title_notifications);
                    return true;
            }
            return false;
        }
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        this.ks = new KeyStore(getFilesDir() + "/keystore", Geth.LightScryptN, Geth.LightScryptP);
        Accounts accounts = null;
        Account account = null;
        String transactionStr = "transaction";
        // Context context = new Context();
        // NodeConfig nodeConfig = new NodeConfig();
        this.nodeConfig.setEthereumNetworkID(1);
        BigInt chain = new BigInt(nodeConfig.getEthereumNetworkID());

        try {
            // Node node = Geth.newNode(getFilesDir() + "/keystore", nodeConfig);
            this.node = Geth.newNode(getFilesDir() + "/.eth1", nodeConfig);
            this.node.start();
        } catch (Exception e) {
            transactionStr = e.getMessage();
            e.printStackTrace();

        }

        try {
            // following code is to demo the signing of transaction
            accounts = ks.getAccounts();
            if (accounts.size() <= 0) {
                createUser();
                accounts = ks.getAccounts();
            }
            account = accounts.get(0);
            transactionStr = getRegisterRequest(account);
            if (accounts.size() <= 1) {
                createUser();
                accounts = ks.getAccounts();
            }
            account = accounts.get(1);
            getRegisterRequest(account);
            // transactionStr += "\n" + getRegisterRequest(account);
            if (accounts.size() <= 2) {
                createUser();
                accounts = ks.getAccounts();
            }
            account = accounts.get(2);
            getRegisterRequest(account);
            // transactionStr += "\n" + getRegisterRequest(account);
        } catch (Exception e) {
            transactionStr = e.getMessage();
            e.printStackTrace();

        }

        // System.out.println("debug 100");
        mTextMessage = (TextView) findViewById(R.id.message);
        mTextMessage.setText(transactionStr);

        // mTextMessage = (TextView) findViewById(R.id.message);
        BottomNavigationView navigation = (BottomNavigationView) findViewById(R.id.navigation);
        navigation.setOnNavigationItemSelectedListener(mOnNavigationItemSelectedListener);
    }

    private void createUser() {
        try {
            Account newAccount = null;
            newAccount = this.ks.newAccount(this.defaultPassword);
            String addressStr = newAccount.getAddress().getHex();
            System.out.println("debug acct hex: " + addressStr);
        } catch (Exception e) {
            e.printStackTrace();

        }
    }

    private String signTransaction(Account account, byte[] dataBytes) {
        long nonce;
        double amount = 0;
        long gasLimit = 0;
        double gasPrice = 0;
        BigInt chain = new BigInt(this.nodeConfig.getEthereumNetworkID());
        String returnStr = null;

        try {
            this.ks.unlock(account, this.defaultPassword);

            // nonce = this.node.getEthereumClient().getPendingNonceAt(context, account.getAddress());
            nonce = 0;
            Transaction tx = new Transaction(
                    (long) nonce,
                    new Address(this.publicAddressStr),
                    new BigInt((long) amount),
                    gasLimit, // new BigInt((long) gasLimit),
                    new BigInt((long) gasPrice),
                    dataBytes);

            // Transaction signed = ks.signTxPassphrase(account, "Creation password", tx, chain);
            Transaction signed = ks.signTx(account, tx, chain);
            // node.getEthereumClient().
            // signed.getFrom(chain);
            // System.out.println("signed.getFrom: " + signed.getFrom(chain).getHex());
            returnStr = signed.encodeJSON();
            Transaction newTrans = Geth.newTransactionFromJSON(returnStr);
            newTrans.getFrom(chain);
            // System.out.println("newTrans.getFrom: " + newTrans.getFrom(chain).getHex());
            // System.out.println("signed encodeJSON: " + returnStr);

        } catch (Exception e) {
            e.printStackTrace();
            return null;

        }

        return returnStr;

        // replace data by public key
        // String data = "very long data very long data very long data very long data very long data very long data very long data very long data very long data very long data ";
        // System.out.println("debug 2");

        /*
        accountsStr = signed.encodeJSON();
        Transaction newTrans = Geth.newTransactionFromJSON(accountsStr);
        newTrans.getFrom(chain);
        System.out.println("newTrans.getFrom: " + newTrans.getFrom(chain).getHex());
        System.out.println("signed encodeJSON: " + accountsStr);
        */
    }

    private String createPublicKey() {
        String algorithm = "RSA";
        String signatureAlg = "SHA256withRSA";
        int keySize = 2048;
        int certExpireInDays = 365;
        String commonName = "CN=KeyManagerTest";
        KeyManager keyManager = new KeyManagerImpl(
                algorithm,
                signatureAlg,
                keySize,
                certExpireInDays,
                commonName);

        String privKeyFileName = getFilesDir() + "/keystore/" + "privatekey.pem";
        String publicKeyFileName = getFilesDir() + "/keystore/" +"publickey.pem";

        try {
            File f = new File(publicKeyFileName);
            if (f.exists())
            {
                return getStringFromFile(publicKeyFileName);
            }
        } catch (Exception e)
        {
            // continue to create the public key
        }
        // String certificateFileName = "/tmp/certificate.pem";
        // keyManager.generateKeyCertificate(privKeyFileName, publicKeyFileName, certificateFileName);
        keyManager.generateKeyCertificate(privKeyFileName, publicKeyFileName, null);
        /*
        PrivateKey privateKey = null;
        PublicKey publicKey = null;
        try {
            privateKey = keyManager.loadPrivateKeyFromRSAPEM(privKeyFileName);
            publicKey = keyManager.loadPublicKeyFromRSAPEM(publicKeyFileName);
            // publicKey = keyManager.loadPublicKeyFromRSA_X509_CertificatePEM(certificateFileName);
        } catch (NoSuchProviderException e1) {
            // TODO Auto-generated catch block
            e1.printStackTrace();
            return null;
        } catch (NoSuchAlgorithmException e1) {
            // TODO Auto-generated catch block
            e1.printStackTrace();
            return null;
        } catch (IOException e1) {
            // TODO Auto-generated catch block
            e1.printStackTrace();
            return null;
        } catch (Exception e1) {
            // TODO Auto-generated catch block
            e1.printStackTrace();
            return null;
        }
        */
        try {
            return getStringFromFile(publicKeyFileName);
        } catch (Exception e) {
            e.printStackTrace();
            return null;

        }
    }

    private String convertStreamToString(InputStream is) throws Exception {
        BufferedReader reader = new BufferedReader(new InputStreamReader(is));
        StringBuilder sb = new StringBuilder();
        String line = null;
        while ((line = reader.readLine()) != null) {
            sb.append(line).append("\n");
        }
        reader.close();
        return sb.toString();
    }

    private String getStringFromFile (String filePath) throws Exception {
        File fl = new File(filePath);
        FileInputStream fin = new FileInputStream(fl);
        String ret = convertStreamToString(fin);
        //Make sure you close all streams.
        fin.close();
        return ret;
    }

    private void getPublicPrivateKeys() {
        KeyManager keyManager = new KeyManagerImpl();
        String privKeyFileName = getFilesDir() + "/keystore/" + "privatekey.pem";
        String publicKeyFileName = getFilesDir() + "/keystore/" +"publickey.pem";

        try {
            this.privateKey = keyManager.loadPrivateKeyFromRSAPEM(privKeyFileName);
            this.publicKey = keyManager.loadPublicKeyFromRSAPEM(publicKeyFileName);
            // publicKey = keyManager.loadPublicKeyFromRSA_X509_CertificatePEM(certificateFileName);
        } catch (NoSuchProviderException e1) {
            // TODO Auto-generated catch block
            e1.printStackTrace();
            return;
        } catch (NoSuchAlgorithmException e1) {
            // TODO Auto-generated catch block
            e1.printStackTrace();
            return;
        } catch (IOException e1) {
            // TODO Auto-generated catch block
            e1.printStackTrace();
            return;
        } catch (Exception e1) {
            // TODO Auto-generated catch block
            e1.printStackTrace();
            return;
        }
    }

    private String encryptData(PublicKey publicKey, String data) {
        String encryptedBase64Str = null;

        KeyManager keyManager = new KeyManagerImpl();
        try {
            encryptedBase64Str = keyManager.encryptTextBase64(data.getBytes(), publicKey);
            // System.out.println("Encrypted text: " + encryptedBase64Str);
            // String decryptedStr = keyManager.decryptTextBase64(encryptedBase64Str.getBytes(), privateKey);
            // System.out.println("Decrypted text: " + decryptedStr);

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
        }
        return encryptedBase64Str;
    }
    private String decryptData(PrivateKey privateKey, String data) {
        String decryptedStr = null;

        KeyManager keyManager = new KeyManagerImpl();
        try {
            decryptedStr = keyManager.decryptTextBase64(data.getBytes(), privateKey);
            System.out.println("Decrypted text: " + decryptedStr);

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
        }
        return decryptedStr;
    }

    private String encryptDataWithSymmetricKey(String inKey, String data) {
        SecretKeySpec key = new SecretKeySpec(inKey.getBytes(), "AES");

        Cipher cipher = null;
        try {
            // int maxKeyLen = Cipher.getMaxAllowedKeyLength("AES");
            // System.out.println("max allowed length: " + maxKeyLen);


            cipher = Cipher.getInstance("AES/ECB/PKCS7Padding", "BC");
            cipher.init(Cipher.ENCRYPT_MODE, key);
        } catch (NoSuchAlgorithmException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        byte[] cipherText = new byte[cipher.getOutputSize(data.length())];
        int ctLength = 0;

        try {
            ctLength = cipher.update(data.getBytes(), 0, data.length(), cipherText, 0);
            ctLength += cipher.doFinal(cipherText, ctLength);
        } catch (ShortBufferException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (BadPaddingException e)
        {
            e.printStackTrace();

        } catch (IllegalBlockSizeException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        String encodedEncryptedStr = new String(Base64.encode(cipherText, Base64.DEFAULT));
        return encodedEncryptedStr;
    }

    private String decryptDataWithSymmetricKey(String inKey, String data) {
        byte[] decryptedPlainText = null;
        int ptLength = 0;
        Cipher cipher = null;
        SecretKeySpec key = new SecretKeySpec(inKey.getBytes(), "AES");
        try {
            // int maxKeyLen = Cipher.getMaxAllowedKeyLength("AES");
            // System.out.println("max allowed length: " + maxKeyLen);


            cipher = Cipher.getInstance("AES/ECB/PKCS7Padding", "BC");
            cipher.init(Cipher.DECRYPT_MODE, key);
        } catch (NoSuchAlgorithmException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        try {
            decryptedPlainText = cipher.doFinal(Base64.decode(data, Base64.DEFAULT));
        } catch (BadPaddingException e)
        {
            e.printStackTrace();

        } catch (IllegalBlockSizeException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        String decryptedString = new String(decryptedPlainText);
        return decryptedString;
    }

    private String getRegisterRequest(Account account) {
        String transactionStr = null;
        try {
            System.out.println("to_address: " + account.getAddress().getHex());

            // replace data by public key
            //String data = "very long data very long data very long data very long data very long data very long data very long data very long data very long data very long data ";
            String data = createPublicKey();
            System.out.println("public key: " + data);
            transactionStr = signTransaction(account, data.getBytes("UTF8"));
            System.out.println("register input length: " + transactionStr.length() + " string: " + transactionStr);
            JSONObject requestNode = new JSONObject();
            requestNode.put("sender_address", account.getAddress().getHex());
            String namePlainText = "NameA";

            String encryptedName = encryptDataWithSymmetricKey(symmetricKeyForAllFriends, namePlainText);
            String decryptedName = decryptDataWithSymmetricKey(symmetricKeyForAllFriends, encryptedName);
            System.out.println("decrypted name: " + decryptedName);
            requestNode.put("name", encryptedName);
            requestNode.put("transaction", transactionStr);
            transactionStr = requestNode.toString();
            System.out.println("register transaction: " + transactionStr);
        } catch (Exception e) {
            transactionStr = e.getMessage();
            e.printStackTrace();

        }
        return transactionStr;
    }

    private String getFriendRequest(Account fromAccount, Account toAccount, String data) {
        // for key of 2048bits, the encrypted data cannot exceed 256 bytes
        // https://stackoverflow.com/questions/10007147/getting-a-illegalblocksizeexception-data-must-not-be-longer-than-256-bytes-when
        String transactionStr = null;
        JSONObject friendRequestNode = new JSONObject();
        try {
            transactionStr = signTransaction(fromAccount, data.getBytes("UTF8"));
            // System.out.println("friend request input: " + "length: " + transactionStr.length() + " string: " + transactionStr);

            // action_types are from server:
            // FRIEND_REQUEST_REQUESTED = 0
            // FRIEND_REQUEST_ACCEPTED = 1
            // FRIEND_REQUEST_REJECTED = 2
            friendRequestNode.put("action_type", 0);

            friendRequestNode.put("to_address", toAccount.getAddress().getHex());
            friendRequestNode.put("from_address", fromAccount.getAddress().getHex());
            friendRequestNode.put("request", transactionStr);
        } catch (org.json.JSONException e) {
            e.printStackTrace();
        } catch (java.io.UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return friendRequestNode.toString();
    }

    private String approveFriendRequest(Account account, String from_address, String mutualKey, String myKeyForAllFriends) {
        String returnStr = null;
        try {
            JSONObject inputNode = new JSONObject();
            inputNode.put("all_friends_symmetric_key", myKeyForAllFriends);
            // use received_key to encrypt approval request
            String encApprovalStr = encryptDataWithSymmetricKey(mutualKey, inputNode.toString());
            returnStr = signTransaction(account, encApprovalStr.getBytes("UTF8"));

            JSONObject approveNode = new JSONObject();
            approveNode.put("action_type", 1);
            approveNode.put("from_address", from_address);
            approveNode.put("to_address", account.getAddress().getHex());
            approveNode.put("request", returnStr);
            returnStr = approveNode.toString();

        } catch (Exception e) {
            e.printStackTrace();
        }

        return returnStr;

    }
}
