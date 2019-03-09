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
import org.json.JSONArray;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;
import java.util.*;

import java.io.FileOutputStream;

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
                        transactionStr = signStringByPrivateKey(privateKey, timeString);
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
            // createPublicKey(); // to create a new set of keys
            populateKeysIntoTextFiles(); // to pouplate from existing strings
            getPublicPrivateKeys();
            String encryptedStr = encryptData(publicKey, "abc");
            String decryptedStr = decryptData(privateKey, encryptedStr);


            KeyManager keyManager = new KeyManagerImpl();
            String publicKeyPEM = keyManager.getKeyPEM(getPublicKeyFileName());
            System.out.println(publicKeyPEM);

            String pubKeyStr = "" +
                    "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAs0Tx0PSR5bUQt0FN0q2c\n" +
                    "lxQ+yrdyOnjCWyW/NZLFCbFYXY7qvdEm1vIO2dMAi7NBN0nEVbKUYR43rY/2PZiJ\n" +
                    "8Q/o6B5vpR2w47BOUAM8tgksqrf+mNCrYpW6dSPuS1dOAWP9lhR3Ow6Gt9yikZ/f\n" +
                    "YgRiVPMwHGiDdkVUOwLfz2oo0wehqtQTTx0FdgP7PB6wB2ev21k5unfQRH4GXXMh\n" +
                    "Fy5q5xKr0gS0J3xTUOSHzoxdsDdOjK9cJk1bP0mxqMY5bWvBlyVVR5AU13qPKe5D\n" +
                    "X3iYDeqdkvLs/v8eZ+FIzLw9aRr9xMeeepk1xCU5ldJHcqMplQ625AtZc00/OyGX\n" +
                    "6BJKIh9LBp8Usl5+DSLc6OFxlC5hhHVST6NbNDRziXK4CdoQBg9jl6sKUCu5kHmX\n" +
                    "D3aXjuo/EE8VBXf+3aIAV/8TiJIMd1i1Vp1Pwi9J8dIc1MkzYs5ecvSq683nGdY6\n" +
                    "F9pYj3OWKucz36eNc1Tl26I8C5huSkJfaXYfhqR3tE9MWvCqMsvilPX43ZPclziw\n" +
                    "31dF+1JuL+aBP/7wQYMiqpWNrw1wOR6P7Nlrm44eLHZeybqx3RxIAK0i1vQU01LW\n" +
                    "YdVn/+bvYz6zrh52vb07kTYmMxKIbbD6y6RV8NR4maaJBjyoGO4OMWP9wOGx6fKV\n" +
                    "0guuUukfZ+CTkZMkusGiBdUCAwEAAQ==";
                    // "-----END PUBLIC KEY-----";
            pubKeyStr = publicKeyPEM;
            /*
            pubKeyStr =
                    "MIMAAiMwDQYJKoZIhvcNAQEBBQADgwACDwAwggIKAoICAQDFg9hGyIQZavKHN27k\n" +
                    "DTa4EcA9zyj13dJyrvqDhDLUNXIOK0z4nura5ojoyfdVo7hj92r5d031InhhdCCA\n" +
                    "VZB6ie4WYU/zXL2vadnYg/U9gBM8e6UAlHz6NKH+CcNqD52glY8vko7FsxoswtZ+\n" +
                    "1RyfurO6L615akStoZq1kPM0dwSrz+WPkRMKmwxcHAhr0iqEyTdjr86xzjdqJKBS\n" +
                    "4OQfYIk4vagp8kZ+BTULfYC7nykKqlo1cfBauKyAGYJZp0Sd7vEE1sp5aq65vvCC\n" +
                    "sVJLpRdNJ85zAxfOF44OrW/4hUafKD3PqTJDWVxpQOMTNnmdd/DIMRhebBjznoLW\n" +
                    "2lnk+tzRI6/U6BY5Es5gKlQ/TjD2iTdUEx+F1lnmZFt/n4ibV2gXrL3gIOHnH447\n" +
                    "XTlyD/DwKb2bqPNjqJVssVeeNYZEgA9gaEEXHD0Op+VeQ8fpdefonZ40oYdzZnbq\n" +
                    "0X+KDKOBWpceQU3oqY0naI2cWm6f5B5AIOFuJLG26e8ysefIYfft7/9bklbKZzyU\n" +
                    "RsOLUBIbOXqx+XIyF+uX+ueSkyutqi+ea1+uLo9bYIyNpPRGLFgXR0U+gouwLyM4\n" +
                    "Mhe9S2M1MRyJWS/RPsaGC5cu5uPS0E6Pdlx7xsY6+NvOSnCJIbKerIX3vvRYxwf7\n" +
                    "GdAqspw5MuNcuCZbXBknX/vWuQIDAQAB";
                    */
            /*
            pubKeyStr = "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAv/1SCD9C8GuD4c4ANTpy\n" +
                    "FXPM5G4J4CjRf82MFMB0LpHSob4qmWupvLhCJTGvvjZHZ0NMHAiyyApKb7LsokW8\n" +
                    "B1wmIw5HZZTL8TC9B7KefXc0wVvH3Uk+bdUGyCdymijmK06nAQ5CZCDLD+m6wL14\n" +
                    "hqkzYPHc7A5TvAErwAcAvkL6bwa/tXDdmy5P3QivK+ZfkDZ8+E2jsn5FSoHrE8ZB\n" +
                    "KPfPCmgE8+SHHvoeEazpokkrd3S5AJb1lBq1pCQCgiVYOstE+IxEGE83OqL3ikCQ\n" +
                    "ysasp78sk0klJ7mTB0o5YdGVV9hG9NKK2/g57v7Q33FruUBLcJnSHYDClXBzdEZ1\n" +
                    "x9WhNuCCgq1LdpRdm+WLv+r04mO8u3LwiISMObHL6+cMmvUadHlPyJ/gs9pwBBQR\n" +
                    "VMw/4tMmtmHxrMtCqp3vR6+10RVPg0pZgCJ2ywcINFIZprY9nP8mMyZySn+ou4FK\n" +
                    "jHMb9iPTdjKHbI84kpc8OBuAtmLTEsVq3P2QcmZgtA1xb8GeblTHEw4C91No5sI2\n" +
                    "ZPbwWWA6I5IH+k0GXFt/gJ82WqjMzLk6RihbnUl0Ihue0PwISQqfGl4h6PRNCUS6\n" +
                    "4/7UG1wU72rkIBNd7aSmneg5WM+D2vpb7+J0nZU2rkn6hgtzFIx1Pjrtq6Og7ukz\n" +
                    "yiVhZ2+k+8ejItw2vDE3xIcCAwEAAQ==";
            */
            PublicKey lTestPubKey = keyManager.loadPublicKeyFromRSAPEMString(pubKeyStr);
            encryptedStr = encryptData(lTestPubKey, "abc");
            System.out.println(encryptedStr);

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

            // get group_invite request
            {
                Account fromAccount = accounts.get(0);
                Account toAccount = accounts.get(1);
                // List< HashMap<String, String> > inviteeList = new ArrayList<HashMap<String, String>>();
                HashMap<String, String> inviteeMap = new HashMap<String, String>();
                inviteeMap.put(toAccount.getAddress().getHex(), "key1");
                // inviteeList.add(inviteeNode);


                String groupAddress = "android-group-12345";
                String requestStr = getGroupInviteRequest(fromAccount, groupAddress, inviteeMap);

            }

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

    private String getPublicKeyFileName() {
        return getFilesDir() + "/keystore/" +"publickey.pem";
    }

    private String getPrivateKeyFileName() {
        return getFilesDir() + "/keystore/" +"privatekey.pem";
    }

    private String signStringByPrivateKey(PrivateKey inPrivateKey, String inString) {
        try {
            byte[] data = inString.getBytes();
            Signature sig = Signature.getInstance("SHA256withRSA");
            sig.initSign(inPrivateKey);
            sig.update(data);
            byte[] signatureBytes = sig.sign();
            String signatureStr = new String(Base64.encode(signatureBytes, Base64.DEFAULT));
            return signatureStr;
        }
        catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
    private void populateKeysIntoTextFiles() {
        File outputFile = new File(getPrivateKeyFileName());
        FileOutputStream privateFile = null;
        String privateKeyStr = "-----BEGIN RSA PRIVATE KEY-----\n" +
                "MIIJKgIBAAKCAgEAxYPYRsiEGWryhzdu5A02uBHAPc8o9d3Scq76g4Qy1DVyDitM\n" +
                "+J7q2uaI6Mn3VaO4Y/dq+XdN9SJ4YXQggFWQeonuFmFP81y9r2nZ2IP1PYATPHul\n" +
                "AJR8+jSh/gnDag+doJWPL5KOxbMaLMLWftUcn7qzui+teWpEraGatZDzNHcEq8/l\n" +
                "j5ETCpsMXBwIa9IqhMk3Y6/Osc43aiSgUuDkH2CJOL2oKfJGfgU1C32Au58pCqpa\n" +
                "NXHwWrisgBmCWadEne7xBNbKeWquub7wgrFSS6UXTSfOcwMXzheODq1v+IVGnyg9\n" +
                "z6kyQ1lcaUDjEzZ5nXfwyDEYXmwY856C1tpZ5Prc0SOv1OgWORLOYCpUP04w9ok3\n" +
                "VBMfhdZZ5mRbf5+Im1doF6y94CDh5x+OO105cg/w8Cm9m6jzY6iVbLFXnjWGRIAP\n" +
                "YGhBFxw9DqflXkPH6XXn6J2eNKGHc2Z26tF/igyjgVqXHkFN6KmNJ2iNnFpun+Qe\n" +
                "QCDhbiSxtunvMrHnyGH37e//W5JWymc8lEbDi1ASGzl6sflyMhfrl/rnkpMrraov\n" +
                "nmtfri6PW2CMjaT0RixYF0dFPoKLsC8jODIXvUtjNTEciVkv0T7GhguXLubj0tBO\n" +
                "j3Zce8bGOvjbzkpwiSGynqyF9770WMcH+xnQKrKcOTLjXLgmW1wZJ1/71rkCAwEA\n" +
                "AQKCAgAEVH9fj+JLf1t5SOcSs1J1hxgYksvSVg5Yysq9qt6FZfWN53ecxLkf2ul5\n" +
                "9wGH3Fq8wE4VUX8BRoPumQHkZlvQP+lbDr+WtXwIFjE7LKtp8X6adxh3Moop3xEF\n" +
                "FXg2AUkindzBfXxJS8OhYxUaOzhRLSHnDUgHjyOZzd7rJ5YZWpmc3aYp91N8Sklj\n" +
                "VI7/tCAQAKxI8G/+2GdBGbP1FS6THIXtm0TORJw0g4815Qa3NkZLUFBBdzG+f2ly\n" +
                "tnxz1DWuI7Cfe0j9j+/sLQovR01nUKN54stFHLZ/I2ePHVDE2UEi2JpATPSH4vPi\n" +
                "b9R6lZllcR1zehYPbd2/K4SxSqCpWUwFEey6/0tphoPBQKTLlo/JZ815L++jeG59\n" +
                "qPUKPTygW/mPcSj53uXLvULd6gA6CPwQXyaJFxp0/kzhh0Olg3W40cJp0wOjvZxz\n" +
                "x7LjYc/Khw+pqt3H9ezMJd+aOWP9Jhtk2Az38d44IewKcrthB/YE8m9DOWYSzEKb\n" +
                "oVU+JgpWccFjITICvX7XGgAR9UzxPqzqDNv7onMEkCPuK3h2hh31sc+Gp+fwmjI2\n" +
                "IQq6ntQonP1ODcayoKqIVIRCekhBYac21WBZOihjMEL7aXKUzN8ykxc0KNtO+ByH\n" +
                "838HOjvdt9kENQXNPzq3e8eeDtHgFp4mrEB/u16OH9uUVDKtAQKCAQEA9Ue7TQZb\n" +
                "sXL5OF08+IFqa7ydXrBaeiq/L5Igde0Mk13DWJDqV6g/h0iMrd4o99VFMPGUrtzW\n" +
                "JhfWkZ3OAsdfEOKCTlU1iMyZOJIVfJI+8V9nUXreIRWt5+mr+EmubZBw5nCCwXMs\n" +
                "7Ivvmd5n0KNnj4gGgJwWg+cXF9cCcG3i/JV59SX8HO5PvKahAJUH7+mRKriglaEM\n" +
                "8QXlxhP7FUqix+vsYQyKtkt856rGyZVKy7d1MUKTct/BDNlArEhV5pK9hqmkXbCg\n" +
                "fHG9jr9bVh+j3JujyusJtX+AzbZ0Hd+EK+bH97UH5RQeGCbCif7x+CSwQzVueXqi\n" +
                "NXC0HRCQjTdUgQKCAQEAziWztz+xbLs/J1I4Xx4G2FIN9VFM0tnjMTupsvkJ09eH\n" +
                "CgkgdtHTDCOYtTL1VO3bfoo6ylF40xMgQ9ixDZdecHU0MCvU0yrE2W7ElEmH4L49\n" +
                "1ivJT90l5GDIsRVMP+dXI4TVF5er3rqUDXgR/2EMxm/yntl8qSy63FEra5XOKmNe\n" +
                "qttRzd/V48AAoE9Ed3nisboZ+SXcuehai8B7uoOuQQdlB4cKuKuCoulVVdJkvK3W\n" +
                "WCcxDPfhzJ7KuwKefXUcpl9ouCCnmk41EdzoQqGYDj8x9EdH6gdI2g7rVTh5d+xX\n" +
                "VOPgcxMwSTh09sUWxgIXDnk57QGQtNDqeukEny8GOQKCAQEAiLINZIPiniZhVlRA\n" +
                "Io6dbKWVXqwSAHvKSQy7In2VwJtEvxskPu35Wb/JBy0Ez/n/saMxJbLVdi1a25SC\n" +
                "t3G9PX++90DtsOu1iJ2BdAddJM/ymKpNGUsnvFOyD5GgsFcLVKHnfUBfDQV/5tTY\n" +
                "LqKimI9KcGqM8b3cVODy7w2Orw3vBfzBYK4/qfeDSvvDjKUyzghPFpTGzZxnzdhc\n" +
                "2iTaS2jkN8HxnF69oa6/UqDtKlN38JgV7LNet3ZsYJd/qBynm2D3xW8mQbRx3Bgx\n" +
                "IvJHNC9ZPUF4C7qfYgYI+I0U8BKR5y7w024+x17ylE2NNKndwdcJVpJNzFKfToNo\n" +
                "zArGAQKCAQEAzduedL8ZCZCPB1A21N1iToDaSYDPa7uEAfUniH7iznZq9p2Ymq77\n" +
                "xyKA62mgzhfc2admAAWN15JA5R+t5vmiqECSRgxvMhSCkPLpQX+QPeEcVRRSqvsX\n" +
                "TNFNeHDhPOti/Cg4t5+RVRESqcSejFy46ix+pxxePX5ad4pjBsOJJpEmxw3Oyfzd\n" +
                "Vdq1hWDC6WCA/aPvLfseSVP7n5UuuVmoGG4u+G5lSXaUNOU3f0VjrXsXEd7JP78F\n" +
                "8FUd89Qwuu3JF2ctZrnNRO0WV+k20tsVwhxfYSYRbWWq3X6KiQalXhlYOIB68c9W\n" +
                "p7fGLWsxS7hol9589u1aOQZrMSQipmfKGQKCAQEAjiEsExdPV7wTZ0yfhHnv6lkR\n" +
                "6yH3qbz+8q+/q3cmKsD0gH1AN+eQPAGeb8cYlKFG8cyNeALqfwBvaqllKO7BERW9\n" +
                "nvpqtmZf0A4XPtAV1ntzRRlZsinTPA+xyu/r6Iu8zMi8sITlwZMRa0TGawWvHPok\n" +
                "EtRgqp/Oq3DkZvAsMBLLjVxu9kFWkYooZ3wH70fcvF81RrFKHlI18ME0XZW/uai4\n" +
                "RHQI63N69CXMZre294Verqx2EAFeZvwguY2U0ax9U7VvVFwaGsV7DWbYhw1Be3UF\n" +
                "Jh+2lu0Aacsuh+h5Kdzc7Kqn+VVcUy1VEhqWcCvaZB6xzxGEr/hGhDykZab94g==\n" +
                "-----END RSA PRIVATE KEY-----";
        try {
            outputFile.getParentFile().mkdirs();
            privateFile = new FileOutputStream(outputFile);
            privateFile.write(privateKeyStr.getBytes());
        }
        catch (Exception e) {
            e.printStackTrace();
        }
        finally {
            try {
                privateFile.close();
            }
            catch (Exception e) {
                e.printStackTrace();
            }
        }

        File publicKeyFile = new File(getPublicKeyFileName());
        FileOutputStream publicKeyFileStream = null;
        String publicKeyStr = "-----BEGIN PUBLIC KEY-----\n" +
                "MIMAAiMwDQYJKoZIhvcNAQEBBQADgwACDwAwggIKAoICAQDFg9hGyIQZavKHN27k\n" +
                "DTa4EcA9zyj13dJyrvqDhDLUNXIOK0z4nura5ojoyfdVo7hj92r5d031InhhdCCA\n" +
                "VZB6ie4WYU/zXL2vadnYg/U9gBM8e6UAlHz6NKH+CcNqD52glY8vko7FsxoswtZ+\n" +
                "1RyfurO6L615akStoZq1kPM0dwSrz+WPkRMKmwxcHAhr0iqEyTdjr86xzjdqJKBS\n" +
                "4OQfYIk4vagp8kZ+BTULfYC7nykKqlo1cfBauKyAGYJZp0Sd7vEE1sp5aq65vvCC\n" +
                "sVJLpRdNJ85zAxfOF44OrW/4hUafKD3PqTJDWVxpQOMTNnmdd/DIMRhebBjznoLW\n" +
                "2lnk+tzRI6/U6BY5Es5gKlQ/TjD2iTdUEx+F1lnmZFt/n4ibV2gXrL3gIOHnH447\n" +
                "XTlyD/DwKb2bqPNjqJVssVeeNYZEgA9gaEEXHD0Op+VeQ8fpdefonZ40oYdzZnbq\n" +
                "0X+KDKOBWpceQU3oqY0naI2cWm6f5B5AIOFuJLG26e8ysefIYfft7/9bklbKZzyU\n" +
                "RsOLUBIbOXqx+XIyF+uX+ueSkyutqi+ea1+uLo9bYIyNpPRGLFgXR0U+gouwLyM4\n" +
                "Mhe9S2M1MRyJWS/RPsaGC5cu5uPS0E6Pdlx7xsY6+NvOSnCJIbKerIX3vvRYxwf7\n" +
                "GdAqspw5MuNcuCZbXBknX/vWuQIDAQAB\n" +
                "-----END PUBLIC KEY-----";
        try {
            publicKeyFileStream = new FileOutputStream(publicKeyFile);
            publicKeyFileStream.write(publicKeyStr.getBytes());
        }
        catch (Exception e) {
            e.printStackTrace();
        }
        finally {
            try {
                publicKeyFileStream.close();
            }
            catch (Exception e) {
                e.printStackTrace();
            }
        }

        return;
    }

    private String createPublicKey() {
        String algorithm = "RSA";
        String signatureAlg = "SHA256withRSA";
        int keySize = 4096;
        int certExpireInDays = 365;
        String commonName = "CN=KeyManagerTest";
        KeyManager keyManager = new KeyManagerImpl(
                algorithm,
                signatureAlg,
                keySize,
                certExpireInDays,
                commonName);

        String privKeyFileName = getPrivateKeyFileName();
        String publicKeyFileName = getPublicKeyFileName();

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
        String privKeyFileName = getPrivateKeyFileName();
        String publicKeyFileName = getPublicKeyFileName();

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

    private String getGroupInviteRequest(Account account, String groupAddress, HashMap<String, String> inviteeMap) {
        String transactionStr = null;
        try {
            System.out.println("from_address: " + account.getAddress().getHex());
            // System.out.println("to_address: " + toAccountAddress);

            // replace data by public key
            long unixTime = System.currentTimeMillis() / 1000L;
            String timeString = Long.toString(unixTime);

            String signedTimeString = signStringByPrivateKey(privateKey, timeString);

            // System.out.println("public key: " + data);
            transactionStr = signTransaction(account, signedTimeString.getBytes("UTF8"));
            System.out.println("register input length: " + transactionStr.length() + " string: " + transactionStr);
            JSONObject requestNode = new JSONObject();
            requestNode.put("from_address", account.getAddress().getHex());
            requestNode.put("group_address", groupAddress);
            requestNode.put("time_stamp", timeString);
            System.out.println("time stamp: " + timeString + " signed time stamp: " + signStringByPrivateKey(privateKey, timeString));
            requestNode.put("transaction", transactionStr);

            // add inviteeList into JSONArray
            JSONObject inviteeDict = new JSONObject();
            Set<String> keySet = inviteeMap.keySet();
            for (String key: keySet) {
                // JSONObject inviteeNode = new JSONObject();
                inviteeDict.put(key, inviteeMap.get(key));
                // inviteeArray.put(inviteeNode);
            }
            requestNode.put("group_invitee_list", inviteeDict);

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
