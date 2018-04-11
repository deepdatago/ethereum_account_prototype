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
import java.util.Base64;

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



    private BottomNavigationView.OnNavigationItemSelectedListener mOnNavigationItemSelectedListener
            = new BottomNavigationView.OnNavigationItemSelectedListener() {

        @Override
        public boolean onNavigationItemSelected(@NonNull MenuItem item) {
            switch (item.getItemId()) {
                case R.id.navigation_home:
                    String transactionStr = "transaction";
                    Accounts accounts = null;
                    Account account = null;

                    try {
                        // following code is to demo the signing of transaction
                        accounts = ks.getAccounts();
                        if (accounts.size() <= 1) {
                            createUser();
                        }
                        account = accounts.get(1);

                        // replace data by public key
                        String data = "very long data very long data very long data very long data very long data very long data very long data very long data very long data very long data ";

                        transactionStr = signTransaction(account, data.getBytes("UTF8"));
                    } catch (Exception e) {
                        transactionStr = e.getMessage();
                        e.printStackTrace();

                    }

                    mTextMessage.setText(transactionStr);
                    // mTextMessage.setText(newAcc.getAddress().getHex());
                    // mTextMessage.setText(R.string.title_home);
                    return true;
                case R.id.navigation_dashboard:
                    mTextMessage.setText(R.string.title_dashboard);
                    return true;
                case R.id.navigation_notifications:
                    mTextMessage.setText(R.string.title_notifications);
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
            }
            account = accounts.get(0);

            // replace data by public key
            //String data = "very long data very long data very long data very long data very long data very long data very long data very long data very long data very long data ";
            String data = createPublicKey();
            System.out.println("public key: " + data);
            transactionStr = signTransaction(account, data.getBytes("UTF8"));
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

            nonce = this.node.getEthereumClient().getPendingNonceAt(context, account.getAddress());
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
            System.out.println("signed.getFrom: " + signed.getFrom(chain).getHex());
            returnStr = signed.encodeJSON();
            Transaction newTrans = Geth.newTransactionFromJSON(returnStr);
            newTrans.getFrom(chain);
            System.out.println("newTrans.getFrom: " + newTrans.getFrom(chain).getHex());
            System.out.println("signed encodeJSON: " + returnStr);

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

}
