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

public class MainActivity extends AppCompatActivity {

    private TextView mTextMessage;

    private BottomNavigationView.OnNavigationItemSelectedListener mOnNavigationItemSelectedListener
            = new BottomNavigationView.OnNavigationItemSelectedListener() {

        @Override
        public boolean onNavigationItemSelected(@NonNull MenuItem item) {
            switch (item.getItemId()) {
                case R.id.navigation_home:
                    EthereumClient client;
                    KeyStore ks = new KeyStore(getFilesDir() + "/keystore", Geth.LightScryptN, Geth.LightScryptP);
                    Accounts accounts = null;
                    Account account = null;
                    String accountsStr = "";
                    Context context = new Context();
                    NodeConfig nodeConfig = new NodeConfig();
                    nodeConfig.setEthereumNetworkID(0);
                    long nonce;
                    double amount = 0;
                    long gasLimit = 0;
                    double gasPrice = 0;
                    String publicAddressStr = "";
                    BigInt chain = new BigInt(nodeConfig.getEthereumNetworkID());


                    try {
                        Node node = Geth.newNode(getFilesDir() + "/.eth1", nodeConfig);
                        node.start();

                        System.out.println("debug 1");
                        accounts = ks.getAccounts();
                        account = accounts.get(0);
                        nonce = node.getEthereumClient().getPendingNonceAt(context, account.getAddress());
                        String data = "my public key";
                        System.out.println("debug 2");
                        Transaction tx = new Transaction(
                                (long) nonce,
                                new Address(publicAddressStr),
                                new BigInt((long) amount),
                                gasLimit, // new BigInt((long) gasLimit),
                                new BigInt((long) gasPrice),
                                data.getBytes("UTF8"));

                        System.out.println("debug 3");
                        Transaction signed = ks.signTxPassphrase(account, "password", tx, chain);
                        System.out.println("signed encodeJSON: " + signed.encodeJSON());
                        // signed.en
                        // node.getEthereumClient().sendTransaction();
                        node.getEthereumClient().sendTransaction(context, signed);

                        // byte[] acctBytes = ks.exportKey(accounts.get(0), "Creation password", "abc123");
                        // Account tmpAcct = ks.importKey(acctBytes, "abc123", "Creation password");
                        // accountsStr = tmpAcct.getAddress().getHex();


                        for (int i = 0; i < accounts.size(); i++)
                        {
                            // accountsStr += accounts.get(i).getAddress().getHex();
                            accountsStr += accounts.get(i).getURL();
                            accountsStr += "\n";
                        }

                        // newAcc = ks.newAccount("Creation password");
                    } catch (Exception e) {
                        e.printStackTrace();

                    }

                    // Account account = new Account();
                    // account.toString();
                    // System.out.println("geth account: " + newAcc.getAddress().getHex());
                    // mTextMessage.setText(newAcc.toString());
                    mTextMessage.setText(accountsStr);
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

        EthereumClient client;
        KeyStore ks = new KeyStore(getFilesDir() + "/keystore", Geth.LightScryptN, Geth.LightScryptP);
        Accounts accounts = null;
        Account account = null;
        String accountsStr = "init1";
        Context context = new Context();
        NodeConfig nodeConfig = new NodeConfig();
        nodeConfig.setEthereumNetworkID(1);
        long nonce;
        double amount = 0;
        long gasLimit = 0;
        double gasPrice = 0;
        String publicAddressStr = "0xce66ae967e95f6f90defa8b58e6ab4a721c3c7fb";
        BigInt chain = new BigInt(nodeConfig.getEthereumNetworkID());

        try {
            // Node node = Geth.newNode(getFilesDir() + "/keystore", nodeConfig);
            Node node = Geth.newNode(getFilesDir() + "/config", nodeConfig);
            System.out.println("debug before start");
            node.start();
            System.out.println("debug after start");
            if (true) // change this to false after the account is created
            {
                Account newAccount = null;
                newAccount = ks.newAccount("Creation password");
                String addressStr = newAccount.getAddress().getHex();
                System.out.println("debug acct hex: " + addressStr);
                return;

            }

            // following code is to demo the signing of transaction
            accounts = ks.getAccounts();
            account = accounts.get(0);
            ks.unlock(account, "Creation password");
            accountsStr = account.getAddress().getHex();
            System.out.println("debug acct hex: " + accountsStr);
            nonce = node.getEthereumClient().getPendingNonceAt(context, account.getAddress());

            // replace data by public key
            String data = "very long data very long data very long data very long data very long data very long data very long data very long data very long data very long data ";
            System.out.println("debug 2");

            Transaction tx = new Transaction(
                    (long) nonce,
                    new Address(publicAddressStr),
                    new BigInt((long) amount),
                    gasLimit, // new BigInt((long) gasLimit),
                    new BigInt((long) gasPrice),
                    data.getBytes("UTF8"));

            // Transaction signed = ks.signTxPassphrase(account, "Creation password", tx, chain);
            Transaction signed = ks.signTx(account, tx, chain);
            // node.getEthereumClient().
            // signed.getFrom(chain);
            System.out.println("signed.getFrom: " + signed.getFrom(chain).getHex());
            accountsStr = signed.encodeJSON();
            Transaction newTrans = Geth.newTransactionFromJSON(accountsStr);
            newTrans.getFrom(chain);
            System.out.println("newTrans.getFrom: " + newTrans.getFrom(chain).getHex());
            System.out.println("signed encodeJSON: " + accountsStr);
            // signed.en
            // node.getEthereumClient().sendTransaction();
            // node.getEthereumClient().sendTransaction(context, signed);

            // byte[] acctBytes = ks.exportKey(accounts.get(0), "Creation password2", "abc123");
            // Account tmpAcct = ks.importKey(acctBytes, "abc123", "Creation password");
            // accountsStr = tmpAcct.getAddress().getHex();

            /*
            for (int i = 0; i < accounts.size(); i++)
            {
                // accountsStr += accounts.get(i).getAddress().getHex();
                accountsStr += accounts.get(i).getURL();
                accountsStr += "\n";
            }
            */

            // newAcc = ks.newAccount("Creation password");
        } catch (Exception e) {
            accountsStr = e.getMessage();
            e.printStackTrace();

        }
        System.out.println("debug 100");
        mTextMessage = (TextView) findViewById(R.id.message);
        mTextMessage.setText(accountsStr);

        // mTextMessage = (TextView) findViewById(R.id.message);
        BottomNavigationView navigation = (BottomNavigationView) findViewById(R.id.navigation);
        navigation.setOnNavigationItemSelectedListener(mOnNavigationItemSelectedListener);
    }

}
