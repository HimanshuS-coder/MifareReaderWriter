package com.example.mifarereaderwriter;

import static com.google.android.material.internal.ContextUtils.getActivity;

import android.app.Activity;
import android.content.Intent;
import android.media.MediaPlayer;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.tech.MifareClassic;
import android.os.Bundle;
import android.os.VibrationEffect;
import android.os.Vibrator;
import android.provider.Settings;
import android.util.Log;
import android.view.View;
import android.widget.ProgressBar;
import android.widget.TextView;
import android.widget.Toast;

import androidx.activity.EdgeToEdge;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.graphics.Insets;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowInsetsCompat;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class ReadTagActivity extends AppCompatActivity implements NfcAdapter.ReaderCallback {

    // there are 3 default keys available
    // MifareClassic.KEY_MIFARE_APPLICATION_DIRECTORY: a0a1a2a3a4a5
    // MifareClassic.KEY_DEFAULT:                      ffffffffffff
    // MifareClassic.KEY_NFC_FORUM:                    d3f7d3f7d3f7
    
    String TAG = "ReadTag";
    TextView tagDetails,tagData;
    NfcAdapter mNfcAdapter;
    ProgressBar progressBar;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        EdgeToEdge.enable(this);
        setContentView(R.layout.activity_read_tag);
        tagDetails = findViewById(R.id.tagDetails);
        tagData = findViewById(R.id.tagData);
        mNfcAdapter = NfcAdapter.getDefaultAdapter(this);
        progressBar = findViewById(R.id.progressBar);

    }

    @Override
    public void onTagDiscovered(Tag tag) {
        Log.d(TAG,"Tag Discovered");
        playSinglePing();
        doVibrate(this);

        MifareClassic mfc = MifareClassic.get(tag);
        if (mfc == null) {
            runOnUiThread(()->{
                Toast.makeText(this, "The tag is not readable with Mifare Classic classes, sorry", Toast.LENGTH_SHORT).show();
            });
            return;
        }

        // Make progress Bar visible
        runOnUiThread(()->{
            progressBar.setVisibility(View.VISIBLE);
        });

        // get card details
        int ttype = mfc.getType();
        StringBuilder sb = new StringBuilder();
        sb.append("MifareClassic TYPE: ").append(ttype).append("\n \n");
        int tagSize = mfc.getSize();
        sb.append("MifareClassic SIZE: ").append(tagSize).append("\n \n");
        int sectorCount = mfc.getSectorCount();
        sb.append("MifareClassic SECTOR COUNT: ").append(sectorCount).append("\n \n");
        int blockCount = mfc.getBlockCount();
        sb.append("MifareClassic BLOCK COUNT: ").append(blockCount).append("\n \n");
        byte[] id = mfc.getTag().getId();
        sb.append("TAG ID: ").append(bytesToHexNpe(id)).append("\n \n");

        String[] techlist = mfc.getTag().getTechList();
        sb.append("TAG TECHLIST: ").append(Arrays.toString(techlist));

        try {
            mfc.connect();

            byte[] dataBytes = new byte[(16*2)+(15*3*16)]; // sector 0 has 2 blocks and rest of the sectors have 3 data blocks each

            if (mfc.isConnected()){

                byte[] keyABytes = null;
                byte[] keyBBytes = null;
                int j =2;

                for (int secCnt = 0; secCnt < sectorCount; secCnt++) {
                    boolean isAuthenticated = false;
                    Log.d(TAG, "readMifareSector " + secCnt);

                    try {
                        if (mfc.authenticateSectorWithKeyA(secCnt, MifareClassic.KEY_MIFARE_APPLICATION_DIRECTORY)) {
                            keyABytes = MifareClassic.KEY_MIFARE_APPLICATION_DIRECTORY.clone();
                            Log.d(TAG, "Auth success with A KEY_MIFARE_APPLICATION_DIRECTORY");
                            isAuthenticated = true;
                        } else if (mfc.authenticateSectorWithKeyA(secCnt, MifareClassic.KEY_DEFAULT)) {
                            keyABytes = MifareClassic.KEY_DEFAULT.clone();
                            Log.d(TAG, "Auth success with A KEY_DEFAULT");
                            isAuthenticated = true;
                        } else if (mfc.authenticateSectorWithKeyA(secCnt, MifareClassic.KEY_NFC_FORUM)) {
                            keyABytes = MifareClassic.KEY_NFC_FORUM.clone();
                            Log.d(TAG, "Auth success with A KEY_NFC_FORUM");
                            isAuthenticated = true;
                        } else if (mfc.authenticateSectorWithKeyB(secCnt, MifareClassic.KEY_DEFAULT)) {
                            keyBBytes = MifareClassic.KEY_DEFAULT.clone();
                            Log.d(TAG, "Auth success with B KEY_DEFAULT");
                            isAuthenticated = true;
                        } else if (mfc.authenticateSectorWithKeyB(secCnt, MifareClassic.KEY_MIFARE_APPLICATION_DIRECTORY)) {
                            keyBBytes = MifareClassic.KEY_MIFARE_APPLICATION_DIRECTORY.clone();
                            isAuthenticated = true;
                            Log.d(TAG, "Auth success with B KEY_MIFARE_APPLICATION_DIRECTORY");
                        } else if (mfc.authenticateSectorWithKeyB(secCnt, MifareClassic.KEY_NFC_FORUM)) {
                            keyBBytes = MifareClassic.KEY_NFC_FORUM;
                            Log.d(TAG, "Auth success with B KEY_NFC_FORUM");
                            isAuthenticated = true;
                        } else if (mfc.authenticateSectorWithKeyA(secCnt, hexStringToByteArray("4D57414C5648"))) {
                            keyABytes = hexStringToByteArray("4D57414C5648");
                            Log.d(TAG, "Auth success with A Crowne Plaza key");
                            isAuthenticated = true;
                            //4D57414C5648 can be custom as well
                        } else {
                            Log.d(TAG, "NO Auth success");
                        }

                        // get the starting blockindex of the sector
                        int block_index = mfc.sectorToBlock(secCnt);
                        Log.d(TAG,"block index: "+block_index);
                        // get total blocks present in sector
                        int blocksInSector = mfc.getBlockCountInSector(secCnt);
                        Log.d(TAG,"block in sector: "+blocksInSector);
                        // get the data of each block
                        //dataBytes = new byte[(16 * blocksInSector)];
                        if(secCnt==0){
                            for (int blockInSectorCount = 1, i = 0; blockInSectorCount < blocksInSector-1; blockInSectorCount++,i++) {
                                // get following data
                                byte[] block = mfc.readBlock((block_index + blockInSectorCount));
                                System.arraycopy(block, 0, dataBytes, (i * 16), 16);
                                System.out.println("*** dataBytes for sector: " + secCnt + "| Block no: "+ (block_index+blockInSectorCount) +" | length: " + block.length + " data: " + bytesToHexNpe(block));
                            }
                        }else{
                            for (int blockInSectorCount = 0; blockInSectorCount < blocksInSector-1; blockInSectorCount++,j++) {
                                // get following data
                                byte[] block = mfc.readBlock((block_index + blockInSectorCount));
                                System.arraycopy(block, 0, dataBytes, (j * 16), 16);
                                System.out.println("*** dataBytes for sector: " + secCnt + "| Block no: "+ (block_index+blockInSectorCount) +" | length: " + block.length + " data: " + bytesToHexNpe(block));
                            }
                        }

                    } catch (IOException e) {
                        Log.e(TAG, "Sector " + secCnt + " IOException: " + e.getMessage());
                        e.printStackTrace();
                    }


                }
                System.out.println("length of dataBytes: " + dataBytes.length + "*** dataBytes data: " + bytesToHexNpe(dataBytes));


            }

            runOnUiThread(()->{
                progressBar.setVisibility(View.INVISIBLE);
                tagDetails.setText(sb.toString());

                StringBuilder s = new StringBuilder();
                s.append("*************** RECORDS ON TAG *************** ").append("\n \n");
                s.append(bytesToString(dataBytes));
                tagData.setText(s.toString());
            });
            mfc.close();


        } catch (IOException e) {
            throw new RuntimeException(e);
        }

    }

    public static String bytesToHexNpe(byte[] bytes) {
        if (bytes == null) return "";
        StringBuffer result = new StringBuffer();
        for (byte b : bytes)
            result.append(Integer.toString((b & 0xff) + 0x100, 16).substring(1));
        return result.toString();
    }

    public String bytesToString(byte[] bytes) {
        if (bytes == null || bytes.length == 0) {
            return "NO DATA FOUND";
        }

        boolean allZeros = true;
        for (byte b : bytes) {
            if (b != 0) {
                allZeros = false;
                break;
            }
        }

        if (allZeros) {
            return "NO DATA FOUND";
        }

        return new String(bytes, StandardCharsets.UTF_8);
    }

    private void showWirelessSettings() {
        Toast.makeText(this, "You need to enable NFC", Toast.LENGTH_SHORT).show();
        Intent intent = new Intent(Settings.ACTION_WIRELESS_SETTINGS);
        startActivity(intent);
    }

    private void playSinglePing() {
        MediaPlayer mp = MediaPlayer.create(this, R.raw.notification_decorative_02);
        mp.start();
    }

    public static void doVibrate(Activity activity) {
        if (activity != null) {
            ((Vibrator) activity.getSystemService(VIBRATOR_SERVICE)).vibrate(VibrationEffect.createOneShot(150, 10));
        }
    }

    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    @Override
    public void onPause() {
        super.onPause();
        if (mNfcAdapter != null)
            mNfcAdapter.disableReaderMode(this);
    }

    @Override
    public void onResume() {
        super.onResume();

        if (mNfcAdapter != null) {

            if (!mNfcAdapter.isEnabled())
                showWirelessSettings();

            Bundle options = new Bundle();
            // Work around for some broken Nfc firmware implementations that poll the card too fast
            options.putInt(NfcAdapter.EXTRA_READER_PRESENCE_CHECK_DELAY, 250);

            // Enable ReaderMode for all types of card and disable platform sounds
            // the option NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK is NOT set
            // to get the data of the tag afer reading
            mNfcAdapter.enableReaderMode(this,
                    this,
                    NfcAdapter.FLAG_READER_NFC_A |
                            NfcAdapter.FLAG_READER_NFC_B |
                            NfcAdapter.FLAG_READER_NFC_F |
                            NfcAdapter.FLAG_READER_NFC_V |
                            NfcAdapter.FLAG_READER_NFC_BARCODE |
                            NfcAdapter.FLAG_READER_NO_PLATFORM_SOUNDS,
                    options);
        }
    }
}