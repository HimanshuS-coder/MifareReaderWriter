package com.example.mifarereaderwriter;

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
import android.text.TextUtils;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
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

public class WriteTagActivity extends AppCompatActivity implements NfcAdapter.ReaderCallback {

    String TAG = "WriteTag";
    NfcAdapter mNfcAdapter;
    EditText writeTagEdit;
    ProgressBar writeTagProgressBar;
    TextView writeTextProgressText,writeTagSize;
    Button writeTagButton;


    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        EdgeToEdge.enable(this);
        setContentView(R.layout.activity_write_tag);
        mNfcAdapter = NfcAdapter.getDefaultAdapter(this);

        writeTagEdit = findViewById(R.id.writeTagEdit);
        writeTagProgressBar = findViewById(R.id.writeTagProgressBar);
        writeTextProgressText = findViewById(R.id.writeTagProgressText);
        writeTagSize = findViewById(R.id.writeTagSize);
        writeTagButton = findViewById(R.id.writeTagButton);

        writeTagButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // Convert the string to a byte array
                byte[] byteArray = writeTagEdit.getText().toString().getBytes();

                // Get the size of the string in bytes
                int sizeInBytes = byteArray.length;

                writeTagSize.setText("Size : "+sizeInBytes);
            }
        });

    }

    @Override
    public void onTagDiscovered(Tag tag) {
        Log.d(TAG,"Tag Discovered");
        playSinglePing();
        doVibrate(this);

        String sendData = writeTagEdit.getText().toString();
        if (TextUtils.isEmpty(sendData)) {
            runOnUiThread(()->{
                Toast.makeText(this,"Please enter some data to write on tag. Aborted",Toast.LENGTH_SHORT).show();
            });
            return;
        }

        MifareClassic mfc = MifareClassic.get(tag);
        if (mfc == null) {
            runOnUiThread(()->{
                Toast.makeText(this, "The tag is not readable with Mifare Classic classes, sorry", Toast.LENGTH_SHORT).show();
            });
            return;
        }

        // Make progress Bar visible
        runOnUiThread(()->{
            writeTagProgressBar.setVisibility(View.VISIBLE);
        });

        try {
            mfc.connect();

            if (mfc.isConnected()) {
                byte[][] byteArray2D = convertStringTo2DByteArray(writeTagEdit.getText().toString(),16);
                byte[] zeroArray = new byte[16];
                int s = byteArray2D.length;
                int j =2;
                for (int secCnt = 0; secCnt < 16; secCnt++) {
                    boolean isAuthenticated = false;
                    Log.d(TAG, "readMifareSector " + secCnt);

                    try {
                        if (mfc.authenticateSectorWithKeyA(secCnt, MifareClassic.KEY_MIFARE_APPLICATION_DIRECTORY)) {
//                            keyABytes = MifareClassic.KEY_MIFARE_APPLICATION_DIRECTORY.clone();
                            Log.d(TAG, "Auth success with A KEY_MIFARE_APPLICATION_DIRECTORY");
                            isAuthenticated = true;
                        } else if (mfc.authenticateSectorWithKeyA(secCnt, MifareClassic.KEY_DEFAULT)) {
//                            keyABytes = MifareClassic.KEY_DEFAULT.clone();
                            Log.d(TAG, "Auth success with A KEY_DEFAULT");
                            isAuthenticated = true;
                        } else if (mfc.authenticateSectorWithKeyA(secCnt, MifareClassic.KEY_NFC_FORUM)) {
//                            keyABytes = MifareClassic.KEY_NFC_FORUM.clone();
                            Log.d(TAG, "Auth success with A KEY_NFC_FORUM");
                            isAuthenticated = true;
                        } else if (mfc.authenticateSectorWithKeyB(secCnt, MifareClassic.KEY_DEFAULT)) {
//                            keyBBytes = MifareClassic.KEY_DEFAULT.clone();
                            Log.d(TAG, "Auth success with B KEY_DEFAULT");
                            isAuthenticated = true;
                        } else if (mfc.authenticateSectorWithKeyB(secCnt, MifareClassic.KEY_MIFARE_APPLICATION_DIRECTORY)) {
//                            keyBBytes = MifareClassic.KEY_MIFARE_APPLICATION_DIRECTORY.clone();
                            isAuthenticated = true;
                            Log.d(TAG, "Auth success with B KEY_MIFARE_APPLICATION_DIRECTORY");
                        } else if (mfc.authenticateSectorWithKeyB(secCnt, MifareClassic.KEY_NFC_FORUM)) {
//                            keyBBytes = MifareClassic.KEY_NFC_FORUM;
                            Log.d(TAG, "Auth success with B KEY_NFC_FORUM");
                            isAuthenticated = true;
                        } else {
                            Log.d(TAG, "NO Auth success");
                        }

                        // get the starting block index of the sector
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
                                byte[] block;
                                if(i<s){
                                    block = byteArray2D[i];
                                }else{
                                    block = zeroArray;
                                }

                                mfc.writeBlock((block_index + blockInSectorCount),block);
//                                mif.writeBlock((block_index + blockInSectorCount), bd1);
//                                System.arraycopy(block, 0, dataBytes, (i * 16), 16);
                                System.out.println("*** dataBytes for sector: " + secCnt + "| Block no: "+ (block_index+blockInSectorCount) +" | length: " + block.length + " data: " + bytesToString(block));
                            }
                        }else{
                            for (int blockInSectorCount = 0; blockInSectorCount < blocksInSector-1; blockInSectorCount++,j++) {
                                // get following data
                                byte[] block;
                                if(j<s){
                                    block = byteArray2D[j];
                                }else{
                                    block = zeroArray;
                                }

                                mfc.writeBlock((block_index + blockInSectorCount),block);
//                                System.arraycopy(block, 0, dataBytes, (j * 16), 16);
                                System.out.println("*** dataBytes for sector: " + secCnt + "| Block no: "+ (block_index+blockInSectorCount) +" | length: " + block.length + " data: " + bytesToString(block));
                            }
                        }

                    } catch (IOException e) {
                        Log.e(TAG, "Sector " + secCnt + " IOException: " + e.getMessage());
                        e.printStackTrace();
                    }


                }

                runOnUiThread(()->{
                    writeTagProgressBar.setVisibility(View.INVISIBLE);
                    writeTextProgressText.setText("Data Written Successfully :)");
                });

                mfc.close();
            }
        } catch (IOException e) {
            runOnUiThread(()->{
                writeTagProgressBar.setVisibility(View.INVISIBLE);
                writeTextProgressText.setText("Some Error Occurred :(");
            });
            e.printStackTrace();
        }
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

//    public static String bytesToHexNpe(byte[] bytes) {
//        if (bytes == null) return "";
//        StringBuffer result = new StringBuffer();
//        for (byte b : bytes)
//            result.append(Integer.toString((b & 0xff) + 0x100, 16).substring(1));
//        return result.toString();
//    }
//
//    public static byte[] hexStringToByteArray(String s) {
//        int len = s.length();
//        byte[] data = new byte[len / 2];
//        for (int i = 0; i < len; i += 2) {
//            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
//                    + Character.digit(s.charAt(i + 1), 16));
//        }
//        return data;
//    }

    public static byte[][] convertStringTo2DByteArray(String text, int rowSize) {
        // Convert the string to a byte array using UTF-8 encoding
        byte[] byteArray = text.getBytes(java.nio.charset.StandardCharsets.UTF_8);

        // Calculate the number of rows needed
        int numRows = (int) Math.ceil((double) byteArray.length / rowSize);

        // Initialize the 2D byte array
        byte[][] byteArray2D = new byte[numRows][rowSize];

        // Fill the 2D byte array
        for (int i = 0; i < byteArray.length; i++) {
            byteArray2D[i / rowSize][i % rowSize] = byteArray[i];
        }

        return byteArray2D;
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