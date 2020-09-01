package com.krestfield.ezsign.test;

import com.krestfield.ezsign.*;

/**
 * Copyright Krestfield 2016
 */
public class TestAESThread implements Runnable
{
    private Thread t;
    private String m_channelName;
    private String m_threadName;
    private String m_keyLabel;
    private int m_numPasses = 100;
    private int m_numGood = 0;
    private int m_numBad = 0;
    private Boolean m_finished = false;

    TestAESThread(String name, String channelName, int numPasses, String keyLabel) {
        m_channelName = channelName;
        m_numPasses = numPasses;
        m_threadName = name;
        m_keyLabel = keyLabel;
        System.out.println("Creating thread for channel " +  channelName );
    }

    public Thread getThread()
    {
        return t;
    }

    public void run() {
        System.out.println("Running " +  m_threadName );
        EzSignClient client = new EzSignClient("127.0.0.1", 5656, 20000, 10000);
        byte[] dataToEncrypt = "Some data to encrypt".getBytes();
        long startTime = System.nanoTime();
        for (int i = 0; i < m_numPasses; i++)
        {
            try
            {
                Thread.sleep(1);
                byte[] encryptedData = client.encryptData(m_channelName, dataToEncrypt, m_keyLabel);
                byte[] clearData = client.decryptData(m_channelName, encryptedData, m_keyLabel);
                m_numGood++;
            }
            catch (KEzSignConnectException connEx)
            {
                m_numBad++;
                System.out.println("There was a connection error: " + connEx.getMessage());
            }
            catch (KEzSignException ex)
            {
                m_numBad++;
                System.out.println("There was a general error: " + ex.getMessage());
            }
            catch (KEncipherException cipherEx)
            {
                System.out.println("There was an error enciphering the data: " + cipherEx.getMessage());
            }
            catch (InterruptedException e)
            {
                e.printStackTrace();
            }
        }
        long endTime = System.nanoTime();

        long duration = (endTime - startTime);
        System.out.println(m_threadName + " - Time Taken: " + duration/1000000 + " milli seconds. GOOD: " + m_numGood + " BAD: " + m_numBad);

        synchronized (m_finished)
        {
            m_finished = true;
        }
    }

    public boolean isFinished()
    {
        synchronized (m_finished)
        {
            return m_finished;
        }
    }


    public void start () {
        if (t == null) {
            t = new Thread (this, m_threadName);
            t.start ();
        }
    }
}
