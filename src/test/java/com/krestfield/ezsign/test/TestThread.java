package com.krestfield.ezsign.test;

import com.krestfield.ezsign.*;

/**
 * Copyright Krestfield 2016
 */
public class TestThread implements Runnable
{
    private Thread t;
    private String m_channelName;
    private String m_threadName;
    private int m_numPasses = 100;
    private int m_numGood = 0;
    private int m_numBad = 0;
    private Boolean m_finished = false;

    TestThread(String name, String channelName, int numPasses) {
        m_channelName = channelName;
        m_numPasses = numPasses;
        m_threadName = name;
        System.out.println("Creating thread for channel " +  channelName );
    }

    public Thread getThread()
    {
        return t;
    }

    public void run() {
        try
        {
            System.out.println("Running " +  m_threadName );

            String keystoreFilename = "C:\\EzSignV4.2.3\\EzSignServer\\keystores\\127.0.0.1.p12";
            //String keystoreFilename = "C:\\EzSignV4.2.3\\EzSignServer\\keystores\\127.0.0.1.jks";

            String keystorePassword = "password";

            EzSignClient client = new EzSignClient("127.0.0.1", 5656).useTls().useClientTls(keystoreFilename, keystorePassword, "PKCS12");
            //EzSignClient client = new EzSignClient("127.0.0.1", 5656, 20000, 10000);
            //EzSignClient client = new EzSignClient("127.0.0.1", 5656, 20000, 10000).useTls();

            long startTime = System.nanoTime();
            for (int i = 0; i < m_numPasses; i++)
            {
                try
                {
                    byte[] randBytes = client.generateRandomBytes(m_channelName, 20);

                    long sigStartTime = System.nanoTime();
                    //byte[] randBytes = {1, 2, 3, 4};
                    byte[] signature = client.signData(m_channelName, randBytes, false);
                    long sigEndTime = System.nanoTime();
                    long sigDuration = (sigEndTime - sigStartTime);
                    //System.out.println("Signing Took: " + sigDuration/1000000 + " milli seconds");

                    //System.out.println("Returned Signature: " + KBase64.ToBase64String(signature));
                    long veriStartTime = System.nanoTime();

                    client.verifySignature(m_channelName, signature, randBytes, false);

                    long veriEndTime = System.nanoTime();
                    long veriDuration = (veriEndTime - veriStartTime);
                    //System.out.println("Verification Took : " + veriDuration/1000000 + " milli seconds");
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
                catch (KSigningException sigEx)
                {
                    System.out.println("There was an error signing the data: " + sigEx.getMessage());
                }
                catch (KVerificationException veriEx)
                {
                    System.out.println("There was an error verifying the signature: " + veriEx.getMessage());
                }
                catch (KRevocationException revEx)
                {
                    System.out.println("There was a revocation exception : " + revEx.getMessage());
                }
                catch (KPathException pathEx)
                {
                    System.out.println("There was a path building exception : " + pathEx.getMessage());
                }
            }
            long endTime = System.nanoTime();

            long duration = (endTime - startTime);
            System.out.println(m_threadName + " - Time Taken: " + duration/1000000 + " milli seconds. GOOD: " + m_numGood + " BAD: " + m_numBad);
            if (m_numBad > 0)
                System.out.println("\nWARNING: THERE WERE FAILURES!!!!\n");

            synchronized (m_finished)
            {
                m_finished = true;
            }
        }
        catch (Exception e)
        {
            System.out.println(e.getMessage());
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
