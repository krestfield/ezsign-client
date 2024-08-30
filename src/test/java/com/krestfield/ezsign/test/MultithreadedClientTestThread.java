package com.krestfield.ezsign.test;

import com.krestfield.ezsign.*;


/**
 * Copyright Krestfield 2016
 */
public class MultithreadedClientTestThread implements Runnable
{
    private Thread t;
    private EzSignClient m_client;
    private String m_channelName;
    private String m_threadName;
    private int m_numPasses = 100;
    private int m_numGood = 0;
    private int m_numBad = 0;
    private Boolean m_finished = false;

    MultithreadedClientTestThread(EzSignClient client, String name, String channelName, int numPasses) {
        m_client = client;
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
        System.out.println("Running " +  m_threadName );

        long startTime = System.nanoTime();
        for (int i = 0; i < m_numPasses; i++)
        {
            try
            {
                byte[] randBytes = m_client.generateRandomBytes(m_channelName, 20);

                long sigStartTime = System.nanoTime();
                byte[] signature = m_client.signData(m_channelName, randBytes, false);
                long sigEndTime = System.nanoTime();
                long sigDuration = (sigEndTime - sigStartTime);
                //System.out.println("Signing Took: " + sigDuration/1000000 + " milli seconds");

                //System.out.println("Returned Signature: " + KBase64.ToBase64String(signature));
                long veriStartTime = System.nanoTime();

                m_client.verifySignature(m_channelName, signature, randBytes, false);

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
