package com.krestfield.ezsign.test;

import com.krestfield.ezsign.EzSignClient;

public class MultithreadedClientTest
{
    private static int numThreads = 100;
    private static int numIterations = 100;
    private static String channel = "SOFT";

    public static void main(String args[])
    {
        try
        {
            System.out.println("Multithreaded Client Test...");

            // Create Client
            String keystoreFilename = "C:\\EzSignV4.2.3\\EzSignServer\\keystores\\127.0.0.1.p12";
            //String keystoreFilename = "C:\\EzSignV4.2.3\\EzSignServer\\keystores\\127.0.0.1.jks";

            String keystorePassword = "password";

            EzSignClient client = new EzSignClient("127.0.0.1", 5656).useTls().useClientTls(keystoreFilename, keystorePassword, "PKCS12");
            //EzSignClient client = new EzSignClient("127.0.0.1", 5656).useTls(); // WORKING
            //EzSignClient client = new EzSignClient("127.0.0.1", 5656);


            MultithreadedClientTestThread[] threads = new MultithreadedClientTestThread[numThreads];
            //TestThread thread = null;

            long startTime = System.nanoTime();
            for (int i = 0; i < numThreads; i++)
            {
                threads[i] = new MultithreadedClientTestThread(client, "Thread " + i, channel, numIterations);
                threads[i].start();
            }

            for (int i = 0; i < numThreads; i++)
            {
                threads[i].getThread().join();
                while (!threads[i].isFinished())
                    Thread.sleep(1);
            }

            long endTime = System.nanoTime();
            long duration = (endTime - startTime);
            System.out.println("Time Taken: " + duration / 1000000 + " milli seconds");
            System.out.println("Time Taken Per Transaction: " + duration / 1000000 / (numIterations * numThreads) + " milli seconds");
        }
        catch (Exception e)
        {
            System.out.println(e.getMessage());
        }
    }
}
