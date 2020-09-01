package com.krestfield.ezsign.test;

/**
 * Copyright Krestfield 2016
 */
public class PertTestClient
{
    public static int NUM_THREADS = 100;
    public static int NUM_ITERATIONS = 100;
    public static String CHANNEL = "TEST";

    public static void main(String[] args)
    {
        try
        {
            System.out.println("Usage: PerfTestClient [channel] [num threads] [num iterations]");
            if (args.length > 0)
                CHANNEL = args[0];

            if (args.length > 1)
                NUM_THREADS = Integer.parseInt(args[1]);

            if (args.length > 2)
                NUM_ITERATIONS = Integer.parseInt(args[2]);

            System.out.println("Channel: " + CHANNEL);
            System.out.println("Num Threads: " + NUM_THREADS);
            System.out.println("Num Interations: " + NUM_ITERATIONS);

            TestThread[] threads = new TestThread[NUM_THREADS];
            //TestThread thread = null;
            long startTime = System.nanoTime();
            for (int i = 0; i < NUM_THREADS; i++)
            {
                threads[i] = new TestThread("Thread " + i, CHANNEL, NUM_ITERATIONS);
                threads[i].start();
            }

            for (int i = 0; i < NUM_THREADS; i++) {
                threads[i].getThread().join();
                while (!threads[i].isFinished())
                    Thread.sleep(1);
            }

            long endTime = System.nanoTime();
            long duration = (endTime - startTime);
            System.out.println("Time Taken: " + duration / 1000000 + " milli seconds");
            System.out.println("Time Taken Per Transaction: " + duration / 1000000 / (NUM_ITERATIONS * NUM_THREADS) + " milli seconds");
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }

    }
}
