package com.bank.jobs;

public class Scheduler {
    private int pending;

    public Runnable build(final int weight) {
        class Batch {
            int size = weight;
        }
        Batch batch = new Batch();
        return new Runnable() {
            @Override
            public void run() {
                pending += batch.size;
            }
        };
    }

    static class Window {
        long opensAt;
    }
}
