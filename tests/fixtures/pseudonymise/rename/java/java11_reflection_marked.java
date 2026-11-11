package com.bank.tools;

public class Probe {
    private long festivalBonus = 7;

    public Object read(Probe target) throws Exception {
        java.lang.reflect.Field field = target.getClass().getDeclaredField("festivalBonus");
        field.setAccessible(true);
        return field.get(target);
    }
}
