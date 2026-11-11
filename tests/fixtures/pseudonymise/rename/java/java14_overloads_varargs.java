package com.bank.util;

public class Joiner2 {
    public String join(String separator, String... parts) {
        StringBuilder out = new StringBuilder();
        for (String part : parts) {
            out.append(part).append(separator);
        }
        return out.toString();
    }

    public String join(String separator, int count) {
        return join(separator, "x", "y");
    }
}
