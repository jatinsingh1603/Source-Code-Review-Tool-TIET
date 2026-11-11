package com.bank.web;

import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class StatementServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        String accountRef = request.getParameter("account");
        response.getWriter().println(render(accountRef));
    }

    private String render(String accountRef) {
        return "statement for " + accountRef;
    }
}
