package com.example.knowquest.xssSecurity;

import org.owasp.html.PolicyFactory;

public interface SanitizerProvider {
    PolicyFactory getPolicyFactory();

}
