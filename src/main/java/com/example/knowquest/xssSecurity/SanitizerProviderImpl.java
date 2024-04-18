package com.example.knowquest.xssSecurity;

import org.owasp.html.PolicyFactory;
import org.owasp.html.Sanitizers;
import org.springframework.stereotype.Service;

@Service
public class SanitizerProviderImpl implements SanitizerProvider{
    @Override
    public PolicyFactory getPolicyFactory() {
        return Sanitizers.FORMATTING.and(Sanitizers.LINKS);
    }
}
