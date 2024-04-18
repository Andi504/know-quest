package com.example.knowquest.xssSecurity;


import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Pointcut;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

@Aspect
@Component
public class ControllerEndpointPropertyAdvice {

    private static final Logger LOGGER = LoggerFactory.getLogger(ControllerEndpointPropertyAdvice.class);

    private final PropertyScanner propertyScanner;

    public ControllerEndpointPropertyAdvice(PropertyScanner propertyScanner) {
        this.propertyScanner = propertyScanner;
    }


    @Pointcut("within(@org.springframework.web.bind.annotation.RestController *) && " +
            "!@annotation(org.springframework.web.bind.annotation.RequestParam) && " +
            "!@annotation(org.springframework.web.bind.annotation.RequestBody)")
    private void withinRestControllerClass() {
    }


    @Pointcut("execution(* *(@org.springframework.web.bind.annotation.RequestParam (*), ..))")
    private void methodExceptingRequestParam() {
    }

    @Pointcut("execution(* *(@org.springframework.web.bind.annotation.RequestBody (*), ..))")
    private void methodExceptingRequestBody() {
    }

    @Around("(withinRestControllerClass() && (methodExceptingRequestParam() || methodExceptingRequestBody()))")
    //@Around("withinRestControllerClass()")
    public Object process(final ProceedingJoinPoint pjp) throws Throwable {

        LOGGER.info("Intercepted method: {}", pjp.getSignature());

        LOGGER.info("Intercepted method: {}", pjp.getSignature());

        // Extract request object from method arguments
        Object[] methodArgs = pjp.getArgs();
        Object requestObject = extractRequestObject(methodArgs);

        // Sanitize request object
        methodArgs[0] = propertyScanner.scan(requestObject);


        // Proceed with the sanitized request object and return the result
        return pjp.proceed(methodArgs);
    }

    private Object extractRequestObject(Object[] methodArgs) {
        // Assuming the first argument is the request object
        return methodArgs[0];
    }
}
