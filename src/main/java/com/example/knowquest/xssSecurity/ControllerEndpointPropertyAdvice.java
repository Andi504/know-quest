package com.example.knowquest.xssSecurity;


import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.aspectj.lang.annotation.Pointcut;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

@Aspect
@Component
public class ControllerEndpointPropertyAdvice {

    private static final Logger LOGGER = LoggerFactory.getLogger(ControllerEndpointPropertyAdvice.class);

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
        Object response = pjp.proceed(pjp.getArgs());
        LOGGER.info("Response: {}", response);
        return response;
    }

    @Before("withinRestControllerClass()")
    public void beforeMethodExecution(JoinPoint joinPoint) {
        LOGGER.debug("Before method execution: {}", joinPoint.getSignature());
    }
}
