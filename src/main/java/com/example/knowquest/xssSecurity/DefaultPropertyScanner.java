package com.example.knowquest.xssSecurity;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.beans.PropertyDescriptor;
import java.lang.reflect.Method;
import java.util.*;

@Service
public class DefaultPropertyScanner implements PropertyScanner {

    private static final Logger LOGGER = LoggerFactory.getLogger(DefaultPropertyScanner.class);

    private final SanitizerProvider sanitizerProvider;

    public DefaultPropertyScanner(SanitizerProvider sanitizerProvider) {
        this.sanitizerProvider = sanitizerProvider;
    }

    public Object scan(Object obj) {
        if (obj instanceof String) {
            return sanitizeString((String) obj);
        } else if (obj instanceof Map) {
            return sanitizeMap((Map<?, ?>) obj);
        } else if (obj instanceof Collection<?>) {
            return sanitizeCollection((Collection<?>) obj);
        } else if (obj != null) {
            return sanitizeObject(obj);
        } else {
            return null;
        }
    }

    private String sanitizeString(String value) {
        return (value != null) ? sanitizerProvider.getPolicyFactory().sanitize(value) : null;
    }

    private Map<String, String> sanitizeMap(Map<?, ?> map) {
        Map<String, String> sanitizedMap = new HashMap<>();
        for (Map.Entry<?, ?> entry : map.entrySet()) {
            Object key = entry.getKey();
            Object value = entry.getValue();
            if (key instanceof String && value instanceof String) {
                String sanitizedKey = sanitizeString((String) key);
                String sanitizedValue = sanitizeString((String) value);
                sanitizedMap.put(sanitizedKey, sanitizedValue);
            } else {
                // Recursively sanitize nested maps
                Map<String, String> nestedMap = sanitizeMap((Map<?, ?>) value);
                sanitizedMap.putAll(nestedMap);
            }
        }
        return sanitizedMap;
    }

    private Collection<?> sanitizeCollection(Collection<?> collection) {
        List<Object> sanitizedList = new ArrayList<>();
        for (Object item : collection) {
            Object sanitizedItem = scan(item);
            sanitizedList.add(sanitizedItem);
        }
        return sanitizedList;
    }

    private Object sanitizeObject(Object obj) {
        try {
            Class<?> clazz = obj.getClass();
            Object sanitizedObj = clazz.getDeclaredConstructor().newInstance();
            PropertyDescriptor[] descriptors = org.apache.commons.beanutils.PropertyUtils.getPropertyDescriptors(obj);
            for (PropertyDescriptor descriptor : descriptors) {
                Method readMethod = descriptor.getReadMethod();
                Method writeMethod = descriptor.getWriteMethod();
                if (readMethod != null && writeMethod != null) {
                    Object value = readMethod.invoke(obj);
                    if (value != null) {
                        Object sanitizedValue = sanitizePropertyValue(value);
                        writeMethod.invoke(sanitizedObj, sanitizedValue);
                    }
                }
            }
            return sanitizedObj;
        } catch (Exception e) {
            LOGGER.error("Error occurred during object sanitization: {}", e.getMessage());
            return null;
        }
    }

    private Object sanitizePropertyValue(Object value) {
        return (isLikelyEmail((String) value) && isValidEmail((String) value)) ? value : sanitizeString((String) value);
    }

    private boolean isLikelyEmail(String value) {
        return value.contains("@");
    }

    private boolean isValidEmail(String email) {
        String emailRegex = "^[A-Za-z0-9._%+-]+(?:@[A-Za-z0-9.-]+)?\\.[A-Za-z]{2,}$";
        return email.matches(emailRegex);
    }
}
