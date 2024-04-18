package com.example.knowquest.xssSecurity;


import lombok.Getter;
import lombok.Setter;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.owasp.html.PolicyFactory;
import org.owasp.html.Sanitizers;

import java.util.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class DefaultPropertyScannerTest {

    @Mock
    private SanitizerProvider sanitizerProvider;

    @InjectMocks
    private DefaultPropertyScanner propertyScanner;

    @Test
    void scan_mapInput_shouldReturnSanitizedMap() {
        // Arrange
        Map<String, String> inputMap = new HashMap<>();
        inputMap.put("key1", "<script>alert('XSS')</script>");
        inputMap.put("key2", "safe");

        Map<String, String> expectedMap = new HashMap<>();
        expectedMap.put("key1", "");
        expectedMap.put("key2", "safe");

        PolicyFactory policyFactoryMock = Sanitizers.FORMATTING.and(Sanitizers.LINKS);
        when(sanitizerProvider.getPolicyFactory()).thenReturn(policyFactoryMock);

        // Act
        Object result = propertyScanner.scan(inputMap);

        // Assert
        assertEquals(expectedMap, result);
    }

    @Test
    void scan_stringInput_shouldReturnSanitizedString() {
        // Arrange
        String input = "<script>alert('XSS')</script>";
        String expected = "";

        // Act
        PolicyFactory policyFactoryMock = Sanitizers.FORMATTING.and(Sanitizers.LINKS);
        when(sanitizerProvider.getPolicyFactory()).thenReturn(policyFactoryMock);
        Object result = propertyScanner.scan(input);

        // Assert
        assertEquals(expected, result);
    }

    @Test
    void scan_collectionInput_shouldReturnSanitizedCollection() {
        // Arrange
        List<String> inputList = Arrays.asList("<script>alert('XSS')</script>", "safe");
        List<String> expectedList = Arrays.asList("", "safe");

        // Act
        PolicyFactory policyFactoryMock = Sanitizers.FORMATTING.and(Sanitizers.LINKS);
        when(sanitizerProvider.getPolicyFactory()).thenReturn(policyFactoryMock);
        Object result = propertyScanner.scan(inputList);

        // Assert
        assertEquals(expectedList, result);
    }

    @Test
    void scan_nullInput_shouldReturnNull() {

        Object result = propertyScanner.scan(null);

        // Assert
        assertNull(result);
    }

    @Test
    void scan_emptyMapInput_shouldReturnEmptyMap() {
        // Arrange
        Map<String, String> inputMap = Collections.emptyMap();

        // Act
        Object result = propertyScanner.scan(inputMap);

        // Assert
        assertInstanceOf(Map.class, result);
        assertTrue(((Map<?, ?>) result).isEmpty());
    }

    @Test
    void scan_nestedCollectionInput_shouldReturnSanitizedNestedCollection() {
        // Arrange
        List<List<String>> nestedList = new ArrayList<>();
        nestedList.add(Arrays.asList("<script>alert('XSS')</script>", "safe"));
        nestedList.add(Arrays.asList("unsafe", "<script>alert('XSS')</script>"));

        List<List<String>> expectedNestedList = new ArrayList<>();
        expectedNestedList.add(Arrays.asList("", "safe"));
        expectedNestedList.add(Arrays.asList("unsafe", ""));

        // Act
        PolicyFactory policyFactoryMock = Sanitizers.FORMATTING.and(Sanitizers.LINKS);
        when(sanitizerProvider.getPolicyFactory()).thenReturn(policyFactoryMock);
        Object result = propertyScanner.scan(nestedList);

        // Assert
        assertEquals(expectedNestedList, result);
    }


    @Test
    void scan_emptyCollectionInput_shouldReturnEmptyCollection() {
        // Arrange
        List<String> inputList = Collections.emptyList();

        // Act
        PolicyFactory policyFactoryMock = Sanitizers.FORMATTING.and(Sanitizers.LINKS);
        lenient().when(sanitizerProvider.getPolicyFactory()).thenReturn(policyFactoryMock);
        Object result = propertyScanner.scan(inputList);

        // Assert
        assertTrue(((Collection<?>) result).isEmpty());
    }

    @Test
    void scan_invalidEmail_shouldSanitize() {
        // Arrange
        TestObject inputObj = new TestObject();
        inputObj.setEmail("<script>alert('XSS')</script>");

        // Act
        PolicyFactory policyFactoryMock = Sanitizers.FORMATTING.and(Sanitizers.LINKS);
        when(sanitizerProvider.getPolicyFactory()).thenReturn(policyFactoryMock);
        TestObject result = (TestObject) propertyScanner.scan(inputObj);

        // Assert
        assertEquals("", result.getEmail());
    }

    @Test
    void scan_likelyEmail_shouldNotSanitize() {
        TestObject inputObj = new TestObject();
        inputObj.setEmail("john.doe@example.com");

        // Act
        PolicyFactory policyFactoryMock = Sanitizers.FORMATTING.and(Sanitizers.LINKS);
        lenient().when(sanitizerProvider.getPolicyFactory()).thenReturn(policyFactoryMock);
        TestObject resultObj = (TestObject) propertyScanner.scan(inputObj);

        // Assert
        assertEquals("john.doe@example.com", resultObj.getEmail());
    }

    @Test
    void scan_notLikelyEmail_shouldSanitize() {
        // Arrange
        TestObject inputObj = new TestObject();
        inputObj.setName("This is not an email");

        // Act
        PolicyFactory policyFactoryMock = Sanitizers.FORMATTING.and(Sanitizers.LINKS);
        when(sanitizerProvider.getPolicyFactory()).thenReturn(policyFactoryMock);
        TestObject result = (TestObject) propertyScanner.scan(inputObj);

        // Assert
        assertNull(result.getEmail());
    }

    @Test
    void scan_propertyValueIsEmail_shouldNotSanitize() {
        // Arrange
        TestObject inputObj = new TestObject();
        inputObj.setEmail("john_doe@example.com");

        // Act
        PolicyFactory policyFactoryMock = Sanitizers.FORMATTING.and(Sanitizers.LINKS);
        lenient().when(sanitizerProvider.getPolicyFactory()).thenReturn(policyFactoryMock);
        TestObject resultObj = (TestObject) propertyScanner.scan(inputObj);

        // Assert
        assertEquals("john_doe@example.com", resultObj.getEmail());
    }

    @Test
    void scan_propertyValueIsNotEmail_shouldSanitize() {
        // Arrange
        TestObject inputObj = new TestObject();
        inputObj.setEmail("<script>alert('XSS')</script>");

        // Act
        PolicyFactory policyFactoryMock = Sanitizers.FORMATTING.and(Sanitizers.LINKS);
        when(sanitizerProvider.getPolicyFactory()).thenReturn(policyFactoryMock);
        TestObject resultObj = (TestObject) propertyScanner.scan(inputObj);

        // Assert
        assertEquals("", resultObj.getEmail());
    }

    @Test
    void scan_objectWithPropertiesToSanitize_shouldSanitize() {
        // Arrange
        TestObject inputObj = new TestObject();
        inputObj.setName("<script>alert('XSS')</script>");

        // Act
        PolicyFactory policyFactoryMock = Sanitizers.FORMATTING.and(Sanitizers.LINKS);
        when(sanitizerProvider.getPolicyFactory()).thenReturn(policyFactoryMock);
        TestObject resultObj = (TestObject) propertyScanner.scan(inputObj);

        // Assert
        assertEquals("", resultObj.getName());
    }

    @Test
    void scan_objectWithPropertiesNotToSanitize_shouldNotSanitize() {
        // Arrange
        TestObject inputObj = new TestObject();
        inputObj.setName("safe");

        // Act
        PolicyFactory policyFactoryMock = Sanitizers.FORMATTING.and(Sanitizers.LINKS);
        when(sanitizerProvider.getPolicyFactory()).thenReturn(policyFactoryMock);
        TestObject resultObj = (TestObject) propertyScanner.scan(inputObj);

        // Assert
        assertEquals("safe", resultObj.getName());
    }

    // Define a test object for testing sanitizeObject method
    @Setter
    @Getter
    static class TestObject {
        private String name;
        private String email;

    }
}

