package it.infn.security.saml.ocp;

import it.infn.security.saml.schema.AttributeValueInterface;

public class SPIDAttributeValue
    implements AttributeValueInterface {

    private String value;

    public SPIDAttributeValue(String value) {
        this.value = value;
    }

    public Object getRawValue() {
        return value;
    }
    
    public String encode(String format) {
        return value;
    }

    public String getDescription() {
        return "";
    }

}