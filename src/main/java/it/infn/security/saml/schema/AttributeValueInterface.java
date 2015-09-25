package it.infn.security.saml.schema;

public interface AttributeValueInterface {

    public Object getRawValue();

    public String encode(String format);

    public String getDescription();

}