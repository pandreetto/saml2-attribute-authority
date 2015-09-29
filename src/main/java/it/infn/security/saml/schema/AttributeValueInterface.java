package it.infn.security.saml.schema;

public interface AttributeValueInterface {

    public String getId();

    public String getType();

    public Object getValue();

    public String encode(String format)
        throws SchemaManagerException;

    public String getDescription();

}