package it.infn.security.saml.ocp;

import it.infn.security.saml.schema.AttributeNameInterface;

public class SPIDAttributeName
    implements AttributeNameInterface {

    private String name;

    private String friendlyName;

    public SPIDAttributeName(String name, String fName) {
        this.name = name;
        this.friendlyName = fName;
    }

    public String getNameId() {
        return name;
    }

    public String getFriendlyName() {
        return friendlyName;
    }

    public String getNameFormat() {
        return "urn:oasis:names:tc:SAML:2.0:attrname-format:basic";
    }

}