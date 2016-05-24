package it.infn.security.saml.datasource;

public class AttrValueTuple {

    private String value;

    private String type;

    public AttrValueTuple(String value, String type) {

        this.value = value;
        this.type = type;

    }

    public String getValue() {
        return value;
    }

    public String getType() {
        return type;
    }
}