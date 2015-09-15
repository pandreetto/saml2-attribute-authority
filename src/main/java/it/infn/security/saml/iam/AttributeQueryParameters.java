package it.infn.security.saml.iam;

public class AttributeQueryParameters {

    private String userId;

    public AttributeQueryParameters(String uid) {
        userId = uid;
    }

    public String getId() {
        return userId;
    }
}