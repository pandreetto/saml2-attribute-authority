package it.infn.security.saml.spmetadata;

import java.util.ArrayList;

public class SPMetadata {

    private long expirationTime;

    private ArrayList<String> attributes;

    public SPMetadata() {
        attributes = new ArrayList<String>();
    }

    public void addAttribute(String attr) {
        attributes.add(attr);
    }

    public String[] getRequiredAttributes() {
        String[] result = new String[attributes.size()];
        attributes.toArray(result);
        return result;
    }

    public void setExpiration(long eTime) {
        expirationTime = eTime;
    }

    public long getExpiration() {
        return expirationTime;
    }

}