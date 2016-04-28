package it.infn.security.saml.spmetadata;

import java.util.HashSet;
import java.util.Set;

public class SPMetadata {

    private long expirationTime;

    private HashSet<String> attributes;

    public SPMetadata() {
        attributes = new HashSet<String>();
    }

    public void addAttribute(String attr) {
        attributes.add(attr);
    }

    public String[] getAttributeArray() {
        String[] result = new String[attributes.size()];
        attributes.toArray(result);
        return result;
    }

    public Set<String> getAttributeSet() {
        return attributes;
    }

    public void setExpiration(long eTime) {
        expirationTime = eTime;
    }

    public long getExpiration() {
        return expirationTime;
    }

}