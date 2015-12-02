package it.infn.security.saml.iam;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;

import org.opensaml.saml2.core.Attribute;

public class AccessConstraints {

    private HashSet<String> filterTable;

    private String signAlgorithm = null;

    private String digestAlgorithm = null;

    private long assertionOffsetTime = -1;

    private long assertionDuration = -1;

    public AccessConstraints() {
        filterTable = new HashSet<String>();
    }

    public void addAttribute(String attrName) {
        filterTable.add(attrName);
    }

    public void removeAttribute(String attrName) {
        filterTable.remove(attrName);
    }

    public Collection<String> getAttributes() {
        return filterTable;
    }

    public List<Attribute> filterAttributes(List<Attribute> inAttrs) {

        if (inAttrs == null || filterTable.size() == 0)
            return inAttrs;

        List<Attribute> result = new ArrayList<Attribute>(inAttrs.size());
        for (Attribute attr : inAttrs) {
            if (filterTable.contains(attr.getName())) {
                result.add(attr);
            }
        }
        return result;

    }

    public void setSignAlgorithm(String algo) {
        signAlgorithm = algo;
    }

    public String getSignAlgorithm() {
        return signAlgorithm;
    }

    public void setDigestAlgorithm(String algo) {
        digestAlgorithm = algo;
    }

    public String getDigestAlgorithm() {
        return digestAlgorithm;
    }

    public void setAssertionOffsetTime(long time) {
        assertionOffsetTime = time;
    }

    public long getAssertionOffsetTime() {
        return assertionOffsetTime;
    }

    public void setAssertionDuration(long duration) {
        assertionDuration = duration;
    }

    public long getAssertionDuration() {
        return assertionDuration;
    }

}