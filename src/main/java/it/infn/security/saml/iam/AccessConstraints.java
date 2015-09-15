package it.infn.security.saml.iam;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;

import org.opensaml.saml2.core.Attribute;

public class AccessConstraints {

    private HashSet<String> filterTable;

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

}