package it.infn.security.scim.core;

import java.util.HashSet;

import it.infn.security.saml.schema.SchemaManagerException;
import it.infn.security.scim.protocol.SCIMConstants;

public class AttributeFilter {

    public static final long serialVersionUID = 1474363015L;

    private int mode;

    private HashSet<String> aTable;

    public AttributeFilter() {
        mode = 0;
        aTable = null;
    }

    public AttributeFilter(String reqStr, String exclStr) throws SchemaManagerException {

        if (reqStr == null)
            reqStr = "";
        if (exclStr == null)
            exclStr = "";

        if (reqStr.length() == 0 && exclStr.length() == 0) {
            mode = 0;
            aTable = null;
        }

        if (reqStr.length() > 0 && exclStr.length() > 0) {
            throw new SchemaManagerException("Cannot specify both attributes and excludeAttributes",
                    SCIMConstants.CODE_BAD_REQUEST);
        }

        if (reqStr.length() > 0) {
            mode = 1;
            aTable = new HashSet<String>();
            for (String tmps : reqStr.split(",")) {
                aTable.add(tmps.trim().toLowerCase());
            }
        } else {
            mode = 2;
            aTable = new HashSet<String>();
            for (String tmps : exclStr.split(",")) {
                aTable.add(tmps.trim().toLowerCase());
            }
        }

    }

    public boolean canShow(String attrName) {

        if (mode == 0)
            return true;

        if (mode == 1 && aTable.contains(attrName))
            return true;

        if (mode == 2 && !aTable.contains(attrName))
            return true;

        return false;
    }

    public boolean canShowNS(String namespace, String attrName) {
        return canShow(namespace + ":" + attrName);
    }
}