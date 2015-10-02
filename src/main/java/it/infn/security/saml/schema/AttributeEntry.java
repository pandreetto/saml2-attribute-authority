package it.infn.security.saml.schema;

import java.util.ArrayList;

public class AttributeEntry
    extends ArrayList<AttributeValueInterface> {

    public static final long serialVersionUID = 1443103746;

    /*
     * TODO missing metadata (creation time, modification time, ecc)
     */
    private AttributeNameInterface name;

    public AttributeEntry(AttributeNameInterface name) {
        this.name = name;
    }

    public AttributeNameInterface getName() {
        return name;
    }

}