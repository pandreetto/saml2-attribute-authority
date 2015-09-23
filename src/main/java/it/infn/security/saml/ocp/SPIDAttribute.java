package it.infn.security.saml.ocp;

import java.util.List;

/*
 * TODO change into a derived class of AbstractSCIMObject
 */
public class SPIDAttribute {
    
    /*
     * TODO missing metadata (creation time, modification time, ecc)
     */
    private String key;
    
    private List<String> values;
    
    private String description;
    
    public SPIDAttribute(String key, List<String> values, String description) {
        this.key = key;
        this.values = values;
        this.description = description;
    }
    
    public String getKey() {
        return key;
    }
    
    public String getDescription() {
        return description;
    }
    
    public List<String> getValues() {
        return values;
    }
}