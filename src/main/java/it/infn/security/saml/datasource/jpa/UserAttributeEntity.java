package it.infn.security.saml.datasource.jpa;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.Table;

@Entity
@Table(name = "user_attrs")
public class UserAttributeEntity {

    @Id
    @GeneratedValue
    private Long id;

    @Column(name = "attr_name", nullable = false)
    private String key;

    @Column(name = "attr_value", nullable = false)
    private String value;
    
    public UserAttributeEntity() {
        
    }
    
    public UserAttributeEntity(String k, String v) {
        key = k;
        value = v;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public Long getId() {
        return id;
    }

    public void setKey(String k) {
        key = k;
    }

    public String getKey() {
        return key;
    }

    public void setValue(String v) {
        value = v;
    }

    public String getValue() {
        return value;
    }
}