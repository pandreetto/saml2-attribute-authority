package it.infn.security.saml.datasource.jpa;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.Table;

@Entity
@Table(name = "user_attrs")
public class UserAttributeEntity {

    @Id
    @GeneratedValue
    private Long id;
    
    @ManyToOne
    @JoinColumn(name = "user_id", nullable = false)
    private UserEntity user;

    @Column(name = "attr_name", nullable = false)
    private String key;

    @Column(name = "attr_value", nullable = false)
    private String value;
    
    public UserAttributeEntity() {
        
    }
    
    public UserAttributeEntity(UserEntity usr, String k, String v) {
        user = usr;
        key = k;
        value = v;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public Long getId() {
        return id;
    }
    
    public void setUser(UserEntity usr) {
        user = usr;
    }
    
    public UserEntity getUser() {
        return user;
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