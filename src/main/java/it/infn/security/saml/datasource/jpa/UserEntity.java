package it.infn.security.saml.datasource.jpa;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Index;
import javax.persistence.Table;

@Entity
@Table(name = "users", indexes = { @Index(columnList = "userName", unique = true) })
public class UserEntity
    extends ResourceEntity {

    @Column(nullable = false)
    private String userName;

    @Column(nullable = false)
    private String commonName;

    public UserEntity() {
    }

    public void setUserName(String uname) {
        userName = uname;
    }

    public String getUserName() {
        return userName;
    }

    public void setCommonName(String cn) {
        commonName = cn;
    }

    public String getCommonName() {
        return commonName;
    }

    public boolean equals(Object other) {
        return super.equals(other);
    }

    public int hashCode() {
        return super.hashCode();
    }

}