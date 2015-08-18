package it.infn.security.saml.datasource.jpa;

import java.util.HashSet;
import java.util.Set;

import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Index;
import javax.persistence.JoinColumn;
import javax.persistence.JoinTable;
import javax.persistence.OneToMany;
import javax.persistence.Table;

@Entity
@Table(name = "users", indexes = { @Index(columnList = "userName", unique = true) })
public class UserEntity
    extends ResourceEntity {

    @Column(nullable = false)
    private String userName;

    @OneToMany(cascade = { CascadeType.ALL })
    @JoinTable(
            name = "bind_user_attrs",
            joinColumns = { @JoinColumn(name = "user_id", referencedColumnName = "id") },
            inverseJoinColumns = { @JoinColumn(name = "attr_id", referencedColumnName = "id") })
    private Set<UserAttributeEntity> userAttributes = new HashSet<UserAttributeEntity>();

    @OneToMany(cascade = { CascadeType.ALL })
    @JoinTable(
            name = "bind_user_addrs",
            joinColumns = { @JoinColumn(name = "user_id", referencedColumnName = "id") },
            inverseJoinColumns = { @JoinColumn(name = "addr_id", referencedColumnName = "id") })
    private Set<UserAddressEntity> userAddresses = new HashSet<UserAddressEntity>();

    public UserEntity() {
    }

    public void setUserName(String uname) {
        userName = uname;
    }

    public String getUserName() {
        return userName;
    }

    public void setUserAttributes(Set<UserAttributeEntity> attrs) {
        userAttributes = attrs;
    }

    public Set<UserAttributeEntity> getUserAttributes() {
        return userAttributes;
    }

    public void setUserAddresses(Set<UserAddressEntity> addrs) {
        userAddresses = addrs;
    }

    public Set<UserAddressEntity> getUserAddresses() {
        return userAddresses;
    }

    public boolean equals(Object other) {
        return super.equals(other);
    }

    public int hashCode() {
        return super.hashCode();
    }

}