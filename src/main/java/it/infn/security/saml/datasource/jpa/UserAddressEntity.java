package it.infn.security.saml.datasource.jpa;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.Table;

@Entity
@Table(name = "user_address")
public class UserAddressEntity {

    @Id
    @GeneratedValue
    private Long id;

    @ManyToOne
    @JoinColumn(name = "user_id", nullable = false)
    private UserEntity user;

    @Column(name = "street")
    private String street;

    @Column(name = "locality")
    private String locality;

    @Column(name = "region")
    private String region;

    @Column(name = "zip")
    private String postalCode;

    @Column(name = "country")
    private String country;

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

    public void setStreet(String st) {
        street = st;
    }

    public String getStreet() {
        return street;
    }

    public void setLocality(String loc) {
        locality = loc;
    }

    public String getLocality() {
        return locality;
    }

    public void setReqion(String reg) {
        region = reg;
    }

    public String getRegion() {
        return region;
    }

    public void setPostalCode(String zip) {
        postalCode = zip;
    }

    public String getPostalCode() {
        return postalCode;
    }

    public void setCountry(String ct) {
        country = ct;
    }

    public String getCountry() {
        return country;
    }

}