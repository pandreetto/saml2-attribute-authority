package it.infn.security.saml.datasource;

public class AddrValueTuple {

    private String street;

    private String locality;

    private String region;

    private String code;

    private String country;

    private String type;

    public AddrValueTuple() {
        street = null;
        locality = null;
        region = null;
        code = null;
        country = null;
        type = null;
    }

    public AddrValueTuple(String street, String locality, String region, String code, String country, String type) {
        this.street = street;
        this.locality = locality;
        this.region = region;
        this.code = code;
        this.country = country;
        this.type = type;
    }

    public void setStreet(String street) {
        this.street = street;
    }

    public String getStreet() {
        return street;
    }

    public void setLocality(String locality) {
        this.locality = locality;
    }

    public String getLocality() {
        return locality;
    }

    public void setRegion(String region) {
        this.region = region;
    }

    public String getRegion() {
        return region;
    }

    public void setCode(String code) {
        this.code = code;
    }

    public String getCode() {
        return code;
    }

    public void setCountry(String country) {
        this.country = country;
    }

    public String getCountry() {
        return country;
    }

    public void setType(String type) {
        this.type = type;
    }

    public String getType() {
        return type;
    }

}