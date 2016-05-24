package it.infn.security.saml.datasource;

public class AddrValueTuple {

    private String street;

    private String locality;

    private String region;

    private String code;

    private String country;

    private String type;

    public AddrValueTuple(String street, String locality, String region, String code, String country, String type) {
        this.street = street;
        this.locality = locality;
        this.region = region;
        this.code = code;
        this.country = country;
        this.type = type;
    }

    public String getStreet() {
        return street;
    }

    public String getLocality() {
        return locality;
    }

    public String getRegion() {
        return region;
    }

    public String getCode() {
        return code;
    }

    public String getCounty() {
        return country;
    }

    public String getType() {
        return type;
    }

}