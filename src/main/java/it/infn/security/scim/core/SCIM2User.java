package it.infn.security.scim.core;

import it.infn.security.saml.datasource.AddrValueTuple;
import it.infn.security.saml.datasource.AttrValueTuple;
import it.infn.security.saml.datasource.DataSourceException;
import it.infn.security.saml.datasource.UserResource;

import java.util.ArrayList;
import java.util.List;

public class SCIM2User
    extends SCIM2Resource
    implements UserResource {

    private String uName = null;

    private String gName = null;

    private String fName = null;

    private String mName = null;

    private String nName = null;

    private String dName = null;

    private String hPrefix = null;

    private String hSuffix = null;

    private String title = null;

    private String position = null;

    private String url = null;

    private String lang = null;

    private String locale = null;

    private String timezone = null;

    private String pwd = null;

    private List<AttrValueTuple> emails = new ArrayList<AttrValueTuple>();

    private List<AttrValueTuple> phones = new ArrayList<AttrValueTuple>();

    private List<AttrValueTuple> ims = new ArrayList<AttrValueTuple>();

    private List<AttrValueTuple> photos = new ArrayList<AttrValueTuple>();

    private List<AttrValueTuple> roles = new ArrayList<AttrValueTuple>();

    private List<AttrValueTuple> entitles = new ArrayList<AttrValueTuple>();

    private List<AttrValueTuple> certificates = new ArrayList<AttrValueTuple>();

    private List<AddrValueTuple> addresses = new ArrayList<AddrValueTuple>();

    public void setName(String name)
        throws DataSourceException {
        uName = name;
    }

    public String getName()
        throws DataSourceException {
        return uName;
    }

    public void setLinkedResources(List<String> listIds)
        throws DataSourceException {

    }

    public List<String> getLinkedResources()
        throws DataSourceException {
        return null;
    }

    public void setAncestorResources(List<String> listIds)
        throws DataSourceException {

    }

    public List<String> getAncestorResources()
        throws DataSourceException {
        return null;
    }

    public void setUserGivenName(String gName)
        throws DataSourceException {
        this.gName = gName;
    }

    public String getUserGivenName()
        throws DataSourceException {
        return gName;
    }

    public void setUserFamilyName(String fName)
        throws DataSourceException {
        this.fName = fName;
    }

    public String getUserFamilyName()
        throws DataSourceException {
        return fName;
    }

    public void setUserMiddleName(String mName)
        throws DataSourceException {
        this.mName = mName;
    }

    public String getUserMiddleName()
        throws DataSourceException {
        return mName;
    }

    public void setUserDisplayName(String dName)
        throws DataSourceException {
        this.dName = dName;
    }

    public String getUserDisplayName()
        throws DataSourceException {
        return dName;
    }

    public void setUserHonorPrefix(String prefix)
        throws DataSourceException {
        hPrefix = prefix;
    }

    public String getUserHonorPrefix()
        throws DataSourceException {
        return hPrefix;
    }

    public void setUserHonorSuffix(String suffix)
        throws DataSourceException {
        hSuffix = suffix;
    }

    public String getUserHonorSuffix()
        throws DataSourceException {
        return hSuffix;
    }

    public void setUserNickName(String nName)
        throws DataSourceException {
        this.nName = nName;
    }

    public String getUserNickName()
        throws DataSourceException {
        return nName;
    }

    public void setUserTitle(String title)
        throws DataSourceException {
        this.title = title;
    }

    public String getUserTitle()
        throws DataSourceException {
        return title;
    }

    public void setUserURL(String url)
        throws DataSourceException {
        this.url = url;
    }

    public String getUserURL()
        throws DataSourceException {
        return url;
    }

    public void setUserPosition(String pos)
        throws DataSourceException {
        position = pos;
    }

    public String getUserPosition()
        throws DataSourceException {
        return position;
    }

    public void setUserLang(String lang)
        throws DataSourceException {
        this.lang = lang;
    }

    public String getUserLang()
        throws DataSourceException {
        return lang;
    }

    public void setUserLocale(String locale)
        throws DataSourceException {
        this.locale = locale;
    }

    public String getUserLocale()
        throws DataSourceException {
        return locale;
    }

    public void setUserTimezone(String zone)
        throws DataSourceException {
        timezone = zone;
    }

    public String getUserTimezone()
        throws DataSourceException {
        return timezone;
    }

    public void setUserPwd(String pwd)
        throws DataSourceException {
        this.pwd = pwd;
    }

    public String getUserPwd()
        throws DataSourceException {
        return pwd;
    }

    public void addUserEmail(String email, String type)
        throws DataSourceException {
        emails.add(new AttrValueTuple(email, type));
    }

    public List<AttrValueTuple> getUserEmails()
        throws DataSourceException {
        return emails;
    }

    public void addUserPhone(String phone, String type)
        throws DataSourceException {
        phones.add(new AttrValueTuple(phone, type));
    }

    public List<AttrValueTuple> getUserPhones()
        throws DataSourceException {
        return phones;
    }

    public void addUserIM(String im, String type)
        throws DataSourceException {
        ims.add(new AttrValueTuple(im, type));
    }

    public List<AttrValueTuple> getUserIMs()
        throws DataSourceException {
        return ims;
    }

    public void addUserPhoto(String photo, String type)
        throws DataSourceException {
        photos.add(new AttrValueTuple(photo, type));
    }

    public List<AttrValueTuple> getUserPhotos()
        throws DataSourceException {
        return photos;
    }

    public void addUserRole(String role, String type)
        throws DataSourceException {
        roles.add(new AttrValueTuple(role, type));
    }

    public List<AttrValueTuple> getUserRoles()
        throws DataSourceException {
        return roles;
    }

    public void addUserEntitle(String entitle, String type)
        throws DataSourceException {
        entitles.add(new AttrValueTuple(entitle, type));
    }

    public List<AttrValueTuple> getUserEntitles()
        throws DataSourceException {
        return entitles;
    }

    public void addUserCertificate(String cert, String type)
        throws DataSourceException {
        certificates.add(new AttrValueTuple(cert, type));
    }

    public List<AttrValueTuple> getUserCertificates()
        throws DataSourceException {
        return certificates;
    }

    public void addUserAddress(String street, String locality, String region, String code, String country, String type)
        throws DataSourceException {
        addresses.add(new AddrValueTuple(street, locality, region, code, country, type));
    }

    public void addUserAddress(AddrValueTuple tuple)
        throws DataSourceException {
        addresses.add(tuple);
    }

    public List<AddrValueTuple> getUserAddresses()
        throws DataSourceException {
        return addresses;
    }

}