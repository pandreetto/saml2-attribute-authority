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

    private String uName;

    private String gName;

    private String fName;

    private String mName;

    private String nName;

    private String dName;

    private String hPrefix;

    private String hSuffix;

    private String title;

    private String position;

    private String url;

    private String lang;

    private String locale;

    private String timezone;

    private String pwd;

    private List<AttrValueTuple> emails;

    private List<AttrValueTuple> phones;

    private List<AttrValueTuple> ims;

    private List<AttrValueTuple> photos;

    private List<AttrValueTuple> roles;

    private List<AttrValueTuple> entitles;

    private List<AttrValueTuple> certificates;

    private List<AddrValueTuple> addresses;

    private List<String> dGroups;

    private List<String> uGroups;

    public SCIM2User() {
        super();

        uName = null;
        gName = null;
        fName = null;
        mName = null;
        nName = null;
        dName = null;
        hPrefix = null;
        hSuffix = null;
        title = null;
        position = null;
        url = null;
        lang = null;
        locale = null;
        timezone = null;
        pwd = null;
        emails = new ArrayList<AttrValueTuple>();
        phones = new ArrayList<AttrValueTuple>();
        ims = new ArrayList<AttrValueTuple>();
        photos = new ArrayList<AttrValueTuple>();
        roles = new ArrayList<AttrValueTuple>();
        entitles = new ArrayList<AttrValueTuple>();
        certificates = new ArrayList<AttrValueTuple>();
        addresses = new ArrayList<AddrValueTuple>();

        dGroups = null;
        uGroups = null;

    }

    public void setName(String name)
        throws DataSourceException {
        if (uName != null) {
            throw new DataSourceException("Cannot change user name");
        }
        uName = name;
    }

    public String getName()
        throws DataSourceException {
        return uName;
    }

    public void setLinkedResources(List<String> listIds)
        throws DataSourceException {
        dGroups = listIds;
    }

    public List<String> getLinkedResources()
        throws DataSourceException {
        return dGroups;
    }

    public void setAncestorResources(List<String> listIds)
        throws DataSourceException {
        uGroups = listIds;
    }

    public List<String> getAncestorResources()
        throws DataSourceException {
        return uGroups;
    }

    public void setUserGivenName(String gName)
        throws DataSourceException {
        if (this.gName != null) {
            resourceUpdated();
        }
        this.gName = gName;
    }

    public String getUserGivenName()
        throws DataSourceException {
        return gName;
    }

    public void setUserFamilyName(String fName)
        throws DataSourceException {
        if (this.fName != null) {
            resourceUpdated();
        }
        this.fName = fName;
    }

    public String getUserFamilyName()
        throws DataSourceException {
        return fName;
    }

    public void setUserMiddleName(String mName)
        throws DataSourceException {
        if (this.mName != null) {
            resourceUpdated();
        }
        this.mName = mName;
    }

    public String getUserMiddleName()
        throws DataSourceException {
        return mName;
    }

    public void setUserDisplayName(String dName)
        throws DataSourceException {
        if (this.dName != null) {
            resourceUpdated();
        }
        this.dName = dName;
    }

    public String getUserDisplayName()
        throws DataSourceException {
        return dName;
    }

    public void setUserHonorPrefix(String prefix)
        throws DataSourceException {
        if (hPrefix != null) {
            resourceUpdated();
        }
        hPrefix = prefix;
    }

    public String getUserHonorPrefix()
        throws DataSourceException {
        return hPrefix;
    }

    public void setUserHonorSuffix(String suffix)
        throws DataSourceException {
        if (hSuffix != null) {
            resourceUpdated();
        }
        hSuffix = suffix;
    }

    public String getUserHonorSuffix()
        throws DataSourceException {
        return hSuffix;
    }

    public void setUserNickName(String nName)
        throws DataSourceException {
        if (this.nName != null) {
            resourceUpdated();
        }
        this.nName = nName;
    }

    public String getUserNickName()
        throws DataSourceException {
        return nName;
    }

    public void setUserTitle(String title)
        throws DataSourceException {
        if (this.title != null) {
            resourceUpdated();
        }
        this.title = title;
    }

    public String getUserTitle()
        throws DataSourceException {
        return title;
    }

    public void setUserURL(String url)
        throws DataSourceException {
        if (this.url != null) {
            resourceUpdated();
        }
        this.url = url;
    }

    public String getUserURL()
        throws DataSourceException {
        return url;
    }

    public void setUserPosition(String pos)
        throws DataSourceException {
        if (position != null) {
            resourceUpdated();
        }
        position = pos;
    }

    public String getUserPosition()
        throws DataSourceException {
        return position;
    }

    public void setUserLang(String lang)
        throws DataSourceException {
        if (this.lang != null) {
            resourceUpdated();
        }
        this.lang = lang;
    }

    public String getUserLang()
        throws DataSourceException {
        return lang;
    }

    public void setUserLocale(String locale)
        throws DataSourceException {
        if (this.locale != null) {
            resourceUpdated();
        }
        this.locale = locale;
    }

    public String getUserLocale()
        throws DataSourceException {
        return locale;
    }

    public void setUserTimezone(String zone)
        throws DataSourceException {
        if (timezone != null) {
            resourceUpdated();
        }
        timezone = zone;
    }

    public String getUserTimezone()
        throws DataSourceException {
        return timezone;
    }

    public void setUserPwd(String pwd)
        throws DataSourceException {
        if (this.pwd != null) {
            resourceUpdated();
        }
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