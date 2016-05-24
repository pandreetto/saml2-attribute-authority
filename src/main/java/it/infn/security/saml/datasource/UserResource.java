package it.infn.security.saml.datasource;

import java.util.List;

public interface UserResource
    extends Resource {

    public void setName(String name)
        throws DataSourceException;

    public String getName()
        throws DataSourceException;

    public void setLinkedResources(List<String> listIds)
        throws DataSourceException;

    public void setAncestorResources(List<String> listIds)
        throws DataSourceException;

    public void setUserGivenName(String gName)
        throws DataSourceException;

    public void setUserFamilyName(String fName)
        throws DataSourceException;

    public void setUserMiddleName(String mName)
        throws DataSourceException;

    public void setUserDisplayName(String dName)
        throws DataSourceException;

    public void setUserHonorPrefix(String prefix)
        throws DataSourceException;

    public void setUserHonorSuffix(String suffix)
        throws DataSourceException;

    public void setUserNickName(String nName)
        throws DataSourceException;

    public void setUserTitle(String title)
        throws DataSourceException;

    public void setUserURL(String url)
        throws DataSourceException;

    public void setUserPosition(String pos)
        throws DataSourceException;

    public void setUserLang(String lang)
        throws DataSourceException;

    public void setUserLocale(String locale)
        throws DataSourceException;

    public void setUserTimezone(String zone)
        throws DataSourceException;

    public void setUserPwd(String pwd)
        throws DataSourceException;

    public void addUserEmail(String email, String type)
        throws DataSourceException;

    public void addUserPhone(String phone, String type)
        throws DataSourceException;

    public void addUserIM(String im, String type)
        throws DataSourceException;

    public void addUserPhoto(String photo, String type)
        throws DataSourceException;

    public void addUserRole(String role, String type)
        throws DataSourceException;

    public void addUserEntitle(String entitle, String type)
        throws DataSourceException;

    public void addUserCertificate(String cert, String type)
        throws DataSourceException;

    public void addUserAddress(String street, String locality, String region, String code, String country, String type)
        throws DataSourceException;

}