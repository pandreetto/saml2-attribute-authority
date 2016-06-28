package it.infn.security.scim.core;

import it.infn.security.saml.datasource.AddrValueTuple;
import it.infn.security.saml.datasource.AttrValueTuple;
import it.infn.security.saml.datasource.DataSourceException;
import it.infn.security.saml.datasource.UserResource;

import java.util.List;

public class SCIM2User
    extends SCIM2Resource
    implements UserResource {

    protected String uName = null;

    protected String gName = null;

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

    }

    public String getUserGivenName()
        throws DataSourceException {
        return null;
    }

    public void setUserFamilyName(String fName)
        throws DataSourceException {

    }

    public String getUserFamilyName()
        throws DataSourceException {
        return null;
    }

    public void setUserMiddleName(String mName)
        throws DataSourceException {

    }

    public String getUserMiddleName()
        throws DataSourceException {
        return null;
    }

    public void setUserDisplayName(String dName)
        throws DataSourceException {

    }

    public String getUserDisplayName()
        throws DataSourceException {
        return null;
    }

    public void setUserHonorPrefix(String prefix)
        throws DataSourceException {

    }

    public String getUserHonorPrefix()
        throws DataSourceException {
        return null;
    }

    public void setUserHonorSuffix(String suffix)
        throws DataSourceException {

    }

    public String getUserHonorSuffix()
        throws DataSourceException {
        return null;
    }

    public void setUserNickName(String nName)
        throws DataSourceException {

    }

    public String getUserNickName()
        throws DataSourceException {
        return null;
    }

    public void setUserTitle(String title)
        throws DataSourceException {

    }

    public String getUserTitle()
        throws DataSourceException {
        return null;
    }

    public void setUserURL(String url)
        throws DataSourceException {

    }

    public String getUserURL()
        throws DataSourceException {
        return null;
    }

    public void setUserPosition(String pos)
        throws DataSourceException {

    }

    public String getUserPosition()
        throws DataSourceException {
        return null;
    }

    public void setUserLang(String lang)
        throws DataSourceException {

    }

    public String getUserLang()
        throws DataSourceException {
        return null;
    }

    public void setUserLocale(String locale)
        throws DataSourceException {

    }

    public String getUserLocale()
        throws DataSourceException {
        return null;
    }

    public void setUserTimezone(String zone)
        throws DataSourceException {

    }

    public String getUserTimezone()
        throws DataSourceException {
        return null;
    }

    public void setUserPwd(String pwd)
        throws DataSourceException {

    }

    public String getUserPwd()
        throws DataSourceException {
        return null;
    }

    public void addUserEmail(String email, String type)
        throws DataSourceException {

    }

    public List<AttrValueTuple> getUserEmails()
        throws DataSourceException {
        return null;
    }

    public void addUserPhone(String phone, String type)
        throws DataSourceException {

    }

    public List<AttrValueTuple> getUserPhones()
        throws DataSourceException {
        return null;
    }

    public void addUserIM(String im, String type)
        throws DataSourceException {

    }

    public List<AttrValueTuple> getUserIMs()
        throws DataSourceException {
        return null;
    }

    public void addUserPhoto(String photo, String type)
        throws DataSourceException {

    }

    public List<AttrValueTuple> getUserPhotos()
        throws DataSourceException {
        return null;
    }

    public void addUserRole(String role, String type)
        throws DataSourceException {

    }

    public List<AttrValueTuple> getUserRoles()
        throws DataSourceException {
        return null;
    }

    public void addUserEntitle(String entitle, String type)
        throws DataSourceException {

    }

    public List<AttrValueTuple> getUserEntitles()
        throws DataSourceException {
        return null;
    }

    public void addUserCertificate(String cert, String type)
        throws DataSourceException {

    }

    public List<AttrValueTuple> getUserCertificates()
        throws DataSourceException {
        return null;
    }

    public void addUserAddress(String street, String locality, String region, String code, String country, String type)
        throws DataSourceException {

    }

    public List<AddrValueTuple> getUserAddresses()
        throws DataSourceException {
        return null;
    }

}