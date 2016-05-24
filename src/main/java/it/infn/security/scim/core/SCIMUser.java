package it.infn.security.scim.core;

import it.infn.security.saml.datasource.DataSourceException;
import it.infn.security.saml.datasource.UserResource;

import java.util.Date;
import java.util.List;

import org.wso2.charon.core.attributes.ComplexAttribute;
import org.wso2.charon.core.attributes.MultiValuedAttribute;
import org.wso2.charon.core.attributes.SimpleAttribute;
import org.wso2.charon.core.exceptions.AbstractCharonException;
import org.wso2.charon.core.exceptions.CharonException;
import org.wso2.charon.core.objects.User;
import org.wso2.charon.core.schema.SCIMConstants;

public class SCIMUser
    extends User
    implements UserResource {

    public static final long serialVersionUID = 1463737051;

    private MultiValuedAttribute emails;

    private MultiValuedAttribute phones;

    private MultiValuedAttribute ims;

    private MultiValuedAttribute photos;

    private MultiValuedAttribute roles;

    private MultiValuedAttribute entitles;

    private MultiValuedAttribute certs;

    private MultiValuedAttribute addresses;

    public SCIMUser() {
        super();

        emails = new MultiValuedAttribute(SCIMConstants.UserSchemaConstants.EMAILS);
        phones = new MultiValuedAttribute(SCIMConstants.UserSchemaConstants.PHONE_NUMBERS);
        ims = new MultiValuedAttribute(SCIMConstants.UserSchemaConstants.IMS);
        photos = new MultiValuedAttribute(SCIMConstants.UserSchemaConstants.PHOTOS);
        roles = new MultiValuedAttribute(SCIMConstants.UserSchemaConstants.ROLES);
        entitles = new MultiValuedAttribute(SCIMConstants.UserSchemaConstants.ENTITLEMENTS);
        certs = new MultiValuedAttribute(SCIMConstants.UserSchemaConstants.X509CERTIFICATE);
        addresses = new MultiValuedAttribute(SCIMConstants.UserSchemaConstants.ADDRESSES);

        super.setAttribute(emails);
        super.setAttribute(phones);
        super.setAttribute(ims);
        super.setAttribute(photos);
        super.setAttribute(roles);
        super.setAttribute(entitles);
        super.setAttribute(certs);
        super.setAttribute(addresses);
    }

    public String getResourceId()
        throws DataSourceException {
        try {
            return super.getId();
        } catch (AbstractCharonException chEx) {
            throw new DataSourceException(chEx.getMessage(), chEx);
        }
    }

    public void setResourceId(String id)
        throws DataSourceException {
        try {
            super.setId(id);
        } catch (AbstractCharonException chEx) {
            throw new DataSourceException(chEx.getMessage(), chEx);
        }
    }

    public Date getResourceCreationDate()
        throws DataSourceException {
        try {
            return super.getCreatedDate();
        } catch (AbstractCharonException chEx) {
            throw new DataSourceException(chEx.getMessage(), chEx);
        }
    }

    public void setResourceCreationDate(Date cDate)
        throws DataSourceException {
        try {
            super.setCreatedDate(cDate);
        } catch (AbstractCharonException chEx) {
            throw new DataSourceException(chEx.getMessage(), chEx);
        }
    }

    public Date getResourceChangeDate()
        throws DataSourceException {
        try {
            return super.getLastModified();
        } catch (AbstractCharonException chEx) {
            throw new DataSourceException(chEx.getMessage(), chEx);
        }

    }

    public void setResourceChangeDate(Date cDate)
        throws DataSourceException {
        try {
            super.setLastModified(cDate);
        } catch (AbstractCharonException chEx) {
            throw new DataSourceException(chEx.getMessage(), chEx);
        }
    }

    public String getResourceVersion()
        throws DataSourceException {
        try {
            return super.getVersion();
        } catch (AbstractCharonException chEx) {
            throw new DataSourceException(chEx.getMessage(), chEx);
        }
    }

    public void setResourceVersion(String version)
        throws DataSourceException {
        try {
            super.setVersion(version);
        } catch (AbstractCharonException chEx) {
            throw new DataSourceException(chEx.getMessage(), chEx);
        }
    }

    public String getResourceExtId()
        throws DataSourceException {
        try {
            return super.getExternalId();
        } catch (AbstractCharonException chEx) {
            throw new DataSourceException(chEx.getMessage(), chEx);
        }
    }

    public void setResourceExtId(String id)
        throws DataSourceException {
        try {
            if (id != null)
                super.setExternalId(id);
        } catch (AbstractCharonException chEx) {
            throw new DataSourceException(chEx.getMessage(), chEx);
        }
    }

    public void setName(String name)
        throws DataSourceException {
        try {
            super.setUserName(name);
        } catch (AbstractCharonException chEx) {
            throw new DataSourceException(chEx.getMessage(), chEx);
        }
    }

    public String getName()
        throws DataSourceException {
        try {
            return super.getUserName();
        } catch (AbstractCharonException chEx) {
            throw new DataSourceException(chEx.getMessage(), chEx);
        }
    }

    public void setLinkedResources(List<String> listIds)
        throws DataSourceException {
        try {
            super.setDirectGroups(listIds);
        } catch (AbstractCharonException chEx) {
            throw new DataSourceException(chEx.getMessage(), chEx);
        }
    }

    public void setAncestorResources(List<String> listIds)
        throws DataSourceException {
        try {
            super.setIndirectGroups(listIds);
        } catch (AbstractCharonException chEx) {
            throw new DataSourceException(chEx.getMessage(), chEx);
        }
    }

    public void setUserGivenName(String gName)
        throws DataSourceException {
        try {
            super.setGivenName(gName);
        } catch (AbstractCharonException chEx) {
            throw new DataSourceException(chEx.getMessage(), chEx);
        }
    }

    public void setUserFamilyName(String fName)
        throws DataSourceException {
        try {
            super.setFamilyName(fName);
        } catch (AbstractCharonException chEx) {
            throw new DataSourceException(chEx.getMessage(), chEx);
        }
    }

    public void setUserMiddleName(String mName)
        throws DataSourceException {
        try {
            super.setMiddleName(mName);
        } catch (AbstractCharonException chEx) {
            throw new DataSourceException(chEx.getMessage(), chEx);
        }
    }

    public void setUserDisplayName(String dName)
        throws DataSourceException {
        try {
            super.setDisplayName(dName);
        } catch (AbstractCharonException chEx) {
            throw new DataSourceException(chEx.getMessage(), chEx);
        }
    }

    public void setUserHonorPrefix(String prefix)
        throws DataSourceException {
        try {
            super.setHonorificPrefix(prefix);
        } catch (AbstractCharonException chEx) {
            throw new DataSourceException(chEx.getMessage(), chEx);
        }
    }

    public void setUserHonorSuffix(String suffix)
        throws DataSourceException {
        try {
            super.setHonorificSuffix(suffix);
        } catch (AbstractCharonException chEx) {
            throw new DataSourceException(chEx.getMessage(), chEx);
        }
    }

    public void setUserNickName(String nName)
        throws DataSourceException {
        try {
            super.setNickName(nName);
        } catch (AbstractCharonException chEx) {
            throw new DataSourceException(chEx.getMessage(), chEx);
        }
    }

    public void setUserTitle(String title)
        throws DataSourceException {
        try {
            super.setTitle(title);
        } catch (AbstractCharonException chEx) {
            throw new DataSourceException(chEx.getMessage(), chEx);
        }
    }

    public void setUserURL(String url)
        throws DataSourceException {
        try {
            super.setProfileURL(url);
        } catch (AbstractCharonException chEx) {
            throw new DataSourceException(chEx.getMessage(), chEx);
        }
    }

    public void setUserPosition(String pos)
        throws DataSourceException {
        try {
            super.setUserType(pos);
        } catch (AbstractCharonException chEx) {
            throw new DataSourceException(chEx.getMessage(), chEx);
        }
    }

    public void setUserLang(String lang)
        throws DataSourceException {
        try {
            super.setPreferredLanguage(lang);
        } catch (AbstractCharonException chEx) {
            throw new DataSourceException(chEx.getMessage(), chEx);
        }
    }

    public void setUserLocale(String locale)
        throws DataSourceException {
        try {
            super.setLocale(locale);
        } catch (AbstractCharonException chEx) {
            throw new DataSourceException(chEx.getMessage(), chEx);
        }
    }

    public void setUserTimezone(String zone)
        throws DataSourceException {
        try {
            super.setTimeZone(zone);
        } catch (AbstractCharonException chEx) {
            throw new DataSourceException(chEx.getMessage(), chEx);
        }
    }

    public void setUserPwd(String pwd)
        throws DataSourceException {
        try {
            super.setPassword(pwd);
        } catch (AbstractCharonException chEx) {
            throw new DataSourceException(chEx.getMessage(), chEx);
        }
    }

    public void addUserEmail(String email, String type)
        throws DataSourceException {
        try {
            emails.getValuesAsSubAttributes().add(buildComplexAttr(email, type));
        } catch (AbstractCharonException chEx) {
            throw new DataSourceException(chEx.getMessage(), chEx);
        }
    }

    public void addUserPhone(String phone, String type)
        throws DataSourceException {
        try {
            phones.getValuesAsSubAttributes().add(buildComplexAttr(phone, type));
        } catch (AbstractCharonException chEx) {
            throw new DataSourceException(chEx.getMessage(), chEx);
        }
    }

    public void addUserIM(String im, String type)
        throws DataSourceException {
        try {
            ims.getValuesAsSubAttributes().add(buildComplexAttr(im, type));
        } catch (AbstractCharonException chEx) {
            throw new DataSourceException(chEx.getMessage(), chEx);
        }
    }

    public void addUserPhoto(String photo, String type)
        throws DataSourceException {
        try {
            photos.getValuesAsSubAttributes().add(buildComplexAttr(photo, type));
        } catch (AbstractCharonException chEx) {
            throw new DataSourceException(chEx.getMessage(), chEx);
        }
    }

    public void addUserRole(String role, String type)
        throws DataSourceException {
        try {
            roles.getValuesAsSubAttributes().add(buildComplexAttr(role, type));
        } catch (AbstractCharonException chEx) {
            throw new DataSourceException(chEx.getMessage(), chEx);
        }
    }

    public void addUserEntitle(String entitle, String type)
        throws DataSourceException {
        try {
            entitles.getValuesAsSubAttributes().add(buildComplexAttr(entitle, type));
        } catch (AbstractCharonException chEx) {
            throw new DataSourceException(chEx.getMessage(), chEx);
        }
    }

    public void addUserCertificate(String cert, String type)
        throws DataSourceException {
        try {
            certs.getValuesAsSubAttributes().add(buildComplexAttr(cert, type));
        } catch (AbstractCharonException chEx) {
            throw new DataSourceException(chEx.getMessage(), chEx);
        }
    }

    public void addUserAddress(String street, String locality, String region, String code, String country, String type)
        throws DataSourceException {
        try {
            addresses.getValuesAsSubAttributes().add(buildAddressAttr(street, locality, region, code, country, type));
        } catch (AbstractCharonException chEx) {
            throw new DataSourceException(chEx.getMessage(), chEx);
        }
    }

    private ComplexAttribute buildComplexAttr(String value, String type)
        throws CharonException {
        ComplexAttribute cplxAttr = new ComplexAttribute();
        cplxAttr.setSubAttribute(new SimpleAttribute(SCIMConstants.CommonSchemaConstants.VALUE, value));
        cplxAttr.setSubAttribute(new SimpleAttribute(SCIMConstants.CommonSchemaConstants.TYPE, type));
        return cplxAttr;
    }

    private ComplexAttribute buildAddressAttr(String street, String locality, String region, String code,
            String country, String type)
        throws CharonException {
        ComplexAttribute cplxAttr = new ComplexAttribute();
        cplxAttr.setSubAttribute(new SimpleAttribute(SCIMConstants.UserSchemaConstants.STREET_ADDRESS, street));
        cplxAttr.setSubAttribute(new SimpleAttribute(SCIMConstants.UserSchemaConstants.LOCALITY, locality));
        cplxAttr.setSubAttribute(new SimpleAttribute(SCIMConstants.UserSchemaConstants.REGION, region));
        cplxAttr.setSubAttribute(new SimpleAttribute(SCIMConstants.UserSchemaConstants.POSTAL_CODE, code));
        cplxAttr.setSubAttribute(new SimpleAttribute(SCIMConstants.UserSchemaConstants.COUNTRY, country));
        cplxAttr.setSubAttribute(new SimpleAttribute(SCIMConstants.CommonSchemaConstants.TYPE, type));
        return cplxAttr;
    }
}