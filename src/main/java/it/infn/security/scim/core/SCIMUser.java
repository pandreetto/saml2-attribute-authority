package it.infn.security.scim.core;

import it.infn.security.saml.datasource.AddrValueTuple;
import it.infn.security.saml.datasource.AttrValueTuple;
import it.infn.security.saml.datasource.DataSourceException;
import it.infn.security.saml.datasource.UserResource;
import it.infn.security.saml.ocp.SPIDSchemaManager;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Map;

import org.wso2.charon.core.attributes.Attribute;
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

    private MultiValuedAttribute emails = null;

    private MultiValuedAttribute phones = null;

    private MultiValuedAttribute ims = null;

    private MultiValuedAttribute photos = null;

    private MultiValuedAttribute roles = null;

    private MultiValuedAttribute entitles = null;

    private MultiValuedAttribute certs = null;

    private MultiValuedAttribute addresses = null;

    public SCIMUser() {
        super();
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

    public String getUserGivenName()
        throws DataSourceException {
        try {
            return super.getGivenName();
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

    public String getUserFamilyName()
        throws DataSourceException {
        try {
            return super.getFamilyName();
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

    public String getUserMiddleName()
        throws DataSourceException {
        try {
            return super.getMiddleName();
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

    public String getUserDisplayName()
        throws DataSourceException {
        try {
            return super.getDisplayName();
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

    public String getUserHonorPrefix()
        throws DataSourceException {
        try {
            return super.getHonorificPrefix();
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

    public String getUserHonorSuffix()
        throws DataSourceException {
        try {
            return super.getHonorificSuffix();
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

    public String getUserNickName()
        throws DataSourceException {
        try {
            return super.getNickName();
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

    public String getUserTitle()
        throws DataSourceException {
        try {
            return super.getTitle();
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

    public String getUserURL()
        throws DataSourceException {
        try {
            return super.getProfileURL();
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

    public String getUserPosition()
        throws DataSourceException {
        try {
            return super.getUserType();
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

    public String getUserLang()
        throws DataSourceException {
        try {
            return super.getPreferredLanguage();
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

    public String getUserLocale()
        throws DataSourceException {
        try {
            return super.getLocale();
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

    public String getUserTimezone()
        throws DataSourceException {
        try {
            return super.getTimeZone();
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

    public String getUserPwd()
        throws DataSourceException {
        try {
            return super.getPassword();
        } catch (AbstractCharonException chEx) {
            throw new DataSourceException(chEx.getMessage(), chEx);
        }
    }

    public void addUserEmail(String email, String type)
        throws DataSourceException {
        try {
            if (emails == null)
                emails = getInnerAttr(SCIMConstants.UserSchemaConstants.EMAILS);
            emails.getValuesAsSubAttributes().add(buildComplexAttr(email, type));
        } catch (AbstractCharonException chEx) {
            throw new DataSourceException(chEx.getMessage(), chEx);
        }
    }

    public List<AttrValueTuple> getUserEmails()
        throws DataSourceException {
        try {
            if (emails == null)
                emails = getInnerAttr(SCIMConstants.UserSchemaConstants.EMAILS);
            return buildAttrTuple(emails);
        } catch (AbstractCharonException chEx) {
            throw new DataSourceException(chEx.getMessage(), chEx);
        }
    }

    public void addUserPhone(String phone, String type)
        throws DataSourceException {
        try {
            if (phones == null)
                phones = getInnerAttr(SCIMConstants.UserSchemaConstants.PHONE_NUMBERS);
            phones.getValuesAsSubAttributes().add(buildComplexAttr(phone, type));
        } catch (AbstractCharonException chEx) {
            throw new DataSourceException(chEx.getMessage(), chEx);
        }
    }

    public List<AttrValueTuple> getUserPhones()
        throws DataSourceException {
        try {
            if (phones == null)
                phones = getInnerAttr(SCIMConstants.UserSchemaConstants.PHONE_NUMBERS);
            return buildAttrTuple(phones);
        } catch (AbstractCharonException chEx) {
            throw new DataSourceException(chEx.getMessage(), chEx);
        }
    }

    public void addUserIM(String im, String type)
        throws DataSourceException {
        try {
            if (ims == null)
                ims = getInnerAttr(SCIMConstants.UserSchemaConstants.IMS);
            ims.getValuesAsSubAttributes().add(buildComplexAttr(im, type));
        } catch (AbstractCharonException chEx) {
            throw new DataSourceException(chEx.getMessage(), chEx);
        }
    }

    public List<AttrValueTuple> getUserIMs()
        throws DataSourceException {
        try {
            if (ims == null)
                ims = getInnerAttr(SCIMConstants.UserSchemaConstants.IMS);
            return buildAttrTuple(ims);
        } catch (AbstractCharonException chEx) {
            throw new DataSourceException(chEx.getMessage(), chEx);
        }
    }

    public void addUserPhoto(String photo, String type)
        throws DataSourceException {
        try {
            if (photos == null)
                photos = getInnerAttr(SCIMConstants.UserSchemaConstants.PHOTOS);
            photos.getValuesAsSubAttributes().add(buildComplexAttr(photo, type));
        } catch (AbstractCharonException chEx) {
            throw new DataSourceException(chEx.getMessage(), chEx);
        }
    }

    public List<AttrValueTuple> getUserPhotos()
        throws DataSourceException {
        try {
            if (photos == null)
                photos = getInnerAttr(SCIMConstants.UserSchemaConstants.PHOTOS);
            return buildAttrTuple(photos);
        } catch (AbstractCharonException chEx) {
            throw new DataSourceException(chEx.getMessage(), chEx);
        }
    }

    public void addUserRole(String role, String type)
        throws DataSourceException {
        try {
            if (roles == null)
                roles = getInnerAttr(SCIMConstants.UserSchemaConstants.ROLES);
            roles.getValuesAsSubAttributes().add(buildComplexAttr(role, type));
        } catch (AbstractCharonException chEx) {
            throw new DataSourceException(chEx.getMessage(), chEx);
        }
    }

    public List<AttrValueTuple> getUserRoles()
        throws DataSourceException {
        try {
            if (roles == null)
                roles = getInnerAttr(SCIMConstants.UserSchemaConstants.ROLES);
            return buildAttrTuple(roles);
        } catch (AbstractCharonException chEx) {
            throw new DataSourceException(chEx.getMessage(), chEx);
        }
    }

    public void addUserEntitle(String entitle, String type)
        throws DataSourceException {
        try {
            if (entitles == null)
                entitles = getInnerAttr(SCIMConstants.UserSchemaConstants.ENTITLEMENTS);
            entitles.getValuesAsSubAttributes().add(buildComplexAttr(entitle, type));
        } catch (AbstractCharonException chEx) {
            throw new DataSourceException(chEx.getMessage(), chEx);
        }
    }

    public List<AttrValueTuple> getUserEntitles()
        throws DataSourceException {
        try {
            if (entitles == null)
                entitles = getInnerAttr(SCIMConstants.UserSchemaConstants.ENTITLEMENTS);
            return buildAttrTuple(entitles);
        } catch (AbstractCharonException chEx) {
            throw new DataSourceException(chEx.getMessage(), chEx);
        }
    }

    public void addUserCertificate(String cert, String type)
        throws DataSourceException {
        try {
            if (certs == null)
                certs = getInnerAttr(SCIMConstants.UserSchemaConstants.X509CERTIFICATES);
            certs.getValuesAsSubAttributes().add(buildComplexAttr(cert, type));
        } catch (AbstractCharonException chEx) {
            throw new DataSourceException(chEx.getMessage(), chEx);
        }
    }

    public List<AttrValueTuple> getUserCertificates()
        throws DataSourceException {
        try {
            if (certs == null)
                certs = getInnerAttr(SCIMConstants.UserSchemaConstants.X509CERTIFICATES);
            return buildAttrTuple(certs);
        } catch (AbstractCharonException chEx) {
            throw new DataSourceException(chEx.getMessage(), chEx);
        }
    }

    public void addUserAddress(String street, String locality, String region, String code, String country, String type)
        throws DataSourceException {
        try {
            if (addresses == null)
                addresses = getInnerAttr(SCIMConstants.UserSchemaConstants.ADDRESSES);
            addresses.getValuesAsSubAttributes().add(buildAddressAttr(street, locality, region, code, country, type));
        } catch (AbstractCharonException chEx) {
            throw new DataSourceException(chEx.getMessage(), chEx);
        }
    }

    public List<AddrValueTuple> getUserAddresses()
        throws DataSourceException {
        if (addresses == null)
            addresses = getInnerAttr(SCIMConstants.UserSchemaConstants.ADDRESSES);
        List<AddrValueTuple> result = new ArrayList<AddrValueTuple>();
        List<Map<String, Object>> addressValues = addresses.getComplexValues();
        if (addressValues == null)
            return result;
        for (Map<String, Object> addrItem : addressValues) {
            String st = addrItem.get(SCIMConstants.UserSchemaConstants.STREET_ADDRESS).toString();
            String loc = addrItem.get(SCIMConstants.UserSchemaConstants.LOCALITY).toString();
            String reg = addrItem.get(SCIMConstants.UserSchemaConstants.REGION).toString();
            String code = addrItem.get(SCIMConstants.UserSchemaConstants.POSTAL_CODE).toString();
            String cou = addrItem.get(SCIMConstants.UserSchemaConstants.COUNTRY).toString();
            String type = addrItem.get(SCIMConstants.CommonSchemaConstants.TYPE).toString();
            result.add(new AddrValueTuple(st, loc, reg, code, cou, type));
        }
        return result;
    }

    /*
     * TODO move into an OCP package
     */
    public Collection<String[]> getSPIDAttributes()
        throws DataSourceException {

        ArrayList<String[]> result = new ArrayList<String[]>();
        if (!super.isAttributeExist(SPIDSchemaManager.ROOT_ATTR_ID)) {
            return result;
        }

        try {

            Attribute extAttribute = super.getAttribute(SPIDSchemaManager.ROOT_ATTR_ID);
            List<Attribute> allSubAttrs = ((MultiValuedAttribute) extAttribute).getValuesAsSubAttributes();
            for (Attribute subAttr : allSubAttrs) {
                ComplexAttribute cplxAttr = (ComplexAttribute) subAttr;

                SimpleAttribute nameAttr = (SimpleAttribute) cplxAttr.getSubAttribute(SPIDSchemaManager.NAME_ATTR_ID);
                if (nameAttr == null) {
                    throw new DataSourceException("Missing attribute " + SPIDSchemaManager.NAME_ATTR_ID);
                }
                SimpleAttribute cntAttr = (SimpleAttribute) cplxAttr.getSubAttribute(SPIDSchemaManager.VALUE_ATTR_ID);
                if (cntAttr == null) {
                    throw new DataSourceException("Missing attribute " + SPIDSchemaManager.VALUE_ATTR_ID);
                }

                result.add(new String[] { nameAttr.getStringValue(), cntAttr.getStringValue() });

            }

        } catch (AbstractCharonException chEx) {
            throw new DataSourceException(chEx.getMessage(), chEx);
        }

        return result;
    }

    private MultiValuedAttribute getInnerAttr(String attName) {

        if (super.isAttributeExist(attName)) {
            return (MultiValuedAttribute) super.getAttributeList().get(attName);
        }

        MultiValuedAttribute tmpAttr = new MultiValuedAttribute(attName);
        super.setAttribute(tmpAttr);

        return tmpAttr;
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

    private List<AttrValueTuple> buildAttrTuple(MultiValuedAttribute mAttr)
        throws CharonException {

        List<AttrValueTuple> result = new ArrayList<AttrValueTuple>();

        if (mAttr.getValuesAsStrings() != null && mAttr.getValuesAsStrings().size() != 0) {
            for (String tmpValue : mAttr.getValuesAsStrings()) {
                result.add(new AttrValueTuple(tmpValue, null));
            }
            return result;
        }

        List<Attribute> subAttributes = mAttr.getValuesAsSubAttributes();
        if (subAttributes == null || subAttributes.size() == 0) {
            return result;
        }

        for (Attribute subAttribute : subAttributes) {
            if (subAttribute instanceof SimpleAttribute) {

                SimpleAttribute valueAttribute = (SimpleAttribute) subAttribute;
                result.add(new AttrValueTuple((String) valueAttribute.getValue(), null));

            } else {

                ComplexAttribute cplxAttr = (ComplexAttribute) subAttribute;
                SimpleAttribute valueAttribute = (SimpleAttribute) (cplxAttr
                        .getSubAttribute(SCIMConstants.CommonSchemaConstants.VALUE));
                String resValue = (String) valueAttribute.getValue();

                SimpleAttribute typeAttribute = (SimpleAttribute) (cplxAttr
                        .getSubAttribute(SCIMConstants.CommonSchemaConstants.TYPE));
                String resType = typeAttribute != null ? (String) typeAttribute.getValue() : null;
                result.add(new AttrValueTuple(resValue, resType));

            }
        }

        return result;

    }
}