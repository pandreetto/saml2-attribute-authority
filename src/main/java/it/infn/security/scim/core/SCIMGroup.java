package it.infn.security.scim.core;

import it.infn.security.saml.datasource.DataSourceException;
import it.infn.security.saml.datasource.GroupResource;
import it.infn.security.saml.ocp.SPIDAttributeName;
import it.infn.security.saml.ocp.SPIDAttributeValue;
import it.infn.security.saml.ocp.SPIDSchemaManager;
import it.infn.security.saml.schema.AttributeEntry;
import it.infn.security.saml.schema.AttributeValueInterface;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.List;

import org.wso2.charon.core.attributes.Attribute;
import org.wso2.charon.core.attributes.ComplexAttribute;
import org.wso2.charon.core.attributes.MultiValuedAttribute;
import org.wso2.charon.core.attributes.SimpleAttribute;
import org.wso2.charon.core.exceptions.AbstractCharonException;
import org.wso2.charon.core.objects.Group;

public class SCIMGroup
    extends Group
    implements GroupResource {

    public static final long serialVersionUID = 1463734695;

    public SCIMGroup() {
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
            super.setDisplayName(name);
        } catch (AbstractCharonException chEx) {
            throw new DataSourceException(chEx.getMessage(), chEx);
        }
    }

    public String getName()
        throws DataSourceException {
        try {
            return super.getDisplayName();
        } catch (AbstractCharonException chEx) {
            throw new DataSourceException(chEx.getMessage(), chEx);
        }
    }

    public void setUserMembers(List<String> idLists)
        throws DataSourceException {
        try {
            for (String id : idLists) {
                super.setUserMember(id);
            }
        } catch (AbstractCharonException chEx) {
            throw new DataSourceException(chEx.getMessage(), chEx);
        }
    }

    public List<String> getUMembers()
        throws DataSourceException {
        try {
            return super.getUserMembers();
        } catch (AbstractCharonException chEx) {
            throw new DataSourceException(chEx.getMessage(), chEx);
        }
    }

    public void setGroupMembers(List<String> idLists)
        throws DataSourceException {
        try {
            for (String id : idLists) {
                super.setGroupMember(id);
            }
        } catch (AbstractCharonException chEx) {
            throw new DataSourceException(chEx.getMessage(), chEx);
        }
    }

    public List<String> getGMembers()
        throws DataSourceException {
        try {
            return super.getGroupMembers();
        } catch (AbstractCharonException chEx) {
            throw new DataSourceException(chEx.getMessage(), chEx);
        }
    }

    public List<String> getAllMembers()
        throws DataSourceException {
        try {
            return super.getMembers();
        } catch (AbstractCharonException chEx) {
            throw new DataSourceException(chEx.getMessage(), chEx);
        }
    }

    /*
     * TODO move into an OCP package
     */
    public Collection<AttributeEntry> getExtendedAttributes()
        throws DataSourceException {

        if (!super.isAttributeExist(SPIDSchemaManager.ROOT_ATTR_ID)) {
            return new ArrayList<AttributeEntry>();
        }

        HashMap<String, AttributeEntry> attrTable = new HashMap<String, AttributeEntry>();

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

                String tmpName = nameAttr.getStringValue();
                String tmpValue = cntAttr.getStringValue();
                AttributeEntry tmpEntry = null;
                if (attrTable.containsKey(tmpName)) {
                    tmpEntry = attrTable.get(tmpName);
                } else {
                    tmpEntry = new AttributeEntry(new SPIDAttributeName(tmpName, ""));
                    attrTable.put(tmpName, tmpEntry);
                }
                tmpEntry.add(new SPIDAttributeValue(tmpValue, ""));

            }

        } catch (AbstractCharonException chEx) {
            throw new DataSourceException(chEx.getMessage(), chEx);
        }

        return attrTable.values();
    }

    public void setExtendedAttributes(Collection<AttributeEntry> xAttributes)
        throws DataSourceException {

        if (xAttributes == null || xAttributes.size() == 0)
            return;

        try {
            MultiValuedAttribute rootAttr = new MultiValuedAttribute(SPIDSchemaManager.ROOT_ATTR_ID);
            List<Attribute> allSubAttrs = new ArrayList<Attribute>();

            for (AttributeEntry aEntry : xAttributes) {
                for (AttributeValueInterface xValue : aEntry) {
                    SimpleAttribute nameAttr = new SimpleAttribute(SPIDSchemaManager.NAME_ATTR_ID);
                    nameAttr.setValue(aEntry.getName().getNameId());
                    SimpleAttribute cntAttr = new SimpleAttribute(SPIDSchemaManager.VALUE_ATTR_ID);
                    cntAttr.setValue(xValue.getValue());
                    ComplexAttribute cplxAttr = new ComplexAttribute();
                    cplxAttr.setSubAttribute(nameAttr);
                    cplxAttr.setSubAttribute(cntAttr);
                    allSubAttrs.add(cplxAttr);
                }
            }

            rootAttr.setValuesAsSubAttributes(allSubAttrs);
            super.setAttribute(rootAttr);

        } catch (AbstractCharonException chEx) {
            throw new DataSourceException(chEx.getMessage(), chEx);
        }
    }

}