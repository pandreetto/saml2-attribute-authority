package it.infn.security.saml.datasource.jpa;

import java.io.Serializable;

import javax.persistence.AttributeOverride;
import javax.persistence.AttributeOverrides;
import javax.persistence.Column;
import javax.persistence.EmbeddedId;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Table;

@Entity
@Table(name = "attributes")
public class AttributeEntity
    implements Serializable {

    public static final long serialVersionUID = 1437726660;

    @EmbeddedId
    @AttributeOverrides({ @AttributeOverride(name = "key", column = @Column(name = "attr_key")),
            @AttributeOverride(name = "content", column = @Column(name = "attr_content")) })
    AttributeEntityId attributeId;

    @Column(name = "attr_descrition", nullable = false)
    private String description;

    public AttributeEntity() {
    }

    public void setAttributeId(AttributeEntityId attrId) {
        attributeId = attrId;
    }

    public AttributeEntityId getAttributeId() {
        return attributeId;
    }

    public void setDescription(String descr) {
        description = descr;
    }

    public String getDescription() {
        return description;
    }

    public boolean equals(Object other) {
        if (other == null || !(other instanceof AttributeEntity)) {
            return false;
        }

        AttributeEntity tmpAttr = (AttributeEntity) other;
        return tmpAttr.attributeId.equals(this.attributeId);
    }

    public int hashCode() {
        return attributeId.hashCode();
    }

}