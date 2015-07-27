package it.infn.security.saml.datasource.jpa;

import java.io.Serializable;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Table;

@Entity
@Table(name = "attributes")
public class AttributeEntity
    implements Serializable {

    public static final long serialVersionUID = 1437726660;

    @Id
    @Column(name = "attr_key", nullable = false)
    private String key;

    @Id
    @Column(name = "attr_content", nullable = false)
    private String content;

    @Column(name = "attr_descrition", nullable = false)
    private String description;

    public AttributeEntity() {
    }

    public void setKey(String key) {
        this.key = key;
    }

    public String getKey() {
        return key;
    }

    public void setContent(String content) {
        this.content = content;
    }

    public String getContent() {
        return content;
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
        if (tmpAttr.key != this.key || tmpAttr.content != this.content) {
            return false;
        }

        return true;
    }

    public int hashCode() {
        // Same algorithm as in java.util.List#hashCode()
        int result = 1;
        result = 31 * result + (key == null ? 0 : key.hashCode());
        result = 31 * result + (content == null ? 0 : content.hashCode());
        return result;
    }

}