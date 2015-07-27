package it.infn.security.saml.datasource.jpa;

import java.io.Serializable;

import javax.persistence.Column;
import javax.persistence.Embeddable;

@Embeddable
public class AttributeEntityId
    implements Serializable {

    public static final long serialVersionUID = 1437999400;

    @Column(name = "attr_key", nullable = false)
    private String key;

    @Column(name = "attr_content", nullable = false)
    private String content;

    public AttributeEntityId() {
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

    public boolean equals(Object other) {
        if (other == null || !(other instanceof AttributeEntityId)) {
            return false;
        }

        AttributeEntityId tmpAttr = (AttributeEntityId) other;
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