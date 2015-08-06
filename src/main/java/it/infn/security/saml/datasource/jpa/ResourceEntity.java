package it.infn.security.saml.datasource.jpa;

import java.util.Date;
import java.util.HashSet;
import java.util.Set;

import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Inheritance;
import javax.persistence.InheritanceType;
import javax.persistence.JoinColumn;
import javax.persistence.JoinTable;
import javax.persistence.ManyToMany;
import javax.persistence.OneToMany;
import javax.persistence.Table;

@Entity
@Table(name = "resources")
@Inheritance(strategy = InheritanceType.JOINED)
public class ResourceEntity {

    public enum ResourceType {
        USER, GROUP
    };

    @Id
    private String id;

    @Column(name = "creation_date", nullable = false)
    private Date createDate;

    @Column(name = "last_update", nullable = false)
    private Date modifyDate;

    @Column(name = "version", nullable = false)
    private String version;

    @Column(name = "resource_type", nullable = false)
    private ResourceType type;

    /*
     * TODO check PERSIST; verify missing index on target
     */
    @ManyToMany(cascade = { CascadeType.PERSIST })
    @JoinTable(
            name = "memberof",
            joinColumns = { @JoinColumn(name = "source", referencedColumnName = "id") },
            inverseJoinColumns = { @JoinColumn(name = "target", referencedColumnName = "id") })
    private Set<ResourceEntity> groups = new HashSet<ResourceEntity>();

    @ManyToMany(cascade = { CascadeType.PERSIST })
    @JoinTable(
            name = "bind_attribute",
            joinColumns = { @JoinColumn(name = "resource_id", referencedColumnName = "id") },
            inverseJoinColumns = { @JoinColumn(referencedColumnName = "attr_key"),
                    @JoinColumn(referencedColumnName = "attr_content") })
    private Set<AttributeEntity> attributes = new HashSet<AttributeEntity>();

    /*
     * TODO try to use just a joinColumns insteadof joinTable
     */
    @OneToMany
    @JoinTable(
            name = "bind_ext_id",
            joinColumns = { @JoinColumn(name = "resource_id", referencedColumnName = "id") },
            inverseJoinColumns = { @JoinColumn(name = "ext_id", referencedColumnName = "id") })
    private Set<ExternalIdEntity> externalIds = new HashSet<ExternalIdEntity>();

    public ResourceEntity() {
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getId() {
        return id;
    }

    public void setCreateDate(Date date) {
        createDate = date;
    }

    public Date getCreateDate() {
        return createDate;
    }

    public void setModifyDate(Date date) {
        modifyDate = date;
    }

    public Date getModifyDate() {
        return modifyDate;
    }

    public void setVersion(String ver) {
        version = ver;
    }

    public String getVersion() {
        return version;
    }

    public void setType(ResourceType type) {
        this.type = type;
    }

    public ResourceType getType() {
        return type;
    }

    public void setGroups(Set<ResourceEntity> groups) {
        this.groups = groups;
    }

    public Set<ResourceEntity> getGroups() {
        return groups;
    }

    public void setAttributes(Set<AttributeEntity> attrs) {
        attributes = attrs;
    }

    public Set<AttributeEntity> getAttributes() {
        return attributes;
    }

    public void setExternalIds(Set<ExternalIdEntity> eIds) {
        externalIds = eIds;
    }

    public Set<ExternalIdEntity> getExternalIds() {
        return externalIds;
    }

    public boolean equals(Object other) {
        if (other == null || !(other instanceof ResourceEntity)) {
            return false;
        }

        ResourceEntity tmpRes = (ResourceEntity) other;
        if (tmpRes.id != this.id) {
            return false;
        }

        return true;
    }

    public int hashCode() {
        return id.hashCode();
    }
}