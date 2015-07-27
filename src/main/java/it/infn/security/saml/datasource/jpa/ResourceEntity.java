package it.infn.security.saml.datasource.jpa;

import java.util.HashSet;
import java.util.Set;

import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.Inheritance;
import javax.persistence.InheritanceType;
import javax.persistence.JoinColumn;
import javax.persistence.JoinTable;
import javax.persistence.ManyToMany;
import javax.persistence.Table;

@Entity
@Table(name = "resources")
@Inheritance(strategy = InheritanceType.JOINED)
public class ResourceEntity {

    public enum ResourceType {
        USER, GROUP
    };

    @Id
    @GeneratedValue
    private Long id;

    @Column(name = "resource_type", nullable = false)
    private ResourceType type;

    @ManyToMany(fetch = FetchType.EAGER, cascade = { CascadeType.PERSIST })
    @JoinTable(name = "memberof", 
        joinColumns = { @JoinColumn(name = "source", referencedColumnName = "id") }, 
        inverseJoinColumns = { @JoinColumn(name = "target", referencedColumnName = "id") })
    private Set<ResourceEntity> groups = new HashSet<ResourceEntity>();

    @ManyToMany(cascade = { CascadeType.PERSIST })
    @JoinTable(name = "bind_attribute",
        joinColumns = { @JoinColumn(name = "resource_id", referencedColumnName = "id") },
        inverseJoinColumns = { 
            @JoinColumn(referencedColumnName = "attr_key"), 
            @JoinColumn(referencedColumnName = "attr_content") })
    private Set<AttributeEntity> attributes = new HashSet<AttributeEntity>();

    public ResourceEntity() {
    }

    public void setId(Long id) {
        this.id = id;
    }

    public Long getId() {
        return id;
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