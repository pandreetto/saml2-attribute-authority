package it.infn.security.saml.datasource.jpa;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.Table;

@Entity
@Table(name = "external_id")
public class ExternalIdEntity {

    @Id
    @GeneratedValue
    private Long id;

    @ManyToOne
    @JoinColumn(name = "owner_id", nullable = false)
    private ResourceEntity owner;

    @Column(nullable = false)
    private String tenant;

    @Column(name = "external_id", nullable = false)
    private String extId;

    public void setId(Long id) {
        this.id = id;
    }

    public Long getId() {
        return id;
    }

    public void setOwner(ResourceEntity res) {
        owner = res;
    }

    public ResourceEntity getOwner() {
        return owner;
    }

    public void setTenant(String tenant) {
        this.tenant = tenant;
    }

    public String getTenant() {
        return tenant;
    }

    public void setExtId(String eId) {
        extId = eId;
    }

    public String getExtId() {
        return extId;
    }
}