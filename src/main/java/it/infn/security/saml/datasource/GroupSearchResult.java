package it.infn.security.saml.datasource;

import java.util.ArrayList;
import java.util.List;

public class GroupSearchResult {

    private int total;

    private int startIdx;

    private int pageSize;

    private List<GroupResource> users;

    public GroupSearchResult() {
        total = 0;
        users = new ArrayList<GroupResource>();
    }

    public GroupSearchResult(int initCap) {
        total = 0;
        users = new ArrayList<GroupResource>(initCap);
    }

    public void add(GroupResource user) {
        users.add(user);
    }

    public List<GroupResource> getGroupList() {
        return users;
    }

    public boolean isEmpty() {
        return users.isEmpty();
    }

    public void setTotalResults(int tot) {
        total = tot;
    }

    public int getTotalResults() {
        return total;
    }

    public void setStartIndex(int st) {
        startIdx = st;
    }

    public int getStartIndex() {
        return startIdx;
    }

    public void setPageSize(int ps) {
        pageSize = ps;
    }

    public int getPageSize() {
        return pageSize;
    }
}