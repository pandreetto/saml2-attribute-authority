package it.infn.security.saml.iam.impl;

import java.util.ArrayList;
import java.util.HashMap;

public class RoundRobinPDPSelector {

    private ArrayList<String> endpoints;

    private HashMap<String, Long> statusTable;

    private int currEp;

    private long restoreTime;

    public RoundRobinPDPSelector(String pdpListStr, long rtime) {
        endpoints = new ArrayList<String>();
        statusTable = new HashMap<String, Long>();

        if (pdpListStr == null)
            throw new IllegalArgumentException("Wrong PDP list");

        for (String tmps : pdpListStr.split(" ")) {
            tmps = tmps.trim();
            if (tmps.length() > 0) {
                endpoints.add(tmps);
                statusTable.put(tmps, new Long(0));
            }
        }

        if (endpoints.size() == 0)
            throw new IllegalArgumentException("No PDP defined");

        currEp = 0;
        restoreTime = rtime;

    }

    public synchronized String getEndpoint() {
        int savedEp = currEp;

        do {

            String tmpep = endpoints.get(currEp);
            long tmpts = statusTable.get(tmpep).longValue();

            currEp = (currEp + 1) % endpoints.size();

            if (tmpts == 0) {
                return tmpep;
            }

            if (System.currentTimeMillis() - tmpts > restoreTime) {
                statusTable.put(tmpep, new Long(0));
                return tmpep;
            }

        } while (savedEp != currEp);

        return null;
    }

    public synchronized void markDown(String ep) {
        statusTable.put(ep, new Long(System.currentTimeMillis()));
    }

}