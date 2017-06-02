/**
 * This file is part of the CRISTAL-iSE jOOQ Cluster Storage Module.
 * Copyright (c) 2001-2017 The CRISTAL Consortium. All rights reserved.
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; either version 3 of the License, or (at
 * your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; with out even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA.
 *
 * http://www.fsf.org/licensing/licenses/lgpl.html
 */
package org.cristalise.storage.jooqdb.auth;

import java.util.List;
import java.util.UUID;

import org.cristalise.kernel.common.AccessRightsException;
import org.cristalise.kernel.common.PersistencyException;
import org.cristalise.kernel.lookup.AgentPath;
import org.cristalise.kernel.lookup.ItemPath;
import org.cristalise.kernel.process.Gateway;
import org.cristalise.kernel.process.auth.Authenticator;
import org.cristalise.kernel.property.BuiltInItemProperties;
import org.cristalise.kernel.property.Property;
import org.cristalise.kernel.utils.Logger;
import org.cristalise.storage.jooqdb.JooqHandler;
import org.cristalise.storage.jooqdb.clusterStore.JooqItemPropertyHandler;
import org.cristalise.storage.jooqdb.lookup.JooqItemHandler;
import org.jooq.DSLContext;

public class JooqAuthenticator implements Authenticator {

    DSLContext context = null;

    private JooqItemHandler         items;
    private JooqItemPropertyHandler properties;

    private Argon2Password paswordHasher;

    @Override
    public boolean authenticate(String resource) throws AccessRightsException {
        try {
            context = JooqHandler.connect();

            items      = new JooqItemHandler();
            properties = new JooqItemPropertyHandler();

            items     .createTables(context);
            properties.createTables(context);
            
            paswordHasher = new Argon2Password();

            return true;
        }
        catch (PersistencyException e) {
            throw new AccessRightsException(e.getMessage());
        }
    }

    @Override
    public String authenticate(String agentName, String password, String resource) throws AccessRightsException {
    	
    	if (context == null) {
    		if ( ! authenticate(resource)) {
    			throw new AccessRightsException("Authentication failed, could not initialize Authenticator");
    		}
    	}
    	
        AccessRightsException failedLoginException = new AccessRightsException("Authentication failed, username-password combination does not exist");

        List<UUID> uuids;
        try {
        	uuids = properties.findItems(context, new Property(BuiltInItemProperties.NAME, agentName), new Property(BuiltInItemProperties.TYPE, "Agent"));
        }
        catch (Exception e) {
        	throw failedLoginException;
        }

        if (null == uuids || uuids.size() != 1) {
        	throw failedLoginException;
        }

        AgentPath agent = new AgentPath(new ItemPath(uuids.get(0)), agentName);

        try {
        	if ( ! paswordHasher.checkPassword(items.fetchPassword(context, agent.getUUID()), password.toCharArray()) ) {
        		throw failedLoginException;
        	}
        }
        catch (PersistencyException e) {
        	Logger.error(e);
        	throw failedLoginException;
        }
        catch (Exception e) {
        	throw failedLoginException;
        }

        return Gateway.getAuthManager().generateToken( agent );        
    }

    @Override
    public Object getAuthObject() {
        if (context == null) {
            try {
                authenticate(null);
            }
            catch (AccessRightsException e) {
                Logger.error(e);
            }
        }
        return context;
    }

    @Override
    public void disconnect() {
        context.close();
    }
}
