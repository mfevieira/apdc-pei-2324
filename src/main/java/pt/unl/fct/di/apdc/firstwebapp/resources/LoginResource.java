package pt.unl.fct.di.apdc.firstwebapp.resources;

import java.util.Date;
import java.util.LinkedList;
import java.util.List;
import java.util.logging.Logger;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;

import org.apache.commons.codec.digest.DigestUtils;

import com.google.cloud.Timestamp;
import com.google.cloud.datastore.*;
import com.google.cloud.datastore.StructuredQuery.*;
import com.google.gson.Gson;

import pt.unl.fct.di.apdc.firstwebapp.util.AuthToken;
import pt.unl.fct.di.apdc.firstwebapp.util.LoginData;

@Path("/login")
@Produces(MediaType.APPLICATION_JSON + ";charset=utf-8")
public class LoginResource {

	/**
	 * Logger Object
	 */
	private static Logger LOG = Logger.getLogger(LoginResource.class.getName());

	/** 24 hours in milliseconds */
	public static final long HOURS24 = 1000*60*60*24;

	/** The data store to store users in */
	private static final Datastore datastore = DatastoreOptions.getDefaultInstance().getService();
	
	/** The key factory for users */
	private static final KeyFactory userKeyFactory = datastore.newKeyFactory().setKind("User");
	
	/** The converter to JSON */
	private final Gson g = new Gson();

	public LoginResource() {
	} // Nothing to be done here

	@POST
	@Path("/")
	@Consumes(MediaType.APPLICATION_JSON)
	public Response doLogin(LoginData data) {
		LOG.fine("Login attempt by user: " + data.username);
		if (data.username.equals("jleitao") && data.password.equals("password")) {
			AuthToken at = new AuthToken(data.username);
			return Response.ok(g.toJson(at)).build();
		}
		return Response.status(Status.FORBIDDEN).entity("Incorrect username or password.").build();
	}

	@GET
	@Path("/{username}")
	public Response checkUsernameAvailable(@PathParam("username") String username) {
		if (username.equals("jleitao")) {
			return Response.ok().entity(g.toJson(false)).build();
		} else {
			return Response.ok().entity(g.toJson(true)).build();
		}
	}
	
	@POST
	@Path("/v1")
	@Consumes(MediaType.APPLICATION_JSON)
	public Response loginV1(LoginData data) {
		LOG.fine("Login attempt by: " + data.username);
		Key userKey = userKeyFactory.newKey(data.username);
		Transaction txn = datastore.newTransaction();
		try {
			Entity user = txn.get(userKey);
			if ( user == null ) {
				LOG.warning("No such user exists.");
				txn.rollback();
				return Response.status(Status.BAD_REQUEST).entity("No such user exists.").build();
			}
			String hashedPassword = (String) user.getString("password");
			if ( hashedPassword.equals(DigestUtils.sha3_512Hex(data.password)) ) {
				txn.commit();
				AuthToken at = new AuthToken(data.username);
				LOG.info("User '" + data.username + "' logged in successfully.");
				return Response.ok(g.toJson(at)).build();
			} else {
				txn.commit();
				LOG.warning("Wrong password for username: " + data.username);
				return Response.status(Status.UNAUTHORIZED).entity("Wrong password.").build();
			}
		} catch ( Exception e ) {
			txn.rollback();
			LOG.severe(e.getMessage());
			return Response.status(Status.INTERNAL_SERVER_ERROR).build();
		} finally {
			if ( txn.isActive() ) {
				txn.rollback();
				return Response.status(Status.INTERNAL_SERVER_ERROR).build();
			}
		}
	}
	
	
	@POST
	@Path("/v2")
	@Consumes(MediaType.APPLICATION_JSON)
	public Response loginV2(LoginData data, 
			@Context HttpServletRequest request,
			@Context HttpHeaders headers) {
		LOG.fine("Login attempt by: " + data.username);
		Key userKey = userKeyFactory.newKey(data.username);
		Key statsKey = datastore.newKeyFactory()
				.addAncestor(PathElement.of("User", data.username))
				.setKind("LoginStats").newKey("counters");
		Key logKey = datastore.allocateId(
				datastore.newKeyFactory()
				.addAncestor(PathElement.of("User", data.username))
				.setKind("UserLog")
				.newKey());
		Transaction txn = datastore.newTransaction();
		try {
			Entity user = txn.get(userKey);
			if ( user == null ) {
				LOG.warning("No such user exists.");
				txn.rollback();
				return Response.status(Status.BAD_REQUEST).entity("No such user exists.").build();
			}
			Entity stats = txn.get(statsKey);
			if ( stats == null ) {
				stats = Entity.newBuilder(statsKey)
						.set("successfulLogins", 0L)
						.set("failedLogins", 0L)
						.set("userFirstLogin", Timestamp.now())
						.set("userLastLogin", Timestamp.now())
						.build();
			}
			String hashedPassword = (String) user.getString("password");
			if ( hashedPassword.equals(DigestUtils.sha3_512Hex(data.password)) ) {
				// TODO: Error in the creation of the log!
				Entity loginStats = Entity.newBuilder(statsKey)
						.set("successfulLogins", 1L + stats.getLong("successfulLogins"))
						.set("failedLogins", stats.getLong("failedLogins"))
						.set("userFirstLogin", stats.getTimestamp("userFirstLogin"))
						.set("userLastLogin", Timestamp.now())
						.build();
				String loginIP = request.getRemoteAddr() != null ? request.getRemoteAddr() : "";
				String loginHost = request.getRemoteHost() != null ? request.getRemoteHost() : "";
				StringValue loginLatLon = StringValue.newBuilder(headers.getHeaderString("X-AppEngine-CityLatLong"))
						.setExcludeFromIndexes(true).build() != null ? StringValue.newBuilder(
								headers.getHeaderString("X-AppEngine-CityLatLong"))
								.setExcludeFromIndexes(true).build() : StringValue.of("");
				String loginCity = headers.getHeaderString("X-AppEngine-City") != null ? headers.getHeaderString("X-AppEngine-City") : "";
				String loginCountry = headers.getHeaderString("X-AppEngine-Country") != null ? headers.getHeaderString("X-AppEngine-Country") : "";
				Entity log = Entity.newBuilder(logKey)
					.set("loginIP", loginIP)
					.set("loginHost", loginHost)
					.set("LoginLatlon", loginLatLon)
					.set("loginCity", loginCity)
					.set("loginCountry", loginCountry)
					.set("loginTime", Timestamp.now())
					.build();
				txn.put(log, loginStats);
				txn.commit();
				AuthToken at = new AuthToken(data.username);
				LOG.info("User '" + data.username + "' logged in successfully.");
				return Response.ok(g.toJson(at)).build();
			} else {
				LOG.warning("Wrong password.");
				Entity userStats = Entity.newBuilder(statsKey)
						.set("successfulLogins", stats.getLong("successfulLogins"))
						.set("failedLogins", 1L + stats.getLong("failedLogins"))
						.set("userFirstLogin", stats.getTimestamp("userFirstLogin"))
						.set("userLastLogin", stats.getTimestamp("userLastLogin"))
						.set("lastLoginAttempt", Timestamp.now())
						.build();
				txn.put(userStats);
				txn.commit();
				LOG.warning("Wrong password for username: " + data.username);
				return Response.status(Status.UNAUTHORIZED).entity("Wrong password.").build();
			}
		} catch ( Exception e ) {
			txn.rollback();
			LOG.severe(e.getMessage());
			return Response.status(Status.INTERNAL_SERVER_ERROR).build();
		} finally {
			if ( txn.isActive() ) {
				txn.rollback();
				return Response.status(Status.INTERNAL_SERVER_ERROR).build();
			}
		}
	}
	
	@GET
	@Path("/user")
	@Consumes(MediaType.APPLICATION_JSON)
	public Response getLast24HourLoginData(LoginData data) {
		LOG.fine("Attempt to get the last 24 hours login timestamps of user: " + data.username);
		Key userKey = userKeyFactory.newKey(data.username);
		Transaction txn = datastore.newTransaction();
		try {
			Entity user = txn.get(userKey);
			if ( user == null ) {
				LOG.warning("No such user exists.");
				txn.rollback();
				return Response.status(Status.BAD_REQUEST).entity("No such user exists.").build();
			}
			String hashedPassword = (String) user.getString("password");
			if ( hashedPassword.equals(DigestUtils.sha3_512Hex(data.password)) ) {
				Query<ProjectionEntity> projectionQuery = Query.newProjectionEntityQueryBuilder()
				        .setKind("UserLogs")
				        .setFilter(CompositeFilter.and(
				        		PropertyFilter.hasAncestor(userKey),
				        		PropertyFilter.ge("loginTime", Timestamp.of(
								new Date(System.currentTimeMillis() - HOURS24)))))
				        .setOrderBy(OrderBy.asc("created"))
				        .setProjection("loginTime")
				        .build();
				List<Timestamp> timestamps = new LinkedList<>();
				QueryResults<ProjectionEntity> results = datastore.run(projectionQuery);
				while ( results.hasNext() ) {
					ProjectionEntity timestamp = results.next();
					timestamps.add(timestamp.getTimestamp("loginTime"));
				}
				/*Query<Entity> query = Query.newEntityQueryBuilder()
						.setKind("UserLogs")
						.setFilter(CompositeFilter.and(
								PropertyFilter.hasAncestor(userKey), 
								PropertyFilter.ge("loginTime", Timestamp.of(
								new Date(System.currentTimeMillis() - HOURS24)))))
						.setOrderBy(OrderBy.asc("created"))
						.build();
				QueryResults<Entity> logs = txn.run(query);*/
				txn.commit();
				LOG.info("User '" + data.username + "' logged in successfully.");
				return Response.ok(g.toJson(timestamps)).build();
			} else {
				txn.commit();
				LOG.warning("Wrong password for username: " + data.username);
				return Response.status(Status.UNAUTHORIZED).entity("Wrong password.").build();
			}
		} catch ( Exception e ) {
			txn.rollback();
			LOG.severe(e.getMessage());
			return Response.status(Status.INTERNAL_SERVER_ERROR).build();
		} finally {
			if ( txn.isActive() ) {
				txn.rollback();
				return Response.status(Status.INTERNAL_SERVER_ERROR).build();
			}
		}
	}
}