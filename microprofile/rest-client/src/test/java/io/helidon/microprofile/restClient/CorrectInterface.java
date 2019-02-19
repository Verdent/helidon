package io.helidon.microprofile.restClient;

import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;

/**
 * Correct test interface for validation
 *
 * @author David Kral
 */

@Path("test/{first}")
public interface CorrectInterface {

    @GET
    @Path("{second}")
    void firstMethod(@PathParam("first") String first, @PathParam("second") String second);

    @GET
    void secondMethod(@PathParam("first") String first, String second);

    @POST
    void thirdMethod(@PathParam("first") String first);

}
