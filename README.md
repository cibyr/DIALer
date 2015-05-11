DIALer is a simple command-line client for the [DIAL protocol](http://www.dial-multiscreen.org/ ), implemented in Rust. DIALer is intended to aid in debugging and testing DIAL applications.

Usage: `./DIALer [options]`

Options:

    -a NAME [PAYLOAD]    Set application name
    -h                   Print this help message

If invoked without any options, DIALer performs DIAL Service Discovery (as described in section 5 of the DIAL specification) then prints the list of discovered DIAL servers.

If an application name is specified (with the `-a` option) DIALer checks with each discovered server for the presence of that application (as described in section 6.1 of the DIAL specification). If exactly one server with the specification application is discovered, DAILer then launches the application on that server (as described in section 6.2 of the DIAL specification), using the given payload (if supplied).

DIALer implements no functionality not present in the [DIAL sample client](http://www.dial-multiscreen.org/example-code ), but does comply with the specification more precisely in a couple of areas (timeouts, and the Content-Type header), which improves compatibility with DIAL servers found in the wild (including the DIAL server found in the Fire TV).
