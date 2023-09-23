#pragma once

#define FOR_EACH_HTTP_STATUS(X)                                                                                                             \
    X(SWITCHING_PROTOCOLS, 101, "Switching protocols", "Protocol is switching over from HTTP")                                              \
    X(OK, 200, "OK", "Success")                                                                                                             \
    X(PARTIAL_CONTENT, 206, "Partial content", "Delivering part of requested resource")                                                     \
    X(MOVED_PERMANENTLY, 301, "Moved permanently", "This content has moved to another place")                                               \
    X(NOT_MODIFIED, 304, "Not modified", "The content has not changed since previous request")                                              \
    X(TEMPORARY_REDIRECT, 307, "Temporary Redirect", "This content can be temporarily found at a different location")                       \
    X(BAD_REQUEST, 400, "Bad request", "The client has issued a bad request")                                                               \
    X(NOT_AUTHORIZED, 401, "Not authorized", "Client has no authorization to access this resource")                                         \
    X(FORBIDDEN, 403, "Forbidden", "Access to this resource has been denied")                                                               \
    X(NOT_FOUND, 404, "Not found", "The requested resource could not be found on this server")                                              \
    X(NOT_ALLOWED, 405, "Not allowed", "The requested method is not allowed by this server")                                                \
    X(NOT_ACCEPTABLE, 406, "Not acceptable", "No suitable accepted-encoding header provided")                                               \
    X(TIMEOUT, 408, "Request timeout", "Client did not produce a request within expected timeframe")                                        \
    X(TOO_LARGE, 413, "Request too large", "The request entity is too large")                                                               \
    X(RANGE_UNSATISFIABLE, 416, "Requested range unsatisfiable", "The server can't supply the requested portion of the requested resource") \
    X(I_AM_A_TEAPOT, 418, "I'm a teapot", "Client requested to brew coffee but device is a teapot")                                         \
    X(CLIENT_TOO_HIGH, 420, "Client too high", "Client is too high to make a request")                                                      \
    X(INTERNAL_ERROR, 500, "Internal server error", "The server encountered an internal error that couldn't be recovered from")             \
    X(NOT_IMPLEMENTED, 501, "Not implemented", "Server lacks the ability to fulfil the request")                                            \
    X(UNAVAILABLE, 503, "Service unavailable", "The server is either overloaded or down for maintenance")                                   \
    X(SERVER_TOO_HIGH, 520, "Server too high", "The server is too high to answer the request")
