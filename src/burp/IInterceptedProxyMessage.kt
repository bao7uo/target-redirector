package burp

/*
 * @(#)IInterceptedProxyMessage.java
 *
 * Copyright PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */
import java.net.InetAddress

/**
 * This interface is used to represent an HTTP message that has been intercepted
 * by Burp Proxy. Extensions can register an
 * `IProxyListener` to receive details of proxy messages using this
 * interface. *
 */
interface IInterceptedProxyMessage {

    /**
     * This method retrieves a unique reference number for this
     * request/response.
     *
     * @return An identifier that is unique to a single request/response pair.
     * Extensions can use this to correlate details of requests and responses
     * and perform processing on the response message accordingly.
     */
    val messageReference: Int

    /**
     * This method retrieves details of the intercepted message.
     *
     * @return An `IHttpRequestResponse` object containing details of
     * the intercepted message.
     */
    val messageInfo: IHttpRequestResponse

    /**
     * This method retrieves the currently defined interception action. The
     * default action is
     * `ACTION_FOLLOW_RULES`. If multiple proxy listeners are
     * registered, then other listeners may already have modified the
     * interception action before it reaches the current listener. This method
     * can be used to determine whether this has occurred.
     *
     * @return The currently defined interception action. Possible values are
     * defined within this interface.
     */
    /**
     * This method is used to update the interception action.
     *
     * @param interceptAction The new interception action. Possible values are
     * defined within this interface.
     */
    var interceptAction: Int

    /**
     * This method retrieves the name of the Burp Proxy listener that is
     * processing the intercepted message.
     *
     * @return The name of the Burp Proxy listener that is processing the
     * intercepted message. The format is the same as that shown in the Proxy
     * Listeners UI - for example, "127.0.0.1:8080".
     */
    val listenerInterface: String

    /**
     * This method retrieves the client IP address from which the request for
     * the intercepted message was received.
     *
     * @return The client IP address from which the request for the intercepted
     * message was received.
     */
    val clientIpAddress: InetAddress

    companion object {
        /**
         * This action causes Burp Proxy to follow the current interception rules to
         * determine the appropriate action to take for the message.
         */
        val ACTION_FOLLOW_RULES = 0
        /**
         * This action causes Burp Proxy to present the message to the user for
         * manual review or modification.
         */
        val ACTION_DO_INTERCEPT = 1
        /**
         * This action causes Burp Proxy to forward the message to the remote server
         * or client, without presenting it to the user.
         */
        val ACTION_DONT_INTERCEPT = 2
        /**
         * This action causes Burp Proxy to drop the message.
         */
        val ACTION_DROP = 3
        /**
         * This action causes Burp Proxy to follow the current interception rules to
         * determine the appropriate action to take for the message, and then make a
         * second call to processProxyMessage.
         */
        val ACTION_FOLLOW_RULES_AND_REHOOK = 0x10
        /**
         * This action causes Burp Proxy to present the message to the user for
         * manual review or modification, and then make a second call to
         * processProxyMessage.
         */
        val ACTION_DO_INTERCEPT_AND_REHOOK = 0x11
        /**
         * This action causes Burp Proxy to skip user interception, and then make a
         * second call to processProxyMessage.
         */
        val ACTION_DONT_INTERCEPT_AND_REHOOK = 0x12
    }
}
