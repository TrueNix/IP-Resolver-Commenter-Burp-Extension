from burp import IBurpExtender
from burp import IHttpListener
from burp import IHttpRequestResponse
from java.net import InetAddress

class BurpExtender(IBurpExtender, IHttpListener):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("IP Resolver Commenter")
        callbacks.registerHttpListener(self)

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # Only process requests from Intruder
        if toolFlag == self._callbacks.TOOL_INTRUDER and messageIsRequest:
            # Get the HTTP service for the request to resolve the IP address
            service = messageInfo.getHttpService()
            host = service.getHost()

            try:
                # Resolve the IP address
                ip = InetAddress.getByName(host).getHostAddress()

                # Append the IP address to the comment field of the request
                comment = "IP: " + ip
                messageInfo.setComment(comment)

            except Exception as e:
                print "Failed to resolve IP: " + str(e)
