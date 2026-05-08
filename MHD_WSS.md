10. Websockets
Websockets are a genuine way to implement push notifications, where the server initiates the communication while the client can be idle. Usually a HTTP communication is half-duplex and always requested by the client, but websockets are full-duplex and only initialized by the client. In the further communication both sites can use the websocket at any time to send data to the other site.

To initialize a websocket connection the client sends a special HTTP request to the server and initializes a handshake between client and server which switches from the HTTP protocol to the websocket protocol. Thus both the server as well as the client must support websockets. If proxys are used, they must support websockets too. In this chapter we take a look on server and client, but with a focus on the server with libmicrohttpd.

Since version 0.9.52 libmicrohttpd supports upgrading requests, which is required for switching from the HTTP protocol. Since version 0.9.74 the library libmicrohttpd_ws has been added to support the websocket protocol.

Upgrading connections with libmicrohttpd
To support websockets we need to enable upgrading of HTTP connections first. This is done by passing the flag MHD_ALLOW_UPGRADE to MHD_start_daemon().

daemon = MHD_start_daemon (MHD_USE_INTERNAL_POLLING_THREAD |
                           MHD_USE_THREAD_PER_CONNECTION |
                           MHD_ALLOW_UPGRADE |
                           MHD_USE_ERROR_LOG,
                           PORT, NULL, NULL,
                           &access_handler, NULL,
                           MHD_OPTION_END);
The next step is to turn a specific request into an upgraded connection. This done in our access_handler by calling MHD_create_response_for_upgrade(). An upgrade_handler will be passed to perform the low-level actions on the socket.

Please note that the socket here is just a regular socket as provided by the operating system. To use it as a websocket, some more steps from the following chapters are required.

static enum MHD_Result
access_handler (void *cls,
                struct MHD_Connection *connection,
                const char *url,
                const char *method,
                const char *version,
                const char *upload_data,
                size_t *upload_data_size,
                void **ptr)
{
  /* ... */
  /* some code to decide whether to upgrade or not */
  /* ... */

  /* create the response for upgrade */
  response = MHD_create_response_for_upgrade (&upgrade_handler,
                                              NULL);

  /* ... */
  /* additional headers, etc. */
  /* ... */

  ret = MHD_queue_response (connection,
                            MHD_HTTP_SWITCHING_PROTOCOLS,
                            response);
  MHD_destroy_response (response);

  return ret;
}
In the upgrade_handler we receive the low-level socket, which is used for the communication with the specific client. In addition to the low-level socket we get:

Some data, which has been read too much while libmicrohttpd was switching the protocols. This value is usually empty, because it would mean that the client has sent data before the handshake was complete.
A struct MHD_UpgradeResponseHandle which is used to perform special actions like closing, corking or uncorking the socket. These commands are executed by passing the handle to MHD_upgrade_action().
Depending of the flags specified while calling MHD_start_deamon() our upgrade_handler is either executed in the same thread as our daemon or in a thread specific for each connection. If it is executed in the same thread then upgrade_handler is a blocking call for our webserver and we should finish it as fast as possible (i. e. by creating a thread and passing the information there). If MHD_USE_THREAD_PER_CONNECTION was passed to MHD_start_daemon() then a separate thread is used and thus our upgrade_handler needs not to start a separate thread.

An upgrade_handler, which is called with a separate thread per connection, could look like this:

static void
upgrade_handler (void *cls,
                 struct MHD_Connection *connection,
                 void *req_cls,
                 const char *extra_in,
                 size_t extra_in_size,
                 MHD_socket fd,
                 struct MHD_UpgradeResponseHandle *urh)
{
  /* ... */
  /* do something with the socket `fd` like `recv()` or `send()` */
  /* ... */

  /* close the socket when it is not needed anymore */
  MHD_upgrade_action (urh,
                      MHD_UPGRADE_ACTION_CLOSE);
}
This is all you need to know for upgrading connections with libmicrohttpd. The next chapters focus on using the websocket protocol with libmicrohttpd_ws.

Websocket handshake with libmicrohttpd_ws
To request a websocket connection the client must send the following information with the HTTP request:

A GET request must be sent.
The version of the HTTP protocol must be 1.1 or higher.
A Host header field must be sent
A Upgrade header field containing the keyword "websocket" (case-insensitive). Please note that the client could pass multiple protocols separated by comma.
A Connection header field that includes the token "Upgrade" (case-insensitive). Please note that the client could pass multiple tokens separated by comma.
A Sec-WebSocket-Key header field with a base64-encoded value. The decoded the value is 16 bytes long and has been generated randomly by the client.
A Sec-WebSocket-Version header field with the value "13".
Optionally the client can also send the following information:

A Origin header field can be used to determine the source of the client (i. e. the website).
A Sec-WebSocket-Protocol header field can contain a list of supported protocols by the client, which can be sent over the websocket.
A Sec-WebSocket-Extensions header field which may contain extensions to the websocket protocol. The extensions must be registered by IANA.
A valid example request from the client could look like this:

GET /chat HTTP/1.1
Host: server.example.com
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Sec-WebSocket-Version: 13
To complete the handshake the server must respond with some specific response headers:

The HTTP response code 101 Switching Protocols must be answered.
An Upgrade header field containing the value "websocket" must be sent.
A Connection header field containing the value "Upgrade" must be sent.
A Sec-WebSocket-Accept header field containing a value, which has been calculated from the Sec-WebSocket-Key request header field, must be sent.
Optionally the server may send following headers:

A Sec-WebSocket-Protocol header field containing a protocol of the list specified in the corresponding request header field.
A Sec-WebSocket-Extension header field containing all used extensions of the list specified in the corresponding request header field.
A valid websocket HTTP response could look like this:

HTTP/1.1 101 Switching Protocols
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=
To upgrade a connection to a websocket the libmicrohttpd_ws provides some helper functions for the access_handler callback function:

MHD_websocket_check_http_version() checks whether the HTTP version is 1.1 or above.
MHD_websocket_check_connection_header() checks whether the value of the Connection request header field contains an "Upgrade" token (case-insensitive).
MHD_websocket_check_upgrade_header() checks whether the value of the Upgrade request header field contains the "websocket" keyword (case-insensitive).
MHD_websocket_check_version_header() checks whether the value of the Sec-WebSocket-Version request header field is "13".
MHD_websocket_create_accept_header() takes the value from the Sec-WebSocket-Key request header and calculates the value for the Sec-WebSocket-Accept response header field.
The access_handler example of the previous chapter can now be extended with these helper functions to perform the websocket handshake:

static enum MHD_Result
access_handler (void *cls,
                struct MHD_Connection *connection,
                const char *url,
                const char *method,
                const char *version,
                const char *upload_data,
                size_t *upload_data_size,
                void **ptr)
{
  static int aptr;
  struct MHD_Response *response;
  enum MHD_Result ret;

  (void) cls;               /* Unused. Silent compiler warning. */
  (void) upload_data;       /* Unused. Silent compiler warning. */
  (void) upload_data_size;  /* Unused. Silent compiler warning. */

  if (0 != strcmp (method, "GET"))
    return MHD_NO;              /* unexpected method */
  if (&aptr != *ptr)
  {
    /* do never respond on first call */
    *ptr = &aptr;
    return MHD_YES;
  }
  *ptr = NULL;                  /* reset when done */

  if (0 == strcmp (url, "/"))
  {
    /* Default page for visiting the server */
    struct MHD_Response *response = MHD_create_response_from_buffer (
                                      strlen (PAGE),
                                      PAGE,
                                      MHD_RESPMEM_PERSISTENT);
    ret = MHD_queue_response (connection,
                              MHD_HTTP_OK,
                              response);
    MHD_destroy_response (response);
  }
  else if (0 == strcmp (url, "/chat"))
  {
    char is_valid = 1;
    const char* value = NULL;
    char sec_websocket_accept[29];

    if (0 != MHD_websocket_check_http_version (version))
    {
      is_valid = 0;
    }
    value = MHD_lookup_connection_value (connection,
                                         MHD_HEADER_KIND,
                                         MHD_HTTP_HEADER_CONNECTION);
    if (0 != MHD_websocket_check_connection_header (value))
    {
      is_valid = 0;
    }
    value = MHD_lookup_connection_value (connection,
                                         MHD_HEADER_KIND,
                                         MHD_HTTP_HEADER_UPGRADE);
    if (0 != MHD_websocket_check_upgrade_header (value))
    {
      is_valid = 0;
    }
    value = MHD_lookup_connection_value (connection,
                                         MHD_HEADER_KIND,
                                         MHD_HTTP_HEADER_SEC_WEBSOCKET_VERSION);
    if (0 != MHD_websocket_check_version_header (value))
    {
      is_valid = 0;
    }
    value = MHD_lookup_connection_value (connection,
                                         MHD_HEADER_KIND,
                                         MHD_HTTP_HEADER_SEC_WEBSOCKET_KEY);
    if (0 != MHD_websocket_create_accept_header (value, sec_websocket_accept))
    {
      is_valid = 0;
    }

    if (1 == is_valid)
    {
      /* upgrade the connection */
      response = MHD_create_response_for_upgrade (&upgrade_handler,
                                                  NULL);
      MHD_add_response_header (response,
                               MHD_HTTP_HEADER_CONNECTION,
                               "Upgrade");
      MHD_add_response_header (response,
                               MHD_HTTP_HEADER_UPGRADE,
                               "websocket");
      MHD_add_response_header (response,
                               MHD_HTTP_HEADER_SEC_WEBSOCKET_ACCEPT,
                               sec_websocket_accept);
      ret = MHD_queue_response (connection,
                                MHD_HTTP_SWITCHING_PROTOCOLS,
                                response);
      MHD_destroy_response (response);
    }
    else
    {
      /* return error page */
      struct MHD_Response*response = MHD_create_response_from_buffer (
                                       strlen (PAGE_INVALID_WEBSOCKET_REQUEST),
                                       PAGE_INVALID_WEBSOCKET_REQUEST,
                                       MHD_RESPMEM_PERSISTENT);
      ret = MHD_queue_response (connection,
                                MHD_HTTP_BAD_REQUEST,
                                response);
      MHD_destroy_response (response);
    }
  }
  else
  {
    struct MHD_Response*response = MHD_create_response_from_buffer (
                                     strlen (PAGE_NOT_FOUND),
                                     PAGE_NOT_FOUND,
                                     MHD_RESPMEM_PERSISTENT);
    ret = MHD_queue_response (connection,
                              MHD_HTTP_NOT_FOUND,
                              response);
    MHD_destroy_response (response);
  }

  return ret;
}
Please note that we skipped the check of the Host header field here, because we don’t know the host for this example.

Decoding/encoding the websocket protocol with libmicrohttpd_ws
Once the websocket connection is established you can receive/send frame data with the low-level socket functions recv() and send(). The frame data which goes over the low-level socket is encoded according to the websocket protocol. To use received payload data, you need to decode the frame data first. To send payload data, you need to encode it into frame data first.

libmicrohttpd_ws provides several functions for encoding of payload data and decoding of frame data:

MHD_websocket_decode() decodes received frame data. The payload data may be of any kind, depending upon what the client has sent. So this decode function is used for all kind of frames and returns the frame type along with the payload data.
MHD_websocket_encode_text() encodes text. The text must be encoded with UTF-8.
MHD_websocket_encode_binary() encodes binary data.
MHD_websocket_encode_ping() encodes a ping request to check whether the websocket is still valid and to test latency.
MHD_websocket_encode_ping() encodes a pong response to answer a received ping request.
MHD_websocket_encode_close() encodes a close request.
MHD_websocket_free() frees data returned by the encode/decode functions.
Since you could receive or send fragmented data (i. e. due to a too small buffer passed to recv) all of these encode/decode functions require a pointer to a struct MHD_WebSocketStream passed as argument. In this structure libmicrohttpd_ws stores information about encoding/decoding of the particular websocket. For each websocket you need a unique struct MHD_WebSocketStream to encode/decode with this library.

To create or destroy struct MHD_WebSocketStream we have additional functions:

MHD_websocket_stream_init() allocates and initializes a new struct MHD_WebSocketStream. You can specify some options here to alter the behavior of the websocket stream.
MHD_websocket_stream_free() frees a previously allocated struct MHD_WebSocketStream.
With these encode/decode functions we can improve our upgrade_handler callback function from an earlier example to a working websocket:

static void
upgrade_handler (void *cls,
                 struct MHD_Connection *connection,
                 void *req_cls,
                 const char *extra_in,
                 size_t extra_in_size,
                 MHD_socket fd,
                 struct MHD_UpgradeResponseHandle *urh)
{
  /* make the socket blocking (operating-system-dependent code) */
  make_blocking (fd);

  /* create a websocket stream for this connection */
  struct MHD_WebSocketStream* ws;
  int result = MHD_websocket_stream_init (&ws,
                                          0,
                                          0);
  if (0 != result)
  {
    /* Couldn't create the websocket stream.
     * So we close the socket and leave
     */
    MHD_upgrade_action (urh,
                        MHD_UPGRADE_ACTION_CLOSE);
    return;
  }

  /* Let's wait for incoming data */
  const size_t buf_len = 256;
  char buf[buf_len];
  ssize_t got;
  while (MHD_WEBSOCKET_VALIDITY_VALID == MHD_websocket_stream_is_valid (ws))
  {
    got = recv (fd,
                buf,
                buf_len,
                0);
    if (0 >= got)
    {
      /* the TCP/IP socket has been closed */
      break;
    }

    /* parse the entire received data */
    size_t buf_offset = 0;
    while (buf_offset < (size_t) got)
    {
      size_t new_offset = 0;
      char *frame_data = NULL;
      size_t frame_len  = 0;
      int status = MHD_websocket_decode (ws,
                                         buf + buf_offset,
                                         ((size_t) got) - buf_offset,
                                         &new_offset,
                                         &frame_data,
                                         &frame_len);
      if (0 > status)
      {
        /* an error occurred and the connection must be closed */
        if (NULL != frame_data)
        {
          MHD_websocket_free (ws, frame_data);
        }
        break;
      }
      else
      {
        buf_offset += new_offset;
        if (0 < status)
        {
          /* the frame is complete */
          switch (status)
          {
          case MHD_WEBSOCKET_STATUS_TEXT_FRAME:
            /* The client has sent some text.
             * We will display it and answer with a text frame.
             */
            if (NULL != frame_data)
            {
              printf ("Received message: %s\n", frame_data);
              MHD_websocket_free (ws, frame_data);
              frame_data = NULL;
            }
            result = MHD_websocket_encode_text (ws,
                                                "Hello",
                                                5,  /* length of "Hello" */
                                                0,
                                                &frame_data,
                                                &frame_len,
                                                NULL);
            if (0 == result)
            {
              send_all (fd,
                        frame_data,
                        frame_len);
            }
            break;

          case MHD_WEBSOCKET_STATUS_CLOSE_FRAME:
            /* if we receive a close frame, we will respond with one */
            MHD_websocket_free (ws,
                                frame_data);
            frame_data = NULL;

            result = MHD_websocket_encode_close (ws,
                                                 0,
                                                 NULL,
                                                 0,
                                                 &frame_data,
                                                 &frame_len);
            if (0 == result)
            {
              send_all (fd,
                        frame_data,
                        frame_len);
            }
            break;

          case MHD_WEBSOCKET_STATUS_PING_FRAME:
            /* if we receive a ping frame, we will respond */
            /* with the corresponding pong frame */
            {
              char *pong = NULL;
              size_t pong_len = 0;
              result = MHD_websocket_encode_pong (ws,
                                                  frame_data,
                                                  frame_len,
                                                  &pong,
                                                  &pong_len);
              if (0 == result)
              {
                send_all (fd,
                          pong,
                          pong_len);
              }
              MHD_websocket_free (ws,
                                  pong);
            }
            break;

          default:
            /* Other frame types are ignored
             * in this minimal example.
             * This is valid, because they become
             * automatically skipped if we receive them unexpectedly
             */
            break;
          }
        }
        if (NULL != frame_data)
        {
          MHD_websocket_free (ws, frame_data);
        }
      }
    }
  }

  /* free the websocket stream */
  MHD_websocket_stream_free (ws);

  /* close the socket when it is not needed anymore */
  MHD_upgrade_action (urh,
                      MHD_UPGRADE_ACTION_CLOSE);
}

/* This helper function is used for the case that
 * we need to resend some data
 */
static void
send_all (MHD_socket fd,
          const char *buf,
          size_t len)
{
  ssize_t ret;
  size_t off;

  for (off = 0; off < len; off += ret)
  {
    ret = send (fd,
                &buf[off],
                (int) (len - off),
                0);
    if (0 > ret)
    {
      if (EAGAIN == errno)
      {
        ret = 0;
        continue;
      }
      break;
    }
    if (0 == ret)
      break;
  }
}

/* This helper function contains operating-system-dependent code and
 * is used to make a socket blocking.
 */
static void
make_blocking (MHD_socket fd)
{
#if defined(MHD_POSIX_SOCKETS)
  int flags;

  flags = fcntl (fd, F_GETFL);
  if (-1 == flags)
    return;
  if ((flags & ~O_NONBLOCK) != flags)
    if (-1 == fcntl (fd, F_SETFL, flags & ~O_NONBLOCK))
      abort ();
#elif defined(MHD_WINSOCK_SOCKETS)
  unsigned long flags = 0;

  ioctlsocket (fd, FIONBIO, &flags);
#endif /* MHD_WINSOCK_SOCKETS */
}

Please note that the websocket in this example is only half-duplex. It waits until the blocking recv() call returns and only does then something. In this example all frame types are decoded by libmicrohttpd_ws, but we only do something when a text, ping or close frame is received. Binary and pong frames are ignored in our code. This is legit, because the server is only required to implement at least support for ping frame or close frame (the other frame types could be skipped in theory, because they don’t require an answer). The pong frame doesn’t require an answer and whether text frames or binary frames get an answer simply belongs to your server application. So this is a valid minimal example.

Until this point you’ve learned everything you need to basically use websockets with libmicrohttpd and libmicrohttpd_ws. These libraries offer much more functions for some specific cases.

The further chapters of this tutorial focus on some specific problems and the client site programming.

Using full-duplex websockets
To use full-duplex websockets you can simply create two threads per websocket connection. One of these threads is used for receiving data with a blocking recv() call and the other thread is triggered by the application internal codes and sends the data.

A full-duplex websocket example is implemented in the example file websocket_chatserver_example.c.

Error handling
The most functions of libmicrohttpd_ws return a value of enum MHD_WEBSOCKET_STATUS. The values of this enumeration can be converted into an integer and have an easy interpretation:

If the value is less than zero an error occurred and the call has failed. Check the enumeration values for more specific information.
If the value is equal to zero, the call succeeded.
If the value is greater than zero, the call succeeded and the value specifies the decoded frame type. Currently positive values are only returned by MHD_websocket_decode() (of the functions with this return enumeration type).
A websocket stream can also get broken when invalid frame data is received. Also the other site could send a close frame which puts the stream into a state where it may not be used for regular communication. Whether a stream has become broken, can be checked with MHD_websocket_stream_is_valid().

Fragmentation
In addition to the regular TCP/IP fragmentation the websocket protocol also supports fragmentation. Fragmentation could be used for continuous payload data such as video data from a webcam. Whether or not you want to receive fragmentation is specified upon initialization of the websocket stream. If you pass MHD_WEBSOCKET_FLAG_WANT_FRAGMENTS in the flags parameter of MHD_websocket_stream_init() then you can receive fragments. If you don’t pass this flag (in the most cases you just pass zero as flags) then you don’t want to handle fragments on your own. libmicrohttpd_ws removes then the fragmentation for you in the background. You only get the completely assembled frames.

Upon encoding you specify whether or not you want to create a fragmented frame by passing a flag to the corresponding encode function. Only MHD_websocket_encode_text() and MHD_websocket_encode_binary() can be used for fragmentation, because the other frame types may not be fragmented. Encoding fragmented frames is independent of the MHD_WEBSOCKET_FLAG_WANT_FRAGMENTS flag upon initialization.


