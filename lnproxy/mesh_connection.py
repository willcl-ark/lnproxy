import logging
import queue
import time

import goTenna
import trio

import lnproxy.config as config
import lnproxy.proxy as proxy
import lnproxy.util as util

# For SPI connection only, set SPI_CONNECTION to true with proper SPI settings
SPI_CONNECTION = False
SPI_BUS_NO = 0
SPI_CHIP_NO = 0
SPI_REQUEST = 22
SPI_READY = 27

logger = util.CustomAdapter(logging.getLogger(__name__), None)
gotenna_logger = logging.getLogger("goTenna")
gotenna_logger.setLevel(level=logging.WARNING)


async def connection_daemon():
    """Load the goTenna mesh connection object (to persistent config.mesh_conn).
    Start the send_queue_daemon in the main nursery.
    """
    # Wait for node info to populate.
    while config.node_info is None:
        logger.info("Can't find node_info")
        await trio.sleep(0.1)
    logger.info("Got node info, starting connection")
    # start the mesh connection
    config.mesh_conn = Connection()
    # start the send_queue_daemon:
    while config.mesh_conn.active is False:
        await trio.sleep(0.1)
    config.nursery.start_soon(proxy.send_queue_daemon)
    logger.info("Connection and send_queue_daemon started successfully")


class Connection:
    """goTenna connection class
    """

    def __init__(self):
        logger.info("Initialising goTenna Connection object")
        self.active = False
        self.api_thread = None
        self.status = {}
        self.in_flight_events = {}
        self._set_frequencies = False
        self._set_tx_power = False
        self._set_bandwidth = False
        self._set_geo_region = False
        self._settings = goTenna.settings.GoTennaSettings(
            rf_settings=goTenna.settings.RFSettings(),
            geo_settings=goTenna.settings.GeoSettings(),
        )
        self._do_encryption = True
        self._awaiting_disconnect_after_fw_update = [False]
        # Wait for node info to populate from main thread
        while not config.node_info:
            time.sleep(0.1)
        while config.node_info["id"] not in config.nodes:
            time.sleep(0.1)
        self.gid = config.nodes[config.node_info["id"]]
        self.geo_region = 2
        self.sdk_token = config.sdk_token
        self.send_mesh_send, self.send_mesh_recv = trio.open_memory_channel(50)
        self.recv_msg_q = queue.Queue()
        self.start_handlers()
        self.configure()
        self.active = True
        logger.info("goTenna Connection object initialised")

    def start_handlers(self):
        # start the queue handlers in the main nursery
        config.nursery.start_soon(self.send_handler)
        config.nursery.start_soon(self.recv_handler)
        logger.info("goTenna Connection handlers started")

    @staticmethod
    async def parse_recv_mesh_msg(msg: bytes):
        """Parses the header of a received message.
        If a queue does not exist for this pubkey, then it creates the required queues
        and will start a new `handle_inbound` (in the main nursery) which will monitor
        this queue.
        Puts the received message in the correct queue (stream) with header stripped.
        """
        _to = msg[0:2].hex()
        _from = msg[2:4].hex()
        _msg = msg[4:]
        # If we don't have a queue, make one and start a daemon to manage connection
        if _from not in config.QUEUE:
            util.create_queue(_from)
            # start a new handle_inbound for this connection
            await config.nursery.start(proxy.handle_inbound, _from)
        await config.QUEUE[_from]["inbound"][0].send_all(_msg)

    @util.rate_dec()
    async def lookup_and_send(self, msg):
        """Get a GID from the lookup table based on the "to" pk in the message header
        and send the message via the mesh.
        """
        # lookup the recipient GID
        to_pk = msg[0:2]
        to_gid = util.get_gid(to_pk)
        # send to GID using private message in binary mode
        self.send_private(to_gid, msg, binary=True)

    async def send_handler(self):
        """Monitors the shared send message queue and sends each message it finds there.
        """
        logger.info("Started send_handler")
        async for msg in self.send_mesh_recv:
            await self.lookup_and_send(msg)

    async def recv_handler(self):
        """Handles all messages received from the mesh.
        Put them in the right queue (memory_stream).
        """
        logger.info("Started recv_handler")
        while True:
            if not self.recv_msg_q.empty():
                await self.parse_recv_mesh_msg(self.recv_msg_q.get())
            else:
                await trio.sleep(1)

    def configure(self):
        if self.api_thread:
            pass
        else:
            self.set_sdk_token(self.sdk_token)
            self.set_geo_region(self.geo_region)
            self.set_gid(self.gid)

    def reset_connection(self):
        if self.api_thread:
            self.api_thread.join()

    def set_sdk_token(self, sdk_token):
        """set sdk_token for the connection
        """
        if self.api_thread:
            logger.warning("To change SDK tokens, restart the app.")
            return
        try:
            if not SPI_CONNECTION:
                self.api_thread = goTenna.driver.Driver(
                    sdk_token=sdk_token,
                    gid=None,
                    settings=None,
                    event_callback=self.event_callback,
                )
            else:
                self.api_thread = goTenna.driver.SpiDriver(
                    SPI_BUS_NO,
                    SPI_CHIP_NO,
                    22,
                    27,
                    sdk_token,
                    None,
                    None,
                    self.event_callback,
                )
            # Manage the API thread with Trio so we can communicate back to it if needed
            config.nursery.start_soon(
                trio.to_thread.run_sync, self.api_thread.run,
            )
        except ValueError:
            logger.error(
                f"SDK token {sdk_token} is not valid. Please enter a valid SDK token.",
            )
        logger.info(f"SDK_TOKEN: {self.api_thread.sdk_token.decode('utf-8')}")

    def event_callback(self, evt):
        """ The event callback that will store even messages from the API.
        See the documentation for ``goTenna.driver``.
        This will be invoked from the API's thread when events are received.
        """
        if evt.event_type == goTenna.driver.Event.MESSAGE:
            # stick it on the receive queue
            self.recv_msg_q.put(evt.message.payload._binary_data)
            # logger.info(f"Received message: {evt.message}")

        elif evt.event_type == goTenna.driver.Event.DEVICE_PRESENT:
            if self._awaiting_disconnect_after_fw_update[0]:
                logger.info("Device physically connected")
            else:
                logger.info("Device physically connected, configure to continue")
                try:
                    self.configure()
                except Exception as e:
                    logger.error(
                        f"Incurred exception whilst trying to auto-configure:\n{e}",
                    )
        elif evt.event_type == goTenna.driver.Event.CONNECT:
            if self._awaiting_disconnect_after_fw_update[0]:
                logger.info("Device reconnected! Firmware update complete!")
                self._awaiting_disconnect_after_fw_update[0] = False
            else:
                logger.info("Connected to goTenna Mesh device!")
        elif evt.event_type == goTenna.driver.Event.DISCONNECT:
            if self._awaiting_disconnect_after_fw_update[0]:
                # Do not reset configuration so that the device will reconnect on its
                # own
                logger.info("Firmware update: Device disconnected, awaiting reconnect")
            else:
                logger.info("Disconnected! {evt}")
                # We reset the configuration here so that if the user plugs in a
                # different device it is not immediately reconfigured with new and
                # incorrect data
                self.api_thread.set_gid(None)
                self.api_thread.set_rf_settings(None)
                self._set_frequencies = False
                self._set_tx_power = False
                self._set_bandwidth = False
        elif evt.event_type == goTenna.driver.Event.STATUS:
            self.status = evt.status
        elif evt.event_type == goTenna.driver.Event.GROUP_CREATE:
            index = -1
            for idx, member in enumerate(evt.group.members):
                if member.gid_val == self.api_thread.gid.gid_val:
                    index = idx
                    break
            logger.info(
                f"Added to group {evt.group.gid.gid_val}: You are member {index}"
            )

    def build_callback(self, error_handler=None, binary=False):
        """ Build a callback for sending to the API thread. May specify a callable
        error_handler(details) taking the error details from the callback.
        The handler should return a string.
        """

        def default_error_handler(details):
            """ Easy error handler if no special behavior is needed.
            Just builds a string with the error.
            """
            if details["code"] in [
                goTenna.constants.ErrorCodes.TIMEOUT,
                goTenna.constants.ErrorCodes.OSERROR,
                goTenna.constants.ErrorCodes.EXCEPTION,
            ]:
                logger.info("USB connection disrupted")
            logger.error(f"{details['code']}: {details['msg']}")

        # Define a second function here so it implicitly captures self
        captured_error_handler = [error_handler]

        def callback(
            correlation_id,
            success=None,
            results=None,
            error=None,
            details=None,
            binary=binary,
        ):
            """ The default callback to pass to the API.
            See the documentation for ``goTenna.driver``.
            Does nothing but log whether the method succeeded or failed.
            """
            method = self.in_flight_events.pop(correlation_id.bytes, "Method call")
            if success:
                if not binary:
                    if results:
                        result = {
                            "method": method,
                            "results": results,
                            "status": "Success",
                        }
                        # self.events.callback.put(result)
                        logger.info(result)
                    else:
                        result = {"method": method, "status": "success"}
                        # self.events.callback.put(result)
                        logger.info(result)
                if binary:
                    # TODO: result not being returned for binary payloads
                    pass
                    # if results:
                    #     logger.info("Sent via mesh:\n")
                    #     utilities.hexdump(results)
            elif error:
                if not captured_error_handler[0]:
                    captured_error_handler[0] = default_error_handler
                    result = {
                        "method": method,
                        "error_details": captured_error_handler[0](details),
                        "status": "failed",
                    }
                    # self.events.callback.put(result)
                    logger.info(result)

        return callback

    def set_gid(self, gid):
        """ Create a new profile (if it does not already exist) with default settings.
        GID should be a 15-digit numerical GID.
        """
        if self.api_thread.connected:
            logger.info("Must not already be connected when setting GID")
            return
        (_gid, _) = self._parse_gid(gid, goTenna.settings.GID.PRIVATE)
        if not _gid:
            return
        self.api_thread.set_gid(_gid)
        self._settings.gid_settings = gid
        logger.info(f"GID: {self.api_thread.gid.gid_val}")

    def send_broadcast(self, message, binary=False):
        """ Send a broadcast message, if binary=True, message must be bytes
        """
        if not self.api_thread.connected:
            logger.error(
                {
                    "send_broadcast": {
                        "status": "failed",
                        "reason": "No device connected",
                    }
                },
            )
        else:

            def error_handler(details):
                """ A special error handler for formatting message failures
                """
                if details["code"] in [
                    goTenna.constants.ErrorCodes.TIMEOUT,
                    goTenna.constants.ErrorCodes.OSERROR,
                ]:
                    logger.error(
                        {
                            "send_broadcast": {
                                "status": "failed",
                                "reason": "message may not have been sent: USB "
                                "connection disrupted",
                            }
                        },
                    )
                logger.error(
                    {
                        "send_broadcast": {
                            "status": "failed",
                            "reason": f"error sending message: {details}",
                        }
                    },
                )

            try:
                if binary:
                    method_callback = self.build_callback(error_handler, binary=True)
                    payload = goTenna.payload.BinaryPayload(message)
                else:
                    method_callback = self.build_callback(error_handler)
                    payload = goTenna.payload.TextPayload(message)

                corr_id = self.api_thread.send_broadcast(payload, method_callback)
                while corr_id is None:
                    # try again if send_broadcast fails
                    time.sleep(10)
                    corr_id = self.api_thread.send_broadcast(payload, method_callback)

                self.in_flight_events[
                    corr_id.bytes
                ] = f"Broadcast message: {message} ({len(message)} bytes)\n"

                if binary:
                    # utilities.hexdump(message, send=True)
                    ...
            except ValueError:
                logger.error(
                    {
                        "send_broadcast": {
                            "status": "failed",
                            "reason": "message too long!",
                        }
                    },
                )
            if not binary:
                logger.error(
                    {
                        "send_broadcast": {
                            "status": "complete",
                            "message": message,
                            "size(B)": len(message),
                        }
                    },
                )

    def _parse_gid(self, __gid, gid_type, print_message=True):
        try:
            if __gid > goTenna.constants.GID_MAX:
                logger.error(
                    f"{str(__gid)} is not a valid GID. The maximum GID is "
                    f"{str(goTenna.constants.GID_MAX)}",
                )
                return None, __gid
            gidobj = goTenna.settings.GID(__gid, gid_type)
            return gidobj, None
        except ValueError:
            if print_message:
                logger.error(f"{__gid} is not a valid GID.")
            return None, None

    def send_private(self, gid: int, message, binary=False):
        """ Send a private message to a contact
        GID is the GID to send the private message to.
        """
        _gid, rest = self._parse_gid(gid, goTenna.settings.GID.PRIVATE)
        if not self.api_thread.connected:
            logger.error("Must connect first")
            return
        if not _gid:
            return

        def error_handler(details):
            """ Special error handler for sending private messages to format errors
            """
            return f"Error sending message: {details}"

        try:
            if binary:
                method_callback = self.build_callback(error_handler, binary=True)
                payload = goTenna.payload.BinaryPayload(message)
            else:
                method_callback = self.build_callback(error_handler)
                payload = goTenna.payload.TextPayload(message)

            def ack_callback(correlation_id, success):
                if not success:
                    logger.error(
                        f"Private message to {_gid.gid_val}: delivery not confirmed,"
                        f"recipient may be offline or out of range",
                    )

            corr_id = self.api_thread.send_private(
                _gid,
                payload,
                method_callback,
                ack_callback=ack_callback,
                # encrypt=self._do_encryption,
                encrypt=False,
            )
        except ValueError:
            logger.error("Message too long!")
            return
        self.in_flight_events[
            corr_id.bytes
        ] = f"Private message to {_gid.gid_val}: {message}"

    def get_device_type(self):
        device = self.api_thread.device_type
        if device is not None:
            logger.info(device)
        return device

    @staticmethod
    def list_geo_region():
        """ List the available region.
        """
        return goTenna.constants.GEO_REGION.DICT

    def set_geo_region(self, region):
        """ Configure the frequencies the device will use.
        Allowed region displayed with list_geo_region.
        """
        if self.get_device_type() == "pro":
            logger.error("This configuration cannot be done for Pro devices.")
            return
        if not goTenna.constants.GEO_REGION.valid(region):
            logger.error("Invalid region setting {}".format(region))
            return
        self._set_geo_region = True
        self._settings.geo_settings.region = region
        self.api_thread.set_geo_settings(self._settings.geo_settings)
        logger.info(f"GEO_REGION: {self.api_thread.geo_settings.region}")

    def can_connect(self):
        """ Return whether a goTenna can connect.
        For a goTenna to connect, a GID and RF settings must be configured.
        """
        result = {}
        if self.api_thread.gid:
            result["GID"] = "OK"
        else:
            result["GID"] = "Not Set"
        if self._set_tx_power:
            result["PRO - TX Power"] = "OK"
        else:
            result["PRO - TX Power"] = "Not Set"
        if self._set_frequencies:
            result["PRO - Frequencies"] = "OK"
        else:
            result["PRO - Frequencies"] = "Not Set"
        if self._set_bandwidth:
            result["PRO - Bandwidth"] = "OK"
        else:
            result["PRO - Bandwidth"] = "Not Set"
        if self._set_geo_region:
            result["MESH - Geo region"] = "OK"
        else:
            result["MESH - Geo region"] = "Not Set"
        logger.info(result)
        return result

    def get_system_info(self):
        """ Get system information.
        """
        if not self.api_thread.connected:
            logger.warning("Device must be connected")
            return
        info = {"SYSTEM_INFO": self.api_thread.system_info}
        logger.info(info)
        return info
