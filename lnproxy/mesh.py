import logging
import time

import goTenna
import trio

import lnproxy.config as config
import lnproxy.network as network
import lnproxy.proxy as proxy
import lnproxy.util as util

# For SPI connection only, set SPI_CONNECTION to true with proper SPI settings
SPI_CONNECTION = False
SPI_BUS_NO = 0
SPI_CHIP_NO = 0
SPI_REQUEST = 22
SPI_READY = 27

logger = util.CustomAdapter(logging.getLogger("mesh"), None)
logging.getLogger("goTenna").setLevel(level=logging.INFO)
logging.getLogger("goTenna.driver").setLevel(level=logging.WARNING)
logging.getLogger("goTenna.device").setLevel(level=logging.WARNING)
logging.getLogger("goTenna.pcb_connection").setLevel(level=logging.WARNING)
router = network.router


async def connection_daemon():
    """Load the goTenna mesh connection object (to persistent config.mesh_conn).
    Start the send_queue_daemon in its own nursery.
    """
    # Wait for node info to populate.
    i = 0
    while config.node_info is None:
        if i > 5:
            logger.debug("Waiting for node info in config.node_info")
        await trio.sleep(0.25)
        i += 1
    logger.debug("Got node info, starting connection")
    # start the mesh connection
    async with trio.open_nursery() as nursery:
        config.mesh_conn = Connection(is_plugin=True, nursery=nursery)
        while config.mesh_conn.active is False:
            await trio.sleep(0.25)
        logger.debug("Connection and send_queue_daemon started successfully")
        await trio.sleep_forever()


class Connection:
    """goTenna connection class
    """

    def __init__(
        self, is_plugin=False, gid=None, geo_region=None, sdk_token=None, nursery=None
    ):
        logger.debug("Initialising goTenna Connection object")
        self.is_plugin = is_plugin
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

        if self.is_plugin:
            # Wait for node info to populate from main thread
            logger.debug("goTenna in C-Lightning plugin mode")
            while not config.node_info and len(router) < 3:
                time.sleep(1)
            self.gid = router.get_gid(config.node_info["id"])
            self.nursery = nursery
            self.geo_region = config.user["gotenna"].getint("geo_region")
            self.sdk_token = config.user["gotenna"]["sdk_token"]
            self.to_mesh_send, self.to_mesh_recv = trio.open_memory_channel(50)
            self.from_mesh_send, self.from_mesh_recv = trio.open_memory_channel(50)
            self.nursery.start_soon(self.start_handlers)
        else:
            self.gid = gid
            self.geo_region = geo_region
            self.sdk_token = sdk_token
            self.recvd_msgs = []
        self.configure()
        self.active = True
        logger.info("goTenna Connection object initialised")

    async def start_handlers(self):
        """Helper to run the handlers in their own nursery for extra protection!
        """
        async with trio.open_nursery() as nursery:
            nursery.start_soon(self.send_handler)
            nursery.start_soon(self.recv_handler)
            logger.debug("goTenna Connection handlers started")
        logger.debug("handler nursery exited")

    @staticmethod
    async def new_inbound(node, _from, task_status=trio.TASK_STATUS_IGNORED):
        logger.debug("Queues not initialised... Initialising")
        node.init_queues()
        task_status.started()
        # start a new handle_inbound for this connection
        async with trio.open_nursery() as nursery:
            await nursery.start(proxy.handle_inbound, _from)

    async def parse_recv_mesh_msg(self, msg: goTenna.message.Message):
        """Parses a received message.
        If a node does not exist for this pubkey, then it should create the node and
        init the queues.
        It will start a new `handle_inbound` (in the main nursery) which will monitor
        this node.
        Puts the received message in the correct queue (stream) with header stripped.
        """
        _from = msg.payload.sender.gid_val
        # check if we already have a handle_inbound running, if so continue
        try:
            node = router.get_node(_from)
        except LookupError:
            logger.exception(f"Node {_from} not found in router")
            # Add to router
            # TODO: Create the new node automagically here
            raise
        except Exception:
            logger.debug("Exception getting node")
            raise
        else:
            if (node.outbound or node.inbound) is None:
                await self.nursery.start(self.new_inbound, node, _from)
            try:
                await node.inbound[0].send_all(msg.payload._binary_data)
            except Exception:
                logger.exception(
                    "Exception in await node.inbound[0].send_all(msg.payload._binary_data)"
                )
                raise

    async def lookup_and_send(self, msg):
        """Extract to_gid from message header and send the message over the mesh.
        """
        # Extract the GID from the header
        to_gid = int.from_bytes(msg[:8], "big")
        # send to GID using private message in binary mode
        # logger.debug(f"lookup_and_send: GID={to_gid}, MSG={msg}")
        await self.send_private(to_gid, msg[8:], True)

    async def send_handler(self):
        """Monitors the shared send message queue and sends each message it finds there.
        """
        logger.debug("Started send_handler")
        try:
            async for msg in self.to_mesh_recv:
                await self.lookup_and_send(msg)
                # This sleep stop us overloading the api_thread during large bursts
                await trio.sleep(1)
        except Exception:
            logger.exception("Exception in send_handler")
            raise

    async def recv_handler(self):
        """Handles all messages received from the mesh.
        Put them in the right queue (memory_stream).
        """
        logger.debug("Started recv_handler")
        while True:
            async for msg in self.from_mesh_recv:
                await self.parse_recv_mesh_msg(msg)

    def configure(self):
        if self.api_thread:
            pass
        else:
            self.set_sdk_token(self.sdk_token)
            self.set_geo_region(self.geo_region)
            self.set_gid(self.gid)

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
            if self.is_plugin:
                self.nursery.start_soon(trio.to_thread.run_sync, self.api_thread.run)
            else:
                self.api_thread.start()
        except ValueError:
            logger.error(
                f"SDK token {sdk_token} is not valid. Please enter a valid SDK token.",
            )
        logger.debug(f"SDK_TOKEN: {self.api_thread.sdk_token.decode('utf-8')}")

    def event_callback(self, evt):
        """ The event callback that will store even messages from the API.
        See the documentation for ``goTenna.driver``.
        This will be invoked from the API's thread when events are received.
        """
        if evt.event_type == goTenna.driver.Event.MESSAGE:
            # stick it on the receive queue
            if self.is_plugin:
                # logger.debug(f"RCVD: {util.msg_hash(evt.message.payload._binary_data)}")
                # We put the whole message on the queue so we can extract GID data
                trio.from_thread.run(self.from_mesh_send.send, evt.message)
            else:
                print(f"Received message: {evt.message}")
                self.recvd_msgs.append(evt)

        elif evt.event_type == goTenna.driver.Event.DEVICE_PRESENT:
            if self._awaiting_disconnect_after_fw_update[0]:
                logger.info("Device physically connected")
            else:
                logger.info("Device physically connected, configure to continue")
                try:
                    self.configure()
                except Exception:
                    logger.exception(
                        f"Incurred exception whilst trying to auto-configure:",
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
                logger.info(f"Disconnected! {evt}")
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
                    logger.error(result)

        return callback

    def set_gid(self, gid):
        """ Create a new profile (if it does not already exist) with default settings.
        GID should be a 15-digit numerical GID.
        """
        if self.api_thread.connected:
            logger.error("Must not already be connected when setting GID")
            return
        (_gid, _) = self._parse_gid(gid, goTenna.settings.GID.PRIVATE)
        if not _gid:
            return
        self.api_thread.set_gid(_gid)
        self._settings.gid_settings = gid
        logger.debug(f"GID: {self.api_thread.gid.gid_val}")

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
                    # logger.debug(f"SENT: {util.msg_hash(message)}")
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

    async def send_private(self, gid: int, message, binary=False):
        """ Send a private message to a contact
        GID is the GID to send the private message to.
        """
        logger.debug(f"Sending {len(message)}B message to gid {gid}. Binary={binary}")
        _gid, rest = self._parse_gid(gid, goTenna.settings.GID.PRIVATE)
        if not self.api_thread.connected:
            logger.error("Must connect first")
            return
        if not _gid and message:
            logger.debug(f"GID or message missing. GID={_gid}, MESSAGE={message}")
            return

        def error_handler(details):
            """ Special error handler for sending private messages to format errors
            """
            return f"Error sending message: {details}"

        try:
            if binary:
                method_callback = self.build_callback(error_handler, binary=True)
                payload = goTenna.payload.BinaryPayload(message)
                encrypt = False
            else:
                method_callback = self.build_callback(error_handler)
                payload = goTenna.payload.TextPayload(message)
                encrypt = True

            def ack_callback(correlation_id, success):
                if not success:
                    logger.error(
                        f"Private message to {_gid.gid_val}: delivery not confirmed,"
                        f"recipient may be offline or out of range",
                    )

            # This loop helps us overcome quota limitation in gotenna where it
            # otherwise insta-fails if we are over quota. Will retry every 5 seconds for
            # 70 seconds. Quota is reset at 60s so this should always succeed unless
            # peer has disappeared.
            i = 0
            corr_id = None
            while corr_id is None and i < 14:
                corr_id = self.api_thread.send_private(
                    _gid,
                    payload,
                    method_callback,
                    ack_callback=ack_callback,
                    encrypt=encrypt,
                )
                i += 1
                if corr_id is None:
                    await trio.sleep(5)
                    logger.debug(f"corr_id is None, retrying: #{i}")
            if corr_id is None:
                logger.error(
                    f"Could not send message {payload} to GID {gid} in {i} tries"
                )
                return
            # logger.debug(f"SENT: {util.msg_hash(message)}")
        except ValueError:
            logger.error("Message too long!")
            return
        try:
            self.in_flight_events[
                corr_id.bytes
            ] = f"Private message to {_gid.gid_val}: {message}"
        except Exception:
            logger.exception("Unhandled exception related to in_flight_events")
            return

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
        logger.debug(f"GEO_REGION: {self.api_thread.geo_settings.region}")

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
